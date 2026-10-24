'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { createHash, randomUUID } = require('node:crypto');
const { spawn, spawnSync } = require('node:child_process');
const { captureCompiler, childEnvironment, workerArgs } = require('./freshness-worker');
const { shouldSkipDirectory } = require('./core/policy');
const { metadataDisposition } = require('./adapters/filesystem');
const hash = value => createHash('sha256').update(value).digest('hex');
const fail = code => { throw Object.assign(new Error(code), { code }); };
const MAX_FILE = 2 * 1024 * 1024;
const MAX_TOTAL = 64 * 1024 * 1024;
const MAX_ENTRIES = 10000;
function readBounded(filename, max = MAX_FILE) {
  const initial = fs.lstatSync(filename);
  if (initial.isSymbolicLink()) fail('symlink_rejected');
  if (!initial.isFile() || initial.size > max) fail('file_limit');
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.size > max) fail('file_limit');
    const buffer = Buffer.alloc(Math.min(max + 1, before.size + 1));
    let count = 0;
    while (count < buffer.length) {
      const n = fs.readSync(fd, buffer, count, buffer.length - count, null);
      if (!n) break;
      count += n;
    }
    const after = fs.fstatSync(fd);
    const current = fs.lstatSync(filename);
    if (count !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs ||
        after.ctimeMs !== before.ctimeMs || current.isSymbolicLink() || current.ino !== before.ino || current.dev !== before.dev) fail('file_changed_during_read');
    return buffer.subarray(0, count);
  } finally { fs.closeSync(fd); }
}
function directory(filename, create = false) {
  if (create && !fs.existsSync(filename)) fs.mkdirSync(filename, { mode: 0o700 });
  const stat = fs.lstatSync(filename);
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail('unsafe_directory');
  return fs.realpathSync(filename);
}
function captureSnapshot(projectRoot, config) {
  const root = directory(path.resolve(projectRoot));
  let entries = 0, total = 0;
  const files = [], restrictedInventory = [];
  const walk = (dir, prefix = '') => {
    const handle = fs.opendirSync(dir);
    try {
      for (;;) {
        const entry = handle.readSync(); if (!entry) break;
        if (++entries > MAX_ENTRIES) fail('inventory_limit');
        const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
        const full = path.join(dir, entry.name);
        if (entry.isSymbolicLink()) fail('symlink_rejected');
        if (entry.isDirectory()) {
          // Match the canonical filesystem walker: directory rules must never
          // exclude a regular file merely named temp-context.js or temp_*.js.
          if (shouldSkipDirectory(relative, config) || fs.existsSync(path.join(full, '.git'))) continue;
          directory(full); walk(full, relative); continue;
        }
        if (!entry.isFile()) fail('non_regular_source');
        const stat = fs.lstatSync(full);
        if (stat.isSymbolicLink()) fail('symlink_rejected');
        if (!stat.isFile()) fail('non_regular_source');
        const disposition = metadataDisposition(relative, config, stat);
        if (disposition) {
          // Effective canonical disposition includes allowed non-text/oversize
          // sources. Bind the canonical metadata fingerprint without content I/O.
          restrictedInventory.push([relative, disposition.classification, disposition.reason,
            stat.size, Math.trunc(stat.mtimeMs), disposition.hash]);
          if (relative !== 'ecf.config.json') continue;
        }
        // Configuration is independently consumed even when metadata-only as a
        // source. Retain its content hash as well as its canonical disposition.
        const bytes = readBounded(full);
        const current = fs.lstatSync(full);
        if (!current.isFile() || current.isSymbolicLink() ||
            ['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs'].some(k => stat[k] !== current[k])) fail('file_changed_during_read');
        total += bytes.length;
        if (total > MAX_TOTAL) fail('total_byte_limit');
        files.push([relative, hash(bytes)]);
      }
    } finally { handle.closeSync(); }
  };
  walk(root);
  const byPath = (a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0;
  files.sort(byPath);
  restrictedInventory.sort(byPath);
  // Metadata shares the existing entry limit and has a separate serialized bound.
  if (Buffer.byteLength(JSON.stringify([files, restrictedInventory])) > MAX_FILE / 2) fail('inventory_limit');
  const configHash = hash(JSON.stringify(config));
  return { workspace_hash: hash(root), config_hash: configHash, files,
    restricted_inventory: restrictedInventory,
    source_digest: hash(JSON.stringify([files, restrictedInventory])),
    digest: hash(JSON.stringify([hash(root), configHash, files, restrictedInventory])) };
}
function currentConfig(root) {
  const configFile = path.join(root, 'ecf.config.json');
  if (fs.existsSync(configFile)) readBounded(configFile);
  return require('./core/config').loadConfig({ projectRoot: root });
}
function generationArtifacts(dir) {
  const files = [];
  for (const item of fs.readdirSync(dir, { withFileTypes: true })) {
    if (item.name === 'freshness.json') continue;
    if (!item.isFile() || !/^[a-z0-9-]+\.json$/.test(item.name)) fail('unexpected_artifact');
    if (files.length >= 32) fail('artifact_limit');
    files.push([item.name, hash(readBounded(path.join(dir, item.name), 8 * 1024 * 1024))]);
  }
  for (const name of ['context-packet.json', 'policy-summary.json', 'source-map.json']) if (!files.some(x => x[0] === name)) fail('missing_artifact');
  return files.sort((a,b) => a[0] < b[0] ? -1 : 1);
}
function atomicJson(filename, value) {
  const temp = `${filename}.${randomUUID()}.tmp`;
  const fd = fs.openSync(temp, 'wx', 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value) + '\n'); fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
  try { fs.renameSync(temp, filename); }
  catch (error) { fs.unlinkSync(temp); throw error; }
}
// Called only inside the fresh graph for canonical refresh. Injection remains
// explicitly test-only; it can never create a retrievable current generation.
async function compileCandidate(root, outDir, compile = require('./compile').compileProject) {
  const before = captureSnapshot(root, currentConfig(root));
  await compile({ projectRoot: root, outDir, emitAgentOs: true });
  const snapshot = captureSnapshot(root, currentConfig(root));
  if (before.digest !== snapshot.digest) fail('source_changed_during_compile');
  return { snapshot, artifacts: generationArtifacts(outDir) };
}
function snapshotCandidate(root, outDir) {
  return { snapshot: captureSnapshot(root, currentConfig(root)), artifacts: generationArtifacts(outDir) };
}
function verifyWorker(bytes, identity) {
  let message;
  try { message = JSON.parse(bytes); } catch { fail('invalid_compiler_response'); }
  if (message.error) fail(/^[a-z_]+$/.test(message.error) ? message.error : 'compiler_child_failed');
  const execution = message.execution;
  if (execution?.compiler_digest !== identity.digest || JSON.stringify(execution.runtime) !== JSON.stringify(identity.runtime) ||
      execution.lifecycle !== 'node_permission_no_descendants' ||
      !Array.isArray(execution.loaded_modules) || !execution.loaded_modules.length) fail('compiler_identity_mismatch');
  const expected = new Map(identity.files), seen = new Set();
  for (const entry of execution.loaded_modules) {
    if (!Array.isArray(entry) || entry.length !== 2 || expected.get(entry[0]) !== entry[1] || seen.has(entry[0])) fail('compiler_identity_mismatch');
    seen.add(entry[0]);
  }
  if (!seen.has('freshness.js') || !seen.has('freshness-worker.js')) fail('compiler_identity_mismatch');
  if (captureCompiler().digest !== identity.digest) fail('source_changed_during_compile');
  return message;
}
function runCompiler(identity, root, outDir, { timeoutMs, signal }, operation = 'compile') {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, workerArgs(identity, __dirname, operation, root, outDir), {
      env: childEnvironment(), stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
    });
    const chunks = [];
    let outputBytes = 0, diagnosticBytes = 0, failure;
    const stop = code => { failure ||= code; child.kill('SIGKILL'); };
    const abort = () => stop('compile_cancelled');
    const timer = setTimeout(() => stop('compile_timeout'), timeoutMs);
    if (signal) AbortSignal.prototype.addEventListener.call(signal, 'abort', abort, { once: true });
    if (signal?.aborted) abort();
    child.stdout.on('data', bytes => {
      outputBytes += bytes.length;
      if (outputBytes > 2 * MAX_FILE) stop('compiler_output_limit');
      else if (!failure) chunks.push(bytes);
    });
    child.stderr.on('data', bytes => {
      diagnosticBytes += bytes.length;
      if (diagnosticBytes > 64 * 1024) stop('compiler_output_limit');
    });
    child.on('error', () => { failure ||= 'compiler_child_failed'; });
    // Node denies process/thread creation before loading compiler modules, so
    // descendants cannot retain these pipes or write after this worker closes.
    // No result (even a complete one) is accepted after a failure.
    child.on('close', (code, terminationSignal) => {
      clearTimeout(timer);
      if (signal) AbortSignal.prototype.removeEventListener.call(signal, 'abort', abort);
      try {
        if (failure) fail(failure);
        if (terminationSignal) fail('compiler_child_failed');
        const message = verifyWorker(Buffer.concat(chunks).toString('utf8'), identity);
        if (code !== 0) fail('compiler_child_failed');
        if (operation === 'compile' && !message.execution.loaded_modules.some(entry => entry[0] === 'compile.js')) fail('compiler_identity_mismatch');
        resolve(message);
      } catch (error) { reject(error); }
    });
  });
}
function sameDirectory(filename, original) {
  try {
    const current = fs.lstatSync(filename);
    return current.isDirectory() && !current.isSymbolicLink() && current.dev === original.dev && current.ino === original.ino;
  } catch { return false; }
}
async function compileFresh(projectRoot, options = {}) {
  const { signal, timeoutMs = 30000 } = options;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300000) fail('invalid_compile_timeout');
  if (signal !== undefined && !(signal instanceof AbortSignal)) fail('invalid_compile_signal');
  if (signal?.aborted) fail('compile_cancelled');
  const root = directory(path.resolve(projectRoot));
  const compiler = captureCompiler();
  const artifactRoot = path.join(root, '.ecf-core'); directory(artifactRoot, true);
  const generations = path.join(artifactRoot, 'fresh'); directory(generations, true);
  const lock = path.join(generations, '.lock');
  try { fs.mkdirSync(lock, { mode: 0o700 }); } catch (error) { if (error.code === 'EEXIST') fail('refresh_locked'); throw error; }
  const lockStat = fs.lstatSync(lock), token = randomUUID(), owner = path.join(lock, 'owner');
  const generation = `gen-${randomUUID()}`;
  const outDir = path.join(generations, generation);
  let outStat, selected = false, ownerWritten = false;
  const ownsLock = () => {
    try { return sameDirectory(lock, lockStat) && readBounded(owner, 128).toString() === token; }
    catch { return false; }
  };
  try {
    fs.writeFileSync(owner, token, { flag: 'wx', mode: 0o600 });
    ownerWritten = true;
    directory(outDir, true);
    outStat = fs.lstatSync(outDir);
    const deadline = Date.now() + timeoutMs;
    const remaining = () => {
      const ms = deadline - Date.now();
      if (ms <= 0) fail('compile_timeout');
      return ms;
    };
    const message = options.compile
      ? { result: await compileCandidate(root, outDir, options.compile), execution: null }
      : await runCompiler(compiler, root, outDir, { timeoutMs: remaining(), signal });
    if (!options.compile) {
      // Compilation can leave pending callbacks. Only verify after it closes,
      // using another fresh graph that does not invoke the compiler again.
      const verified = await runCompiler(compiler, root, outDir, { timeoutMs: remaining(), signal }, 'snapshot');
      if (message.result.snapshot.digest !== verified.result.snapshot.digest) fail('source_changed_during_compile');
      if (JSON.stringify(message.result.artifacts) !== JSON.stringify(verified.result.artifacts)) fail('artifact_changed');
      remaining();
    }
    if (signal?.aborted) fail('compile_cancelled');
    if (compiler.digest !== captureCompiler().digest) fail('source_changed_during_compile');
    if (!ownsLock()) fail('refresh_lock_lost');
    const { snapshot } = message.result;
    const artifacts = generationArtifacts(outDir);
    if (JSON.stringify(artifacts) !== JSON.stringify(message.result.artifacts)) fail('artifact_changed');
    const seal = { schema_version: 'ecf-core.freshness.v1', generation, snapshot,
      compiler_digest: compiler.digest, execution: message.execution, artifacts, created_at: new Date().toISOString(),
      compiler_mode: options.compile ? 'injected_test_only' : 'ecf_core',
      host_consumption_verified: false };
    atomicJson(path.join(outDir, 'freshness.json'), seal);
    if (!ownsLock()) fail('refresh_lock_lost');
    atomicJson(path.join(generations, 'current.json'), { generation, seal_hash: hash(readBounded(path.join(outDir, 'freshness.json'))) });
    selected = true;
    return { state: options.compile ? 'test_only' : 'fresh', generation, compiler_mode: seal.compiler_mode, host_consumption_verified: false };
  } finally {
    try {
      if (!selected && outStat && sameDirectory(outDir, outStat)) fs.rmSync(outDir, { recursive: true });
    } finally {
      if (ownsLock()) { fs.unlinkSync(owner); fs.rmdirSync(lock); }
      else if (!ownerWritten && sameDirectory(lock, lockStat) && fs.readdirSync(lock).length === 0) fs.rmdirSync(lock);
    }
  }
}
function inspectGeneration(projectRoot, { includeContext = false, includeVerification = false } = {}, compiler = captureCompiler()) {
  try {
    const root = directory(path.resolve(projectRoot));
    directory(path.join(root, '.ecf-core'));
    const generations = directory(path.join(root, '.ecf-core', 'fresh'));
    const pointerBytes = readBounded(path.join(generations, 'current.json'), 4096);
    const pointer = JSON.parse(pointerBytes);
    if (!/^gen-[a-f0-9-]{36}$/.test(pointer.generation) || !/^[a-f0-9]{64}$/.test(pointer.seal_hash)) fail('invalid_generation');
    const outDir = directory(path.join(generations, pointer.generation));
    const bytes = readBounded(path.join(outDir, 'freshness.json'));
    if (hash(bytes) !== pointer.seal_hash) fail('seal_changed');
    const seal = JSON.parse(bytes);
    if (seal.schema_version !== 'ecf-core.freshness.v1' || seal.generation !== pointer.generation) fail('invalid_seal');
    if (seal.compiler_mode !== 'ecf_core') fail('test_generation_not_current_context');
    const snapshot = captureSnapshot(root, currentConfig(root));
    if (snapshot.digest !== seal.snapshot?.digest) return { state: 'stale', generation: seal.generation, reason: 'source_or_policy_changed', context: null };
    if (compiler.digest !== seal.compiler_digest) return { state: 'stale', generation: seal.generation, reason: 'compiler_changed', context: null };
    if (seal.execution?.compiler_digest !== compiler.digest || JSON.stringify(seal.execution.runtime) !== JSON.stringify(compiler.runtime) ||
        seal.execution.lifecycle !== 'node_permission_no_descendants') fail('compiler_identity_mismatch');
    const expected = new Map(compiler.files);
    if (!Array.isArray(seal.execution.loaded_modules) || !seal.execution.loaded_modules.some(entry => entry[0] === 'compile.js') ||
        seal.execution.loaded_modules.some(entry => !Array.isArray(entry) || entry.length !== 2 || expected.get(entry[0]) !== entry[1])) fail('compiler_identity_mismatch');
    if (JSON.stringify(generationArtifacts(outDir)) !== JSON.stringify(seal.artifacts)) fail('artifact_changed');
    let context;
    if (includeContext) {
      const contextBytes = readBounded(path.join(outDir, 'context-packet.json'), 8 * 1024 * 1024);
      if (hash(contextBytes) !== seal.artifacts.find(x => x[0] === 'context-packet.json')[1]) fail('artifact_changed');
      context = JSON.parse(contextBytes);
    }
    // Recheck after reading; never serve a cached generation following detected drift.
    if (captureSnapshot(root, currentConfig(root)).digest !== snapshot.digest) fail('source_changed_during_read');
    if (JSON.stringify(generationArtifacts(outDir)) !== JSON.stringify(seal.artifacts)) fail('artifact_changed');
    if (hash(readBounded(path.join(outDir, 'freshness.json'))) !== pointer.seal_hash) fail('seal_changed');
    if (!readBounded(path.join(generations, 'current.json'), 4096).equals(pointerBytes)) fail('current_generation_changed');
    return { state: 'fresh', generation: seal.generation, source_digest: snapshot.source_digest,
      host_consumption_verified: false, ...(includeContext ? { context } : {}),
      ...(includeVerification ? { verification: {
        generation: seal.generation, seal_hash: pointer.seal_hash,
        snapshot_digest: snapshot.digest, source_digest: snapshot.source_digest,
        config_hash: snapshot.config_hash, compiler_digest: compiler.digest,
        artifacts: seal.artifacts,
      } } : {}) };
  } catch (error) {
    return { state: 'unknown', context: null, reason: error.code === 'ERR_ACCESS_DENIED' ? 'compiler_capability_denied'
      : /^[a-z_]+$/.test(error.code || '') ? error.code : 'freshness_unavailable' };
  }
}
function inspectFresh(projectRoot, { includeContext = false, includeVerification = false } = {}) {
  try {
    if (includeContext && includeVerification) fail('invalid_inspection_options');
    const compiler = captureCompiler();
    const operation = includeVerification ? 'verify' : includeContext ? 'read' : 'inspect';
    const child = spawnSync(process.execPath, workerArgs(compiler, __dirname, operation, path.resolve(projectRoot)), {
      env: childEnvironment(), encoding: 'utf8', windowsHide: true,
      timeout: 30000, killSignal: 'SIGKILL', maxBuffer: 10 * 1024 * 1024,
    });
    if (child.error || child.signal) fail('compiler_child_failed');
    const message = verifyWorker(child.stdout, compiler);
    if (child.status !== 0) fail('compiler_child_failed');
    return message.result;
  } catch (error) {
    return { state: 'unknown', context: null, reason: error.code === 'ERR_ACCESS_DENIED' ? 'compiler_capability_denied'
      : /^[a-z_]+$/.test(error.code || '') ? error.code : 'freshness_unavailable' };
  }
}
module.exports = { readBounded, captureSnapshot, compileFresh, inspectFresh, compileCandidate, snapshotCandidate, inspectGeneration };
