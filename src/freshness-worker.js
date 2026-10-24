'use strict';
// Builtins only before the buffered loader is installed. The parent executes
// these exact bytes with --eval, without inherited Node preloads or flags.
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const Module = require('node:module');
const vm = require('node:vm');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = code => { throw Object.assign(new Error(code), { code }); };
const MAX_FILE = 2 * 1024 * 1024;
function readFile(filename, max = MAX_FILE) {
  const initial = fs.lstatSync(filename);
  if (initial.isSymbolicLink() || !initial.isFile()) fail('compiler_file_rejected');
  if (initial.size > max) fail('compiler_limit');
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.size > max) fail('compiler_limit');
    const bytes = Buffer.alloc(before.size + 1);
    let count = 0, n;
    while (count < bytes.length && (n = fs.readSync(fd, bytes, count, bytes.length - count, null))) count += n;
    const after = fs.fstatSync(fd), current = fs.lstatSync(filename);
    if (count !== before.size || current.isSymbolicLink() ||
        ['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs'].some(k => before[k] !== after[k] || before[k] !== current[k])) fail('compiler_changed_during_read');
    return bytes.subarray(0, count);
  } finally { fs.closeSync(fd); }
}
function runtimeIdentity() {
  // Streaming bounds avoid allocating an executable-sized buffer. This binds
  // Node (including builtins), not OS libraries or the entire machine image.
  const filename = fs.realpathSync(process.execPath), fd = fs.openSync(filename, 'r');
  try {
    const before = fs.fstatSync(fd), digest = createHash('sha256');
    if (!before.isFile() || before.size > 256 * 1024 * 1024) fail('runtime_limit');
    const buffer = Buffer.alloc(64 * 1024);
    let total = 0, count;
    while ((count = fs.readSync(fd, buffer, 0, buffer.length, null))) {
      total += count;
      if (total > 256 * 1024 * 1024) fail('runtime_limit');
      digest.update(buffer.subarray(0, count));
    }
    const after = fs.fstatSync(fd), current = fs.statSync(filename);
    if (total !== before.size || ['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs'].some(k => before[k] !== after[k] || before[k] !== current[k])) fail('runtime_changed');
    return { executable_sha256: digest.digest('hex'), node: process.version,
      versions: process.versions, platform: process.platform, arch: process.arch };
  } finally { fs.closeSync(fd); }
}
function captureCompiler(sourceRoot = __dirname) {
  const root = path.resolve(sourceRoot), buffers = new Map(), files = [];
  let entries = 0, total = 0;
  const add = filename => {
    const bytes = readFile(filename);
    total += bytes.length;
    if (total > 64 * 1024 * 1024) fail('compiler_limit');
    buffers.set(filename, bytes);
    files.push([path.relative(root, filename).replace(/\\/g, '/'), hash(bytes)]);
  };
  const walk = dir => {
    const stat = fs.lstatSync(dir);
    if (!stat.isDirectory() || stat.isSymbolicLink()) fail('compiler_symlink');
    const handle = fs.opendirSync(dir);
    try {
      for (let entry; (entry = handle.readSync());) {
        if (++entries > 2000) fail('compiler_limit');
        const filename = path.join(dir, entry.name);
        if (entry.isSymbolicLink()) fail('compiler_symlink');
        if (entry.isDirectory()) walk(filename);
        else if (entry.isFile() && /\.(js|json)$/.test(entry.name)) add(filename);
        else fail('unsupported_compiler_file');
      }
    } finally { handle.closeSync(); }
  };
  walk(root);
  for (const name of ['package.json', 'package-lock.json']) {
    const filename = path.join(root, '..', name);
    if (fs.existsSync(filename)) add(filename);
  }
  files.sort((a, b) => a[0] < b[0] ? -1 : 1);
  const runtime = runtimeIdentity();
  return { buffers, files, runtime, digest: hash(JSON.stringify([files, runtime])) };
}
function childEnvironment() {
  return Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(NODE_OPTIONS|NODE_PATH)$/i.test(key)));
}
function workerArgs(identity, sourceRoot, operation, root, outDir = '') {
  const bytes = identity.buffers.get(path.join(sourceRoot, 'freshness-worker.js'));
  if (!bytes) fail('missing_worker');
  // The canonical compiler never starts other processes or threads. Enforce
  // that supported boundary in Node, before any captured module is executed.
  // Node 20 uses the experimental spelling; newer runtimes use --permission.
  const permission = ['--permission', '--experimental-permission']
    .find(flag => process.allowedNodeEnvironmentFlags.has(flag));
  if (!permission) fail('unsupported_worker_runtime');
  return [permission, '--allow-fs-read=*', '--allow-fs-write=*',
    '--eval', bytes.toString('utf8'), '--', 'ecf-fresh-worker', sourceRoot, operation, root, outDir];
}
// A private CommonJS graph for the long-lived reader. Unlike the child
// bootstrap below, this must not replace process-global module loaders/cache.
// Only captured local buffers and Node builtins may be required. This binds
// execution bytes; it is not a malicious-code or filesystem sandbox.
function capturedGraph(identity, sourceRoot = __dirname) {
  const cache = new Map(), loaded = new Map();
  const load = filename => {
    if (cache.has(filename)) return cache.get(filename).exports;
    const bytes = identity.buffers.get(filename);
    if (!bytes) fail('unbound_reader_dependency');
    const module = new Module(filename);
    module.filename = filename;
    module.paths = Module._nodeModulePaths(path.dirname(filename));
    Object.defineProperty(module, 'ecfCapturedReader', { value: Object.freeze({ digest: identity.digest, loaded }) });
    cache.set(filename, module);
    loaded.set(path.relative(sourceRoot, filename).replace(/\\/g, '/'), hash(bytes));
    const localRequire = request => Module.isBuiltin(request) ? require(request)
      : load(Module._resolveFilename(request, module));
    localRequire.resolve = request => Module._resolveFilename(request, module);
    module.require = localRequire;
    if (filename.endsWith('.json')) module.exports = JSON.parse(bytes.toString('utf8'));
    else if (filename.endsWith('.js')) {
      const body = bytes.toString('utf8').replace(/^\uFEFF/, '').replace(/^#![^\n]*/, '');
      const execute = vm.compileFunction(body, ['exports', 'require', 'module', '__filename', '__dirname'], {
        filename, importModuleDynamically: () => fail('unbound_reader_dependency'),
      });
      execute.call(module.exports, module.exports, localRequire, module, filename, path.dirname(filename));
    } else fail('unbound_reader_dependency');
    module.loaded = true;
    return module.exports;
  };
  return { load, loaded };
}
async function main() {
  if (!process.permission || process.permission.has('child') || process.permission.has('worker')) fail('worker_lifecycle_not_restricted');
  const [, , sourceRoot, operation, root, outDir] = process.argv;
  const identity = captureCompiler(sourceRoot), loaded = new Map();
  const bootstrap = path.join(sourceRoot, 'freshness-worker.js');
  if (hash(process._eval) !== hash(identity.buffers.get(bootstrap))) fail('compiler_changed_during_compile');
  loaded.set('freshness-worker.js', hash(process._eval));
  // Each module executes the very buffer whose digest is recorded, including
  // lazy dependencies. No parent cache, disk reread, or node_modules fallback.
  const load = (module, filename) => {
    const bytes = identity.buffers.get(filename);
    if (!bytes) fail('unbound_compiler_dependency');
    loaded.set(path.relative(sourceRoot, filename).replace(/\\/g, '/'), hash(bytes));
    if (filename.endsWith('.json')) module.exports = JSON.parse(bytes.toString('utf8'));
    else {
      const body = bytes.toString('utf8').replace(/^\uFEFF/, '').replace(/^#![^\n]*/, '');
      const execute = vm.compileFunction(body, ['exports', 'require', 'module', '__filename', '__dirname'], {
        filename, importModuleDynamically: () => fail('unbound_compiler_dependency'),
      });
      execute.call(module.exports, module.exports, Module.createRequire(filename), module, filename, path.dirname(filename));
    }
  };
  Module._extensions['.js'] = load;
  Module._extensions['.json'] = load;
  Module._extensions['.node'] = () => fail('unbound_compiler_dependency');
  const api = require(path.join(sourceRoot, 'freshness.js'));
  let result;
  if (operation === 'compile') result = await api.compileCandidate(root, outDir);
  else if (operation === 'snapshot') result = api.snapshotCandidate(root, outDir);
  else if (operation === 'inspect' || operation === 'read' || operation === 'verify') result = api.inspectGeneration(root,
    { includeContext: operation === 'read', includeVerification: operation === 'verify' }, identity);
  else fail('invalid_worker_operation');
  if (identity.digest !== captureCompiler(sourceRoot).digest) fail('source_changed_during_compile');
  const execution = { compiler_digest: identity.digest, runtime: identity.runtime, lifecycle: 'node_permission_no_descendants',
    loaded_modules: [...loaded].sort((a, b) => a[0] < b[0] ? -1 : 1) };
  process.stdout.write(JSON.stringify({ result, execution }));
}
if (process.argv[1] === 'ecf-fresh-worker' && module.id === '[eval]') main().catch(error => {
  const code = error.code === 'ERR_ACCESS_DENIED' ? 'compiler_capability_denied'
    : /^[a-z_]+$/.test(error.code || '') ? error.code : 'compiler_child_failed';
  process.stdout.write(JSON.stringify({ error: code })); process.exitCode = 1;
});
module.exports = { captureCompiler, childEnvironment, workerArgs, capturedGraph };
