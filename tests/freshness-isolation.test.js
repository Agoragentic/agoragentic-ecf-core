'use strict';
// Mutation probes use disposable copies of the real compiler and its actual
// dependencies. No replacement artifact generator or internal-module mocks.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { setTimeout: delay } = require('node:timers/promises');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
function fixture(t) {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'ecf-isolation-'));
  const copy = path.join(temp, 'compiler'), root = path.join(temp, 'project');
  fs.mkdirSync(copy); fs.mkdirSync(root);
  fs.cpSync(path.resolve(__dirname, '../src'), path.join(copy, 'src'), { recursive: true });
  fs.copyFileSync(path.resolve(__dirname, '../package.json'), path.join(copy, 'package.json'));
  fs.writeFileSync(path.join(root, 'README.md'), '# Fixture\nLocal context.\n');
  t.after(() => {
    for (const key of Object.keys(require.cache)) if (key.startsWith(copy + path.sep)) delete require.cache[key];
    fs.rmSync(temp, { recursive: true, force: true });
  });
  const target = path.join(copy, 'src/compile.js');
  const load = () => { require(target); return require(path.join(copy, 'src/freshness.js')); };
  const wrap = body => fs.appendFileSync(target, `\nconst canonical = module.exports.compileProject;\nmodule.exports.compileProject = async options => { ${body} };\n`);
  const freshDir = path.join(root, '.ecf-core/fresh');
  return { temp, copy, root, target, load, wrap, freshDir };
}
function output(f, result, name) {
  return JSON.parse(fs.readFileSync(path.join(f.freshDir, result.generation, name)));
}
function assertBound(f, result, filename) {
  const seal = output(f, result, 'freshness.json');
  const entry = seal.execution.loaded_modules.find(row => row[0] === filename);
  assert.equal(entry?.[1], sha(fs.readFileSync(path.join(f.copy, 'src', filename))));
  assert.equal(seal.execution.runtime.node, process.version);
  assert.match(seal.execution.runtime.executable_sha256, /^[a-f0-9]{64}$/);
  assert.equal(seal.compiler_digest, seal.execution.compiler_digest);
  assert.equal(seal.execution.lifecycle, 'node_permission_no_descendants');
}
test('parent loads compiler A; refresh executes on-disk compiler B with its actual bytes', async t => {
  const f = fixture(t), api = f.load();
  const original = fs.readFileSync(f.target, 'utf8');
  assert(original.includes('scope: config.scope'));
  fs.writeFileSync(f.target, original.replace('scope: config.scope', "scope: 'self_hosted_workspace'"));
  const result = await api.compileFresh(f.root);
  assert.equal(output(f, result, 'context-packet.json').scope, 'self_hosted_workspace');
  assert.equal(api.inspectFresh(f.root).state, 'fresh');
  assertBound(f, result, 'compile.js');
});
test('dependency-only edit after parent load executes B and inspection uses fresh config', async t => {
  const f = fixture(t), api = f.load();
  const filename = path.join(f.copy, 'src/core/config.js');
  const original = fs.readFileSync(filename, 'utf8');
  fs.writeFileSync(filename, original.replace('max_calls: 10', 'max_calls: 23'));
  const result = await api.compileFresh(f.root);
  assert.equal(output(f, result, 'policy-summary.json').tool_limits.max_calls, 23);
  assert.equal(api.inspectFresh(f.root).state, 'fresh');
  assertBound(f, result, 'core/config.js');
  fs.writeFileSync(filename, original.replace('max_calls: 10', 'max_calls: 24'));
  const stale = api.inspectFresh(f.root, { includeContext: true });
  assert.equal(stale.state, 'stale'); assert.equal(stale.context, null);
});
test('local JSON dependency bytes are bound and refreshed after a cached parent load', async t => {
  const f = fixture(t), config = path.join(f.copy, 'src/core/config.js');
  const dependency = path.join(f.copy, 'src/core/fixture.json');
  fs.writeFileSync(dependency, '{"calls":11}');
  fs.writeFileSync(config, fs.readFileSync(config, 'utf8').replace('max_calls: 10', "max_calls: require('./fixture.json').calls"));
  const api = f.load();
  // Load the lazy JSON dependency in the parent too.
  require(config).loadConfig({ projectRoot: f.root });
  fs.writeFileSync(dependency, '{"calls":22}');
  const result = await api.compileFresh(f.root);
  assert.equal(output(f, result, 'policy-summary.json').tool_limits.max_calls, 22);
  assertBound(f, result, 'core/fixture.json');
});
for (const [label, body] of [
  ['source drift', "fs.writeFileSync(path.join(options.projectRoot, 'README.md'), '# Changed');"],
  ['configuration drift', "fs.writeFileSync(path.join(options.projectRoot, 'ecf.config.json'), '{\"project_name\":\"changed\"}');"],
  ['compiler drift', "fs.appendFileSync(__filename, '\\n// changed during compile\\n');"],
  ['dependency drift', "fs.appendFileSync(path.join(__dirname, 'core/config.js'), '\\n// changed during compile\\n');"],
]) test(`${label} during execution refuses promotion and removes failed output`, async t => {
  const f = fixture(t), api = f.load();
  const first = await api.compileFresh(f.root);
  const pointer = fs.readFileSync(path.join(f.freshDir, 'current.json'), 'utf8');
  f.wrap(`const result = await canonical(options); ${body} return result;`);
  await assert.rejects(api.compileFresh(f.root), { code: 'source_changed_during_compile' });
  assert.equal(fs.readFileSync(path.join(f.freshDir, 'current.json'), 'utf8'), pointer);
  assert.deepEqual(fs.readdirSync(f.freshDir).sort(), ['current.json', first.generation].sort());
});
test('failed child after real artifact writes preserves selection and cleans its generation', async t => {
  const f = fixture(t), api = f.load(), first = await api.compileFresh(f.root);
  const pointer = fs.readFileSync(path.join(f.freshDir, 'current.json'), 'utf8');
  f.wrap("await canonical(options); throw new Error('private diagnostic must not escape');");
  await assert.rejects(api.compileFresh(f.root), { code: 'compiler_child_failed', message: 'compiler_child_failed' });
  assert.equal(fs.readFileSync(path.join(f.freshDir, 'current.json'), 'utf8'), pointer);
  assert.deepEqual(fs.readdirSync(f.freshDir).sort(), ['current.json', first.generation].sort());
});
test('source drift in pending child work after compile returns still refuses promotion', async t => {
  const f = fixture(t), api = f.load(), first = await api.compileFresh(f.root);
  const pointer = fs.readFileSync(path.join(f.freshDir, 'current.json'), 'utf8');
  f.wrap(`const result = await canonical(options);
    setTimeout(() => fs.writeFileSync(path.join(options.projectRoot, 'README.md'), '# Delayed change'), 200);
    return result;`);
  await assert.rejects(api.compileFresh(f.root), { code: 'source_changed_during_compile' });
  assert.equal(fs.readFileSync(path.join(f.freshDir, 'current.json'), 'utf8'), pointer);
  assert.deepEqual(fs.readdirSync(f.freshDir).sort(), ['current.json', first.generation].sort());
});
async function started(f, outcome) {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    for (const name of fs.readdirSync(f.freshDir)) {
      const marker = path.join(f.freshDir, name, 'child-started.json');
      if (fs.existsSync(marker)) return JSON.parse(fs.readFileSync(marker));
    }
    const early = await Promise.race([outcome, delay(20).then(() => null)]);
    if (early) assert.fail(`child exited before starting: ${early.error?.code}`);
  }
  assert.fail('child did not start');
}
for (const cancellation of [false, true]) test(`${cancellation ? 'cancellation' : 'timeout'} kills the child before cleanup and preserves pointer`, async t => {
  const f = fixture(t), api = f.load(), first = await api.compileFresh(f.root);
  const pointer = fs.readFileSync(path.join(f.freshDir, 'current.json'), 'utf8');
  f.wrap("fs.writeFileSync(path.join(options.outDir, 'child-started.json'), JSON.stringify({pid:process.pid})); while (true) {} ");
  const controller = new AbortController();
  const outcome = api.compileFresh(f.root, { timeoutMs: cancellation ? 20000 : 5000, signal: controller.signal })
    .then(value => ({ value }), error => ({ error }));
  const child = await started(f, outcome);
  if (cancellation) controller.abort();
  const result = await outcome;
  assert.equal(result.error?.code, cancellation ? 'compile_cancelled' : 'compile_timeout');
  assert.throws(() => process.kill(child.pid, 0), { code: 'ESRCH' });
  assert.equal(fs.readFileSync(path.join(f.freshDir, 'current.json'), 'utf8'), pointer);
  assert.deepEqual(fs.readdirSync(f.freshDir).sort(), ['current.json', first.generation].sort());
});
test('pre-cancellation and invalid timeout create no generation or lock', async t => {
  const f = fixture(t), api = f.load(), controller = new AbortController(); controller.abort();
  await assert.rejects(api.compileFresh(f.root, { signal: controller.signal }), { code: 'compile_cancelled' });
  await assert.rejects(api.compileFresh(f.root, { timeoutMs: 0 }), { code: 'invalid_compile_timeout' });
  await assert.rejects(api.compileFresh(f.root, { signal: { aborted: false } }), { code: 'invalid_compile_signal' });
  assert(!fs.existsSync(f.freshDir));
});
test('replacement lock is preserved and cannot authorize generation selection', async t => {
  const f = fixture(t), api = f.load(), first = await api.compileFresh(f.root);
  const pointer = fs.readFileSync(path.join(f.freshDir, 'current.json'), 'utf8');
  f.wrap(`const result = await canonical(options);
    const lock = path.join(options.outDir, '..', '.lock');
    fs.unlinkSync(path.join(lock, 'owner')); fs.rmdirSync(lock); fs.mkdirSync(lock);
    fs.writeFileSync(path.join(lock, 'owner'), 'other-owner'); return result;`);
  await assert.rejects(api.compileFresh(f.root), { code: 'refresh_lock_lost' });
  assert.equal(fs.readFileSync(path.join(f.freshDir, '.lock/owner'), 'utf8'), 'other-owner');
  assert.equal(fs.readFileSync(path.join(f.freshDir, 'current.json'), 'utf8'), pointer);
  assert.deepEqual(fs.readdirSync(f.freshDir).sort(), ['.lock', 'current.json', first.generation].sort());
});
for (const channel of ['stdout', 'stderr']) test(`child ${channel} is bounded and over-limit output cannot select a generation`, async t => {
  const f = fixture(t), api = f.load();
  f.wrap(`process.${channel}.write('x'.repeat(5 * 1024 * 1024)); await canonical(options);`);
  await assert.rejects(api.compileFresh(f.root), { code: 'compiler_output_limit' });
  assert.deepEqual(fs.readdirSync(f.freshDir), []);
});
test('external CommonJS dependencies are rejected instead of acquiring unbound identity', async t => {
  const f = fixture(t), api = f.load();
  fs.writeFileSync(path.join(f.copy, 'outside.js'), 'module.exports = 23;');
  f.wrap("require('../outside.js'); return canonical(options);");
  await assert.rejects(api.compileFresh(f.root), { code: 'unbound_compiler_dependency' });
  assert.deepEqual(fs.readdirSync(f.freshDir), []);
});
test('dynamic imports are refused without executing an external module', async t => {
  const f = fixture(t), api = f.load(), marker = path.join(f.temp, 'esm-ran');
  fs.writeFileSync(path.join(f.copy, 'outside.mjs'), `import fs from 'node:fs'; fs.writeFileSync(${JSON.stringify(marker)}, 'bad');`);
  f.wrap("await import('../outside.mjs'); return canonical(options);");
  await assert.rejects(api.compileFresh(f.root));
  assert(!fs.existsSync(marker)); assert.deepEqual(fs.readdirSync(f.freshDir), []);
});
test('child ignores parent NODE_OPTIONS preloads and NODE_PATH', async t => {
  const f = fixture(t), api = f.load(), preload = path.join(f.temp, 'preload.cjs'), marker = path.join(f.temp, 'preloaded');
  fs.writeFileSync(preload, `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'bad');`);
  const oldOptions = process.env.NODE_OPTIONS, oldPath = process.env.NODE_PATH;
  try {
    process.env.NODE_OPTIONS = `--require "${preload}"`; process.env.NODE_PATH = f.temp;
    const result = await api.compileFresh(f.root);
    assert.equal(result.state, 'fresh'); assert.equal(api.inspectFresh(f.root).state, 'fresh');
    assert.equal(api.inspectFresh(f.root, { includeVerification: true }).state, 'fresh');
    assert(!fs.existsSync(marker));
  } finally {
    if (oldOptions === undefined) delete process.env.NODE_OPTIONS; else process.env.NODE_OPTIONS = oldOptions;
    if (oldPath === undefined) delete process.env.NODE_PATH; else process.env.NODE_PATH = oldPath;
  }
});

// These probes use the same OS process APIs on Windows and POSIX. Node refuses
// creation before stdio inheritance, detachment or a late writer can take effect.
for (const stdio of ['inherit', 'ignore']) test(`descendant with ${stdio} stdio is refused before creation and preserves replacement lock`, async t => {
  const f = fixture(t), api = f.load(), first = await api.compileFresh(f.root);
  const pointer = fs.readFileSync(path.join(f.freshDir, 'current.json'), 'utf8');
  const marker = path.join(f.temp, 'descendant-wrote');
  f.wrap(`await canonical(options);
    fs.writeFileSync(path.join(options.outDir, '..', '.lock', 'owner'), 'replacement-owner');
    require('node:child_process').spawn(process.execPath, ['-e',
      "setTimeout(() => require('node:fs').writeFileSync(process.argv[1], 'late'), 300);", ${JSON.stringify(marker)}],
      {detached:true, stdio:${JSON.stringify(stdio)}, windowsHide:true});
    throw new Error('process creation was allowed');`);
  await assert.rejects(api.compileFresh(f.root, { timeoutMs: 5000 }), { code: 'compiler_capability_denied' });
  await delay(500);
  assert(!fs.existsSync(marker));
  assert.equal(fs.readFileSync(path.join(f.freshDir, 'current.json'), 'utf8'), pointer);
  assert.equal(fs.readFileSync(path.join(f.freshDir, '.lock/owner'), 'utf8'), 'replacement-owner');
  assert.deepEqual(fs.readdirSync(f.freshDir).sort(), ['.lock', 'current.json', first.generation].sort());
});

for (const cancellation of [false, true]) test(`${cancellation ? 'cancellation' : 'timeout'} settles after denied inherited-pipe and detached descendants`, { timeout: 15000 }, async t => {
  const f = fixture(t), api = f.load(), first = await api.compileFresh(f.root);
  const pointer = fs.readFileSync(path.join(f.freshDir, 'current.json'), 'utf8');
  const marker = path.join(f.temp, 'late-descendant-write');
  f.wrap(`await canonical(options);
    const denials = [];
    for (const stdio of ['inherit', 'ignore']) {
      try {
        require('node:child_process').spawn(process.execPath, ['-e',
          "setTimeout(() => require('node:fs').writeFileSync(process.argv[1], 'late'), 300);", ${JSON.stringify(marker)}],
          {detached:true, stdio, windowsHide:true});
      } catch (error) { denials.push([error.code, error.permission]); }
    }
    fs.writeFileSync(path.join(options.outDir, 'child-started.json'), JSON.stringify({pid:process.pid,denials}));
    while (true) {}`);
  const controller = new AbortController(), began = Date.now();
  const outcome = api.compileFresh(f.root, { timeoutMs: cancellation ? 10000 : 3000, signal: controller.signal })
    .then(value => ({ value }), error => ({ error }));
  const child = await started(f, outcome);
  assert.deepEqual(child.denials, [['ERR_ACCESS_DENIED', 'ChildProcess'], ['ERR_ACCESS_DENIED', 'ChildProcess']]);
  if (cancellation) controller.abort();
  const result = await outcome;
  assert.equal(result.error?.code, cancellation ? 'compile_cancelled' : 'compile_timeout');
  assert(Date.now() - began < 10000, 'termination must settle without inherited descendant pipes');
  assert.throws(() => process.kill(child.pid, 0), { code: 'ESRCH' });
  await delay(500);
  assert(!fs.existsSync(marker));
  assert.equal(fs.readFileSync(path.join(f.freshDir, 'current.json'), 'utf8'), pointer);
  assert.deepEqual(fs.readdirSync(f.freshDir).sort(), ['current.json', first.generation].sort());
});

test('Node denies alternate process APIs and worker threads in the captured compiler graph', async t => {
  const f = fixture(t), api = f.load();
  f.wrap(`const cp = require('node:child_process'), denials = [];
    const attempts = [
      () => cp.execFile(process.execPath, ['-e', '']),
      () => cp.execFileSync(process.execPath, ['-e', '']),
      () => cp.spawnSync(process.execPath, ['-e', '']),
      () => cp.exec('echo ecf-lifecycle-probe'),
      () => cp.execSync('echo ecf-lifecycle-probe'),
      () => cp.fork(__filename, [], {stdio:'ignore'}),
      () => new (require('node:worker_threads').Worker)('', {eval:true}),
    ];
    for (const attempt of attempts) { try { attempt(); } catch (error) { denials.push([error.code, error.permission]); } }
    if (denials.length !== attempts.length) throw new Error('creation API unexpectedly allowed');
    const result = await canonical(options);
    fs.writeFileSync(path.join(options.outDir, 'denials.json'), JSON.stringify(denials)); return result;`);
  const result = await api.compileFresh(f.root);
  assert.deepEqual(output(f, result, 'denials.json'), [
    ...Array.from({ length: 6 }, () => ['ERR_ACCESS_DENIED', 'ChildProcess']),
    ['ERR_ACCESS_DENIED', 'WorkerThreads'],
  ]);
  assert.equal(api.inspectFresh(f.root).state, 'fresh');
  assertBound(f, result, 'compile.js');
});

for (const operation of ['snapshot', 'inspect', 'verify']) test(`${operation} dependencies also cannot create descendants`, async t => {
  const f = fixture(t), api = f.load(), first = await api.compileFresh(f.root);
  const pointer = fs.readFileSync(path.join(f.freshDir, 'current.json'), 'utf8');
  const config = path.join(f.copy, 'src/core/config.js');
  fs.appendFileSync(config, `\nif (process.argv[3] === ${JSON.stringify(operation)}) require('node:child_process').spawn(process.execPath, ['-e', ''], {stdio:'ignore', detached:true, windowsHide:true});\n`);
  if (operation === 'inspect' || operation === 'verify') {
    const inspection = api.inspectFresh(f.root, { includeVerification: operation === 'verify' });
    assert.equal(inspection.state, 'unknown'); assert.equal(inspection.context, null);
    assert.equal(inspection.reason, 'compiler_capability_denied');
  } else await assert.rejects(api.compileFresh(f.root), { code: 'compiler_capability_denied' });
  assert.equal(fs.readFileSync(path.join(f.freshDir, 'current.json'), 'utf8'), pointer);
  assert.deepEqual(fs.readdirSync(f.freshDir).sort(), ['current.json', first.generation].sort());
});

test('worker bootstrap refuses execution without the runtime lifecycle restriction', t => {
  const f = fixture(t), marker = path.join(f.temp, 'compiler-module-loaded');
  fs.appendFileSync(path.join(f.copy, 'src/core/config.js'), `\nfs.writeFileSync(${JSON.stringify(marker)}, 'loaded');\n`);
  const bootstrap = fs.readFileSync(path.join(f.copy, 'src/freshness-worker.js'), 'utf8');
  const child = require('node:child_process').spawnSync(process.execPath,
    ['--eval', bootstrap, '--', 'ecf-fresh-worker', path.join(f.copy, 'src'), 'compile', f.root, path.join(f.temp, 'output')],
    { env: require('../src/freshness-worker').childEnvironment(), encoding: 'utf8', timeout: 5000, windowsHide: true });
  assert.equal(child.status, 1);
  assert.equal(JSON.parse(child.stdout).error, 'worker_lifecycle_not_restricted');
  assert(!fs.existsSync(marker));
});
