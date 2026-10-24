'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { captureSnapshot, compileFresh, inspectFresh } = require('../src/freshness');
const config = { allow: ['*.js', '*.md', 'src/**'], block: ['.env', 'secrets/**'] };
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ecf-review-'));
  fs.writeFileSync(path.join(root, 'README.md'), '# Review fixture\nLocal context.\n');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}
test('snapshot includes allowed regular files matching directory-skip names', t => {
  const root = fixture(t);
  for (const name of ['temp-context.js', 'temp_context.js', 'temp.js']) fs.writeFileSync(path.join(root, name), 'module.exports=1;');
  const before = captureSnapshot(root, config);
  for (const name of ['temp-context.js', 'temp_context.js', 'temp.js']) assert(before.files.some(f => f[0] === name));
  fs.writeFileSync(path.join(root, 'temp-context.js'), 'module.exports=2;');
  assert.notEqual(before.digest, captureSnapshot(root, config).digest);
});
test('snapshot still excludes actual skipped directories', t => {
  const root = fixture(t), before = captureSnapshot(root, config);
  for (const name of ['temp-work', '.ecf-core', 'secrets']) {
    fs.mkdirSync(path.join(root, name)); fs.writeFileSync(path.join(root, name, 'a.js'), 'ignored');
  }
  assert.deepEqual(before, captureSnapshot(root, config));
});
for (const [name, classification] of [['.env', 'blocked'], ['review.bin', 'review_required']]) test(`snapshot tracks ${classification} metadata without opening content`, t => {
  const root = fixture(t), filename = path.join(root, name), first = captureSnapshot(root, config);
  fs.writeFileSync(filename, 'private fixture bytes');
  const original = fs.openSync;
  t.mock.method(fs, 'openSync', function (file, ...args) {
    assert.notEqual(path.resolve(String(file)), filename, 'restricted content must never be opened');
    return original.call(fs, file, ...args);
  });
  const added = captureSnapshot(root, config);
  assert.notEqual(first.digest, added.digest);
  assert.equal(added.restricted_inventory[0][1], classification);
  assert(!JSON.stringify(added).includes('private fixture bytes'));
  const edit = original.call(fs, filename, 'r+');
  try { fs.ftruncateSync(edit, 2); } finally { fs.closeSync(edit); }
  const resized = captureSnapshot(root, config);
  assert.notEqual(added.digest, resized.digest);
  fs.unlinkSync(filename);
  assert.equal(first.digest, captureSnapshot(root, config).digest);
});
test('canonical walker and snapshot retain the same regular-file inventory', t => {
  const { walkFiles } = require('../src/adapters/filesystem');
  const root = fixture(t);
  for (const name of ['temp-context.js', '.env', 'review.bin']) fs.writeFileSync(path.join(root, name), 'fixture');
  fs.mkdirSync(path.join(root, 'temp-skip')); fs.writeFileSync(path.join(root, 'temp-skip', 'a.js'), 'ignore');
  const snapshot = captureSnapshot(root, config);
  const actual = [...snapshot.files, ...snapshot.restricted_inventory].map(x => x[0]).sort();
  assert.deepEqual(actual, walkFiles(root, config).map(p => path.relative(root, p).split(path.sep).join('/')).sort());
});
test('canonical generation refuses a changed allowed temp-context.js', async t => {
  const root = fixture(t), file = path.join(root, 'temp-context.js');
  fs.writeFileSync(file, 'module.exports=1;');
  await compileFresh(root);
  assert.equal(inspectFresh(root).state, 'fresh');
  fs.writeFileSync(file, 'module.exports=2;');
  const stale = inspectFresh(root, { includeContext: true });
  assert.equal(stale.state, 'stale'); assert.equal(stale.context, null);
});
test('canonical generation becomes stale when restricted inventory changes', async t => {
  const root = fixture(t); await compileFresh(root);
  fs.writeFileSync(path.join(root, '.env'), 'private fixture bytes');
  assert.equal(inspectFresh(root, { includeContext: true }).state, 'stale');
  assert.equal(inspectFresh(root, { includeContext: true }).context, null);
  const refreshed = await compileFresh(root);
  const map = fs.readFileSync(path.join(root, '.ecf-core', 'fresh', refreshed.generation, 'source-map.json'), 'utf8');
  assert(map.includes('.env')); assert(!map.includes('private fixture bytes'));
  assert.equal(inspectFresh(root).state, 'fresh');
  fs.unlinkSync(path.join(root, '.env'));
  assert.equal(inspectFresh(root).state, 'stale');
});
test('CLI reports fresh exit zero and stale exit two with no context', t => {
  const root = fixture(t), cli = path.resolve(__dirname, '../scripts/fresh-context.cjs');
  const run = command => spawnSync(process.execPath, [cli, command, root], { encoding: 'utf8', shell: false, timeout: 30000 });
  const compiled = run('compile'); assert.equal(compiled.status, 0, compiled.stderr);
  const fresh = run('read'); assert.equal(fresh.status, 0, fresh.stderr); assert.equal(JSON.parse(fresh.stdout).state, 'fresh');
  fs.writeFileSync(path.join(root, 'README.md'), '# Changed\n');
  const stale = run('read'); assert.equal(stale.status, 2, stale.stderr);
  assert.equal(JSON.parse(stale.stdout).context, null);
  assert.equal(run('status').status, 2);
});
