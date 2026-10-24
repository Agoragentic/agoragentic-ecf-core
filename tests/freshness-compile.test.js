'use strict';
// Producer/consumer integration against the real ECF compiler; no replacement artifact mocks.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { compileFresh, inspectFresh } = require('../src/freshness');
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ecf-generation-'));
  fs.writeFileSync(path.join(root, 'README.md'), '# Example\nA local context fixture.\n');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}
test('canonical compile, stale read refusal, and explicit refresh use distinct generations', async t => {
  const root = fixture(t), first = await compileFresh(root);
  assert.equal(first.state, 'fresh');
  const read = inspectFresh(root, { includeContext: true });
  assert.equal(read.state, 'fresh'); assert.equal(read.context.schema_version, 'ecf-core.context-packet.v1');
  assert.equal(read.host_consumption_verified, false);
  fs.writeFileSync(path.join(root, 'README.md'), '# Changed\nNew source content.\n');
  const stale = inspectFresh(root, { includeContext: true });
  assert.equal(stale.state, 'stale'); assert.equal(stale.context, null);
  const second = await compileFresh(root);
  assert.notEqual(first.generation, second.generation);
  assert.equal(inspectFresh(root).state, 'fresh');
  fs.writeFileSync(path.join(root, 'ecf.config.json'), JSON.stringify({ tool_limits: { max_calls: 2 } }));
  assert.equal(inspectFresh(root, { includeContext: true }).context, null);
});
test('artifact substitution is rejected even with unchanged source', async t => {
  const root = fixture(t), result = await compileFresh(root);
  const file = path.join(root, '.ecf-core', 'fresh', result.generation, 'context-packet.json');
  const packet = JSON.parse(fs.readFileSync(file, 'utf8')); packet.scope = 'changed';
  fs.writeFileSync(file, JSON.stringify(packet));
  const read = inspectFresh(root, { includeContext: true });
  assert.equal(read.state, 'unknown'); assert.equal(read.reason, 'artifact_changed'); assert.equal(read.context, null);
});
test('failed refresh preserves prior selection and releases only its own lock', async t => {
  const root = fixture(t); await compileFresh(root);
  const pointer = path.join(root, '.ecf-core', 'fresh', 'current.json');
  const before = fs.readFileSync(pointer, 'utf8');
  await assert.rejects(compileFresh(root, { compile: async () => { throw new Error('synthetic failure'); } }));
  assert.equal(fs.readFileSync(pointer, 'utf8'), before);
  assert.equal(inspectFresh(root).state, 'fresh');
  assert(!fs.existsSync(path.join(root, '.ecf-core', 'fresh', '.lock')));
});
test('existing refresh lock is not stolen', async t => {
  const root = fixture(t); await compileFresh(root);
  const lock = path.join(root, '.ecf-core', 'fresh', '.lock'); fs.mkdirSync(lock);
  await assert.rejects(compileFresh(root), { code: 'refresh_locked' }); assert(fs.existsSync(lock));
});
test('source drift during compile leaves no selected generation', async t => {
  const root = fixture(t);
  await assert.rejects(compileFresh(root, { compile: async () => { fs.writeFileSync(path.join(root, 'README.md'), 'changed'); } }), { code: 'source_changed_during_compile' });
  assert.equal(inspectFresh(root).state, 'unknown');
});
test('test compiler output cannot become current context', async t => {
  const root = fixture(t);
  const result = await compileFresh(root, { compile: async ({ outDir }) => {
    for (const f of ['context-packet.json', 'policy-summary.json', 'source-map.json']) fs.writeFileSync(path.join(outDir, f), '{}');
  } });
  assert.equal(result.state, 'test_only');
  assert.equal(inspectFresh(root).reason, 'test_generation_not_current_context');
});
