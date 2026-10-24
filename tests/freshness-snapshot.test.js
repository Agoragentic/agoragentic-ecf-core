'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { captureSnapshot, readBounded, inspectFresh } = require('../src/freshness');
const config = { allow: ['src/**', '*.md'], block: ['secrets/**'] };
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ecf-fresh-'));
  fs.mkdirSync(path.join(root, 'src'));
  fs.writeFileSync(path.join(root, 'src', 'a.js'), 'export const n=1;');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}
test('same files and policy produce deterministic snapshot without source contents', t => {
  const root = fixture(t), a = captureSnapshot(root, config);
  assert.deepEqual(a, captureSnapshot(root, config));
  assert(!JSON.stringify(a).includes('export const'));
});
test('same-size source edit is detected even when mtime is restored', t => {
  const root = fixture(t), file = path.join(root, 'src', 'a.js'), old = fs.statSync(file);
  const a = captureSnapshot(root, config);
  fs.writeFileSync(file, 'export const n=2;'); fs.utimesSync(file, old.atime, old.mtime);
  assert.notEqual(a.digest, captureSnapshot(root, config).digest);
});
test('policy change changes freshness independently of source bytes', t => {
  const root = fixture(t);
  assert.notEqual(captureSnapshot(root, config).digest, captureSnapshot(root, { ...config, tool_limits: { write_allowed: false } }).digest);
});
test('new source and deleted source change inventory', t => {
  const root = fixture(t), a = captureSnapshot(root, config);
  fs.writeFileSync(path.join(root, 'src', 'b.js'), 'b');
  assert.notEqual(a.digest, captureSnapshot(root, config).digest);
  fs.unlinkSync(path.join(root, 'src', 'a.js'));
  assert.equal(captureSnapshot(root, config).files.length, 1);
});
test('generated and blocked data are excluded without reading their contents', t => {
  const root = fixture(t), a = captureSnapshot(root, config);
  for (const name of ['.ecf-core', '.micro-ecf', 'secrets']) { fs.mkdirSync(path.join(root, name)); fs.writeFileSync(path.join(root, name, 'private.md'), 'private'); }
  assert.deepEqual(a, captureSnapshot(root, config));
});
test('input outside byte limit is rejected before content allocation', t => {
  const root = fixture(t), file = path.join(root, 'src', 'large.js');
  fs.writeFileSync(file, Buffer.alloc(2 * 1024 * 1024 + 1));
  assert.throws(() => captureSnapshot(root, config), { code: 'file_limit' });
  assert.throws(() => readBounded(file, 32), { code: 'file_limit' });
});
test('missing generation produces unknown with no context', t => {
  const result = inspectFresh(fixture(t), { includeContext: true });
  assert.equal(result.state, 'unknown'); assert.equal(result.context, null);
});
test('directories cannot be read as regular files', t => {
  assert.throws(() => readBounded(fixture(t)), { code: 'file_limit' });
});
