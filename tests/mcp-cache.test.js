'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { callTool, handleMcpRequest } = require('../src/mcp-server');

function fixture(t) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ecf-mcp-cache-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    return root;
}

function write(root, name, value) {
    const file = path.join(root, name);
    fs.writeFileSync(file, JSON.stringify(value));
    // A fixed whole-second timestamp makes preserved metadata deterministic.
    const stamp = new Date('2026-01-01T00:00:00Z');
    fs.utimesSync(file, stamp, stamp);
    return fs.statSync(file);
}

function policy(root) {
    return callTool({ artifactDir: root, name: 'ecf_core.get_policy' }).policy_summary;
}

test('same-size, same-mtime policy replacement invalidates the long-lived cache', (t) => {
    const root = fixture(t);
    const original = write(root, 'policy-summary.json', { mode: 'read' });
    assert.equal(policy(root).mode, 'read');
    const replaced = write(root, 'policy-summary.json', { mode: 'deny' });
    assert.equal(replaced.size, original.size);
    assert.equal(replaced.mtimeMs, original.mtimeMs);
    assert.equal(policy(root).mode, 'deny');
});

test('source lookup and search reindex replaced bytes with unchanged metadata', (t) => {
    const root = fixture(t);
    const packet = (word) => ({ sources: [{ id: 'src_fixture', path: 'fixture.md', summary: word }] });
    const source = () => callTool({ artifactDir: root, name: 'ecf_core.get_source', args: { source_id: 'src_fixture' } });
    const original = write(root, 'context-packet.json', packet('alpha'));
    assert.equal(source().source.summary, 'alpha');
    const replaced = write(root, 'context-packet.json', packet('omega'));
    assert.equal(replaced.size, original.size);
    assert.equal(replaced.mtimeMs, original.mtimeMs);
    assert.equal(source().source.summary, 'omega');
    const response = handleMcpRequest({ jsonrpc: '2.0', id: 1, method: 'tools/call',
        params: { name: 'ecf_core.search_context', arguments: { query: 'omega' } } }, { artifactDir: root });
    const result = JSON.parse(response.result.content[0].text);
    assert.equal(result.results.length, 1);
    assert.equal(result.results[0].summary, 'omega');
});

test('unchanged bytes reuse indexed artifacts even when the timestamp changes', (t) => {
    const root = fixture(t);
    write(root, 'policy-summary.json', { mode: 'read' });
    const first = policy(root);
    fs.utimesSync(path.join(root, 'policy-summary.json'), new Date(), new Date());
    assert.strictEqual(policy(root), first);
});

test('malformed replacement is rejected instead of returning cached policy', (t) => {
    const root = fixture(t);
    const original = write(root, 'policy-summary.json', { mode: 'read' });
    assert.equal(policy(root).mode, 'read');
    const file = path.join(root, 'policy-summary.json');
    fs.writeFileSync(file, '!'.repeat(original.size));
    fs.utimesSync(file, original.atime, original.mtime);
    assert.throws(() => policy(root), SyntaxError);
    write(root, 'policy-summary.json', { mode: 'deny' });
    assert.equal(policy(root).mode, 'deny');
});

test('deleted artifacts are not served from cache and recreation is observed', (t) => {
    const root = fixture(t);
    write(root, 'policy-summary.json', { mode: 'read' });
    policy(root);
    fs.unlinkSync(path.join(root, 'policy-summary.json'));
    assert.throws(() => policy(root), /policy-summary\.json is missing/);
    write(root, 'policy-summary.json', { mode: 'deny' });
    assert.equal(policy(root).mode, 'deny');
});

test('read errors are surfaced instead of returning a previous cached result', (t) => {
    const root = fixture(t);
    write(root, 'policy-summary.json', { mode: 'read' });
    policy(root);
    const originalRead = fs.readFileSync;
    t.mock.method(fs, 'readFileSync', function (file, ...args) {
        if (file === path.join(root, 'policy-summary.json')) {
            throw Object.assign(new Error('synthetic permission denial'), { code: 'EACCES' });
        }
        return originalRead.call(this, file, ...args);
    });
    assert.throws(() => policy(root), { code: 'EACCES' });
});

test('the cache key and parsed value use the same captured bytes', (t) => {
    const root = fixture(t);
    write(root, 'policy-summary.json', { mode: 'read' });
    const originalRead = fs.readFileSync;
    let reads = 0;
    t.mock.method(fs, 'readFileSync', function (file, ...args) {
        const bytes = originalRead.call(this, file, ...args);
        if (file === path.join(root, 'policy-summary.json')) {
            reads += 1;
            write(root, 'policy-summary.json', { mode: 'deny' });
        }
        return bytes;
    });
    assert.equal(policy(root).mode, 'read');
    assert.equal(reads, 1);
    assert.equal(policy(root).mode, 'deny');
    assert.equal(reads, 2);
});
