'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { PassThrough } = require('node:stream');
const { spawnSync } = require('node:child_process');
const { compileFresh } = require('../src/freshness');
const { callTool, handleMcpRequest, runMcpServer } = require('../src/mcp-server');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const query = { name: 'ecf_core.search_context', arguments: { query: 'alpha' } };
const fixedTime = new Date('2020-01-02T03:04:05.000Z');
function stableTime(filename) { fs.utimesSync(filename, fixedTime, fixedTime); }

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ecf-mcp-verified-'));
  fs.writeFileSync(path.join(root, 'README.md'), '# Alpha\nalpha value one.\n');
  fs.writeFileSync(path.join(root, 'ecf.config.json'), JSON.stringify({ project_name: 'alpha', tool_limits: { max_calls: 10 } }));
  stableTime(path.join(root, 'README.md')); stableTime(path.join(root, 'ecf.config.json'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}
function reader(t, root, api = { runMcpServer }) {
  const input = new PassThrough(), output = new PassThrough(), pending = new Map();
  let id = 0, buffer = '';
  output.on('data', chunk => {
    buffer += chunk;
    let newline;
    while ((newline = buffer.indexOf('\n')) >= 0) {
      const value = JSON.parse(buffer.slice(0, newline)); buffer = buffer.slice(newline + 1);
      pending.get(value.id)(value); pending.delete(value.id);
    }
  });
  api.runMcpServer({ verifiedProjectRoot: root, input, output });
  t.after(() => { input.end(); output.end(); });
  return (params = query, method = 'tools/call') => new Promise(resolve => {
    pending.set(++id, resolve);
    input.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  });
}
function payload(response) {
  assert.equal(response.error, undefined, JSON.stringify(response.error));
  return JSON.parse(response.result.content[0].text);
}
function refused(response) {
  assert(response.error, 'must return a JSON-RPC error');
  assert.equal(response.result, undefined, 'must not return stale content or a proof');
  assert(!JSON.stringify(response).includes('alpha value one'));
}
function editSameMetadata(filename, from, to) {
  assert.equal(Buffer.byteLength(from), Buffer.byteLength(to));
  const old = fs.statSync(filename), bytes = fs.readFileSync(filename, 'utf8');
  assert(bytes.includes(from));
  fs.writeFileSync(filename, bytes.replace(from, to));
  fs.utimesSync(filename, old.atime, old.mtime);
  assert.equal(fs.statSync(filename).size, old.size);
  assert.equal(Math.trunc(fs.statSync(filename).mtimeMs), Math.trunc(old.mtimeMs));
}

test('one long-lived MCP reader consumes all five tools with per-request digest evidence', async t => {
  const root = fixture(t), generation = await compileFresh(root), send = reader(t, root);
  const moduleCache = Object.keys(require.cache).sort();
  const jsLoader = require('node:module')._extensions['.js'];
  const listing = await send({}, 'tools/list');
  assert.equal(listing.result.tools.length, 5);
  const ids = new Set();
  for (const params of [query, { name: 'ecf_core.route_query', arguments: { query: 'alpha' } },
    { name: 'ecf_core.get_source', arguments: { path: 'README.md' } },
    { name: 'ecf_core.get_policy' }, { name: 'ecf_core.get_manifest' }]) {
    const value = payload(await send(params)), proof = value.verified_consumption;
    assert.equal(proof.request_verified, true);
    assert.equal(proof.host_consumption_verified, false);
    assert.equal(proof.reader_pid, process.pid);
    assert.equal(proof.generation, generation.generation);
    assert.equal(proof.reader_digest, proof.compiler_digest);
    assert(proof.reader_loaded_modules.some(row => row[0] === 'mcp-server.js'));
    assert(proof.reader_loaded_modules.some(row => row[0] === 'core/ranking.js'));
    assert.equal(proof.consumed_artifacts.length, 7);
    for (const [file, digest] of proof.consumed_artifacts) {
      assert.equal(digest, new Map(proof.artifacts).get(file));
      assert.equal(digest, hash(fs.readFileSync(path.join(root, '.ecf-core/fresh', proof.generation, file))));
    }
    for (const key of ['seal_hash', 'snapshot_digest', 'source_digest', 'config_hash', 'compiler_digest']) assert.match(proof[key], /^[a-f0-9]{64}$/);
    const { verified_consumption, ...response } = value;
    assert.equal(proof.response_sha256, hash(JSON.stringify(response)));
    assert(!ids.has(proof.request_id)); ids.add(proof.request_id);
  }
  const seal = JSON.parse(fs.readFileSync(path.join(root, '.ecf-core/fresh', generation.generation, 'freshness.json')));
  assert.equal(seal.host_consumption_verified, false);
  assert.deepEqual(Object.keys(require.cache).sort(), moduleCache);
  assert.equal(require('node:module')._extensions['.js'], jsLoader);
});

for (const mutation of ['source', 'configuration', 'artifact']) test(`same-size restored-mtime ${mutation} invalidates the next request`, async t => {
  const root = fixture(t), generation = await compileFresh(root), send = reader(t, root);
  payload(await send());
  if (mutation === 'source') editSameMetadata(path.join(root, 'README.md'), 'one', 'two');
  if (mutation === 'configuration') editSameMetadata(path.join(root, 'ecf.config.json'), '10', '11');
  if (mutation === 'artifact') {
    const dir = path.join(root, '.ecf-core/fresh', generation.generation);
    stableTime(path.join(dir, 'context-packet.json'));
    // Prime ordinary serving; verified mode must independently refuse tampering.
    callTool({ artifactDir: dir, name: query.name, args: query.arguments });
    editSameMetadata(path.join(dir, 'context-packet.json'), 'one', 'two');
  }
  refused(await send());
  refused(await send()); // The previous response must never be reused.
});

test('explicit refresh consumes the new generation in the same MCP process', async t => {
  const root = fixture(t), first = await compileFresh(root), send = reader(t, root);
  const old = payload(await send());
  editSameMetadata(path.join(root, 'README.md'), 'one', 'two');
  refused(await send());
  const second = await compileFresh(root), current = payload(await send());
  assert.notEqual(first.generation, second.generation);
  assert.equal(current.verified_consumption.generation, second.generation);
  assert.notEqual(old.verified_consumption.source_digest, current.verified_consumption.source_digest);
  assert.notEqual(old.verified_consumption.request_id, current.verified_consumption.request_id);
  assert(JSON.stringify(current.results).includes('alpha value two'));
  assert(!JSON.stringify(current.results).includes('alpha value one'));
});

test('source drift after response computation discards the response', async t => {
  const root = fixture(t); await compileFresh(root);
  const original = JSON.stringify;
  let changed = false;
  t.mock.method(JSON, 'stringify', function (value, ...args) {
    const result = original(value, ...args);
    if (!changed && value?.schema_version === 'ecf-core.mcp.search-result.v1') {
      changed = true; editSameMetadata(path.join(root, 'README.md'), 'one', 'two');
    }
    return result;
  });
  refused(await reader(t, root)());
  assert(changed);
});

test('generation switch after response computation discards the response', async t => {
  const root = fixture(t); await compileFresh(root);
  const pointer = path.join(root, '.ecf-core/fresh/current.json'), first = fs.readFileSync(pointer);
  await compileFresh(root);
  const second = fs.readFileSync(pointer); fs.writeFileSync(pointer, first);
  const original = JSON.stringify;
  let changed = false;
  t.mock.method(JSON, 'stringify', function (value, ...args) {
    const result = original(value, ...args);
    if (!changed && value?.schema_version === 'ecf-core.mcp.search-result.v1') {
      changed = true; fs.writeFileSync(pointer, second);
    }
    return result;
  });
  refused(await reader(t, root)());
  assert(changed);
});

test('hashes the actual consumed buffer even if an artifact is restored before post-inspection', async t => {
  const root = fixture(t), generation = await compileFresh(root);
  const file = path.join(root, '.ecf-core/fresh', generation.generation, 'context-packet.json');
  stableTime(file);
  const bytes = fs.readFileSync(file), stat = fs.statSync(file);
  const originalOpen = fs.openSync, originalClose = fs.closeSync;
  let armed = true, targetFd;
  t.mock.method(fs, 'openSync', function (filename, flags, ...args) {
    if (armed && path.resolve(String(filename)) === file && typeof flags === 'number') {
      armed = false; editSameMetadata(file, 'one', 'two');
      targetFd = originalOpen.call(fs, filename, flags, ...args); return targetFd;
    }
    return originalOpen.call(fs, filename, flags, ...args);
  });
  t.mock.method(fs, 'closeSync', function (fd) {
    const result = originalClose.call(fs, fd);
    if (fd === targetFd) {
      targetFd = undefined; fs.writeFileSync(file, bytes); fs.utimesSync(file, stat.atime, stat.mtime);
    }
    return result;
  });
  refused(await reader(t, root)());
  assert(!armed); assert.deepEqual(fs.readFileSync(file), bytes);
});

test('cached reader/ranking A executes captured B or refuses, never seals A as B', async t => {
  const root = fixture(t), copy = path.join(os.tmpdir(), `ecf-reader-copy-${path.basename(root)}`);
  fs.mkdirSync(copy);
  fs.cpSync(path.resolve(__dirname, '../src'), path.join(copy, 'src'), { recursive: true });
  fs.copyFileSync(path.resolve(__dirname, '../package.json'), path.join(copy, 'package.json'));
  t.after(() => {
    for (const key of Object.keys(require.cache)) if (key.startsWith(copy + path.sep)) delete require.cache[key];
    fs.rmSync(copy, { recursive: true, force: true });
  });
  const api = require(path.join(copy, 'src/mcp-server.js')); // Cache A.
  const ranking = path.join(copy, 'src/core/ranking.js');
  fs.appendFileSync(ranking, '\nconst originalRank = module.exports.rankRecords;\nmodule.exports.rankRecords = (...args) => ({...originalRank(...args), ranking_mode:"captured_reader_B"});\n');
  const generation = await require(path.join(copy, 'src/freshness.js')).compileFresh(root);
  const value = payload(await reader(t, root, api)());
  assert.equal(value.ranking.mode, 'captured_reader_B');
  assert.equal(value.verified_consumption.generation, generation.generation);
  const loaded = new Map(value.verified_consumption.reader_loaded_modules);
  assert.equal(loaded.get('core/ranking.js'), hash(fs.readFileSync(ranking)));
});

test('default remains off; verified mode refuses unsupported tools, overrides and missing generations', async t => {
  const root = fixture(t);
  const listing = handleMcpRequest({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
  assert.equal(listing.result.tools.length, 11);
  assert.throws(() => require('../src/mcp-server').callVerifiedTool({ verifiedProjectRoot: root, name: query.name }), { code: 'verified_reader_not_bound' });
  assert.throws(() => callTool({ verifiedProjectRoot: root, name: 'ecf_core.work_memory' }), { code: 'tool_not_supported_in_verified_mode' });
  assert.throws(() => callTool({ verifiedProjectRoot: root, artifactDir: root, name: query.name }), { code: 'verified_artifact_override_not_allowed' });
  assert.throws(() => callTool({ verifiedProjectRoot: root, name: query.name, args: { query: 'a'.repeat(65536) } }), { code: 'verified_request_limit' });
  refused(await reader(t, root)());
  assert(!fs.existsSync(path.join(root, '.ecf-core')), 'read must not compile or activate');
});

test('CLI opt-in selects verified reads without writing host configuration', async t => {
  const root = fixture(t); await compileFresh(root);
  const cli = path.resolve(__dirname, '../bin/ecf-core.js');
  const child = spawnSync(process.execPath, [cli, 'serve-mcp', '--verified-project', root], {
    input: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: query }) + '\n',
    encoding: 'utf8', windowsHide: true, timeout: 30000,
  });
  assert.equal(child.status, 0, child.stderr);
  const value = payload(JSON.parse(child.stdout));
  assert.equal(value.verified_consumption.reader_pid, child.pid);
  assert.equal(value.verified_consumption.host_consumption_verified, false);
  const override = spawnSync(process.execPath, [cli, 'serve-mcp', root, '--verified-project', root], { encoding: 'utf8', windowsHide: true });
  assert.notEqual(override.status, 0);
});
