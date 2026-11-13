'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { createHash } = require('node:crypto');
const { redactSensitiveText, FilesystemAdapter } = require('../src/adapters/filesystem');
const { createDefaultConfig } = require('../src/core/config');
const { compileProject } = require('../src/compile');

test('compact JSON redacts sensitive fields in nested objects and arrays', () => {
    const input = [{ name: 'local', settings: { password: 'synthetic-json-password', retries: 3 } },
        { api_key: 'synthetic-json-key', enabled: true, count: 0 }];
    const output = redactSensitiveText(JSON.stringify(input));
    assert.deepEqual(JSON.parse(output), [
        { name: 'local', settings: { password: '[REDACTED]', retries: 3 } },
        { api_key: '[REDACTED]', enabled: true, count: 0 },
    ]);
});

test('sensitive JSON containers are removed as whole values while output stays valid', () => {
    const input = { connectionStrings: { local: 'synthetic-json-connection', options: [1, { value: 'synthetic-json-child' }] },
        token: ['synthetic-json-token', null], password: 12345, secret: false, name: 'safe' };
    const output = redactSensitiveText(JSON.stringify(input, null, 2));
    assert.deepEqual(JSON.parse(output), { connectionStrings: '[REDACTED]', token: '[REDACTED]',
        password: '[REDACTED]', secret: '[REDACTED]', name: 'safe' });
    assert.equal(output.includes('synthetic-json-'), false);
});

test('escaped and duplicate sensitive JSON keys are all redacted without object-key mutation', () => {
    const input = '{"pass\\u0077ord":"synthetic-first","password":"synthetic-second","nested":{"to\\u006ben":"synthetic-third"},"__proto__":{"safe":"retained"}}';
    const output = redactSensitiveText(input);
    assert.equal(output.includes('synthetic-'), false);
    assert.equal((output.match(/\[REDACTED\]/g) || []).length, 3);
    assert.equal(JSON.parse(output).__proto__.safe, 'retained');
    assert.equal(Object.getPrototypeOf(JSON.parse(output)), Object.prototype);
});

test('JSON redaction preserves safe source bytes including exact numbers, escapes and spacing', () => {
    const input = '{ "precise":900719925474099312345, "exponent":1.2300e+45, "negativeZero":-0,\n "text":"brace } and quote \\" plus unicode \\u0061", "password" : "synthetic-format-value", "empty": [] }';
    const expected = input.replace('"synthetic-format-value"', '"[REDACTED]"');
    assert.doesNotThrow(() => JSON.parse(input), 'the precision/escape fixture must be valid JSON');
    assert.equal(redactSensitiveText(input), expected);
});

test('recognized credential values and existing non-JSON redaction remain active', () => {
    const marker = 'sk-test-syntheticJsonMarkerOnly123';
    assert.equal(JSON.parse(redactSensitiveText(JSON.stringify({ note: marker }))).note, '[REDACTED]');
    assert.equal(redactSensitiveText('password=synthetic-assignment\nname=local'), 'password=[REDACTED]\nname=local');
    assert.equal(redactSensitiveText('token: synthetic-yaml\nname: local'), 'token: [REDACTED]\nname: local');
    const encoded = '{"note":"\\u0073k-test-syntheticEscapedMarker123"}';
    assert.equal(JSON.parse(redactSensitiveText(encoded)).note, '[REDACTED]');
});

test('complete JSON examples in Markdown are redacted before section extraction', () => {
    const input = '# Setup\n{"password":"synthetic-inline-json","token":"synthetic-inline-token"}\n\n```json\n{\n  "secret": {\n    "value": "synthetic-fenced-child"\n  },\n  "name": "safe"\n}\n```\n';
    const output = redactSensitiveText(input);
    assert.equal(output.includes('synthetic-'), false);
    assert.ok(output.includes('"name": "safe"'));
    assert.ok(output.startsWith('# Setup\n'));
    assert.equal(redactSensitiveText(output), output);
});

test('multiple quoted property assignments on one line are all redacted', () => {
    const input = '  "password":"synthetic-property-password", "token":{"nested":"synthetic-property-child"}, "name":"safe",  \r';
    assert.equal(redactSensitiveText(input), '  "password":"[REDACTED]", "token":"[REDACTED]", "name":"safe",  \r');
});

test('deep sensitive JSON containers are handled iteratively and safe JSON is unchanged', () => {
    const safe = '{"name":"local","array":[null,true,false,{},[],"quoted \\" text"],"count":1e999}';
    assert.doesNotThrow(() => JSON.parse(safe));
    assert.equal(redactSensitiveText(safe), safe);
    const input = '{"password":' + '['.repeat(512) + '"synthetic-deep-value"' + ']'.repeat(512) + ',"safe":true}';
    assert.equal(redactSensitiveText(input), '{"password":"[REDACTED]","safe":true}');
});

test('compiled JSON artifacts redact credentials but retain original source provenance', async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ecf-json-redaction-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const source = '{"project":"local","nested":{"password":"synthetic-artifact-json-password"}}';
    const sourceFile = path.join(root, 'settings.json');
    fs.writeFileSync(sourceFile, source);
    const additional = {
        'compact.json': '{"password":"synthetic-compact-password"}',
        'multiple.json': '{"password":"synthetic-multiple-password","token":"synthetic-multiple-token","name":"safe"}',
        'containers.json': JSON.stringify({ secret: { child: 'synthetic-container-child' }, name: 'safe' }, null, 2),
        'README.md': '# JSON examples\n{"password":"synthetic-markdown-json"}\n\n```json\n{\n  "secret": {\n    "value": "synthetic-markdown-child"\n  }\n}\n```\n\n"password":"synthetic-property-password","token":"synthetic-property-token"\n',
    };
    for (const [name, text] of Object.entries(additional)) fs.writeFileSync(path.join(root, name), text);
    const outDir = path.join(root, '.ecf-core');
    const result = await compileProject({ projectRoot: root, outDir, emitAgentOs: true });
    const record = result.contextPacket.sources.find(item => item.path === 'settings.json');
    assert.ok(record);
    assert.equal(record.hash, createHash('sha256').update(source).digest('hex'));
    for (const [name, text] of Object.entries(additional)) {
        const entry = result.contextPacket.sources.find(item => item.path === name);
        assert.ok(entry, `${name} must participate in compilation`);
        assert.equal(entry.hash, createHash('sha256').update(text).digest('hex'));
    }
    assert.equal(result.agentOsImport.live_deploy_allowed, false);
    const markers = ['synthetic-artifact-json-password', 'synthetic-compact-password', 'synthetic-multiple-password',
        'synthetic-multiple-token', 'synthetic-container-child', 'synthetic-markdown-json', 'synthetic-markdown-child',
        'synthetic-property-password', 'synthetic-property-token'];
    for (const marker of markers) assert.equal(JSON.stringify(result).includes(marker), false, 'compiled return values exposed a JSON credential');
    for (const name of fs.readdirSync(outDir)) {
        const artifact = path.join(outDir, name);
        if (!fs.statSync(artifact).isFile()) continue;
        const output = fs.readFileSync(artifact, 'utf8');
        for (const marker of markers) assert.equal(output.includes(marker), false, `${name} exposed a sensitive JSON value`);
    }
    const before = (await new FilesystemAdapter().discover({ projectRoot: root, config: createDefaultConfig() })).find(item => item.path === 'settings.json');
    fs.writeFileSync(sourceFile, source.replace('json-password', 'json-replacement'));
    const after = (await new FilesystemAdapter().discover({ projectRoot: root, config: createDefaultConfig() })).find(item => item.path === 'settings.json');
    assert.notEqual(after.hash, before.hash);
    assert.equal(after.content_preview, before.content_preview);
});
