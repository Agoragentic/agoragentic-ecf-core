'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { createHash } = require('node:crypto');
const { MarkdownDocsAdapter } = require('../src/adapters/markdown-docs');
const { compileProject } = require('../src/compile');
const { createDefaultConfig } = require('../src/core/config');

const digest = text => createHash('sha256').update(text).digest('hex');

function fixture(t, text) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ecf-markdown-redaction-'));
    fs.writeFileSync(path.join(root, 'README.md'), text);
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    return root;
}

async function sections(root) {
    return new MarkdownDocsAdapter().discover({ projectRoot: root, config: createDefaultConfig() });
}

test('Markdown section summaries redact sensitive assignments while retaining source provenance', async t => {
    const text = '# Setup\n\npassword=synthetic-markdown-fixture-one\n';
    const root = fixture(t, text);
    const [record] = await sections(root);
    assert.equal(record.path, 'README.md#setup');
    assert.equal(record.heading, 'Setup');
    assert.equal(record.summary, 'Setup: password=[REDACTED]');
    assert.equal(record.content_preview, '# Setup\n\npassword=[REDACTED]');
    assert.equal(record.hash, digest(text.trim()));
    assert.equal(record.byte_count, Buffer.byteLength(text.trim()));
    assert.equal(record.classification, 'allowed');

    const changed = text.replace('fixture-one', 'fixture-two');
    fs.writeFileSync(path.join(root, 'README.md'), changed);
    const [next] = await sections(root);
    assert.equal(next.summary, record.summary);
    assert.equal(next.content_preview, record.content_preview);
    assert.notEqual(next.hash, record.hash);
    assert.equal(next.hash, digest(changed.trim()));
});

test('recognized credential values in headings do not leak through section citations or metadata', async t => {
    const marker = 'sk-test-syntheticMarkdownOnly123';
    const text = `# Setup ${marker}\n\nLocal setup guidance.\n`;
    const root = fixture(t, text);
    const [record] = await sections(root);
    assert.equal(record.heading, 'Setup [REDACTED]');
    assert.equal(record.path, 'README.md#setup-redacted');
    assert.equal(record.summary, 'Setup [REDACTED]: Local setup guidance.');
    assert.equal(JSON.stringify(record).includes(marker), false);
    assert.equal(record.hash, digest(text.trim()));
});

test('sensitive assignments in headings are redacted in every exposed section field', async t => {
    const marker = 'synthetic-heading-password';
    const text = `## password=${marker}\n\nLocal setup guidance.\n`;
    const root = fixture(t, text);
    const [record] = await sections(root);
    assert.equal(record.heading, 'password=[REDACTED]');
    assert.equal(record.path, 'README.md#password-redacted');
    assert.equal(record.summary, 'password=[REDACTED]: Local setup guidance.');
    assert.equal(record.content_preview, '## password=[REDACTED]\n\nLocal setup guidance.');
    assert.equal(JSON.stringify(record).includes(marker), false);
    assert.equal(record.hash, digest(text.trim()));
});

test('compiled artifacts retain safe Markdown context without redacted credential values', async t => {
    const password = 'synthetic-compiled-fixture-password';
    const marker = 'sk-test-syntheticArtifactOnly123';
    const text = `# Setup ${marker}\n\npassword=${password}\n\n## Usage\n\nUse the local CLI.\n`;
    const root = fixture(t, text);
    const outDir = path.join(root, '.ecf-core');
    const result = await compileProject({ projectRoot: root, outDir, emitAgentOs: true });
    assert.ok(result.contextPacket.sources.some(source => source.path === 'README.md#usage'));
    assert.equal(result.agentOsImport.live_deploy_allowed, false);
    for (const name of fs.readdirSync(outDir)) {
        const artifact = path.join(outDir, name);
        if (!fs.statSync(artifact).isFile()) continue;
        const output = fs.readFileSync(artifact, 'utf8');
        assert.equal(output.includes(password), false, `${name} exposed a sensitive assignment`);
        assert.equal(output.includes(marker), false, `${name} exposed a credential from a heading`);
        assert.equal(output.includes(marker.toLowerCase()), false, `${name} exposed a credential in a citation`);
    }
});
