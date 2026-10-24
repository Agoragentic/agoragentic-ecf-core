'use strict';

const path = require('node:path');
const { ContextAdapter } = require('./base');
const { fileType, previewText, readAdmittedSource, summarizeText, walkFiles } = require('./filesystem');
const { sha256, sourceId } = require('../core/hash');
const { classifyPath, normalizePath } = require('../core/policy');

function slug(value) {
    return String(value || '')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 80) || 'section';
}

function extractMarkdownSections(text) {
    const lines = text.split(/\r?\n/);
    const sections = [];
    let current = null;

    for (const line of lines) {
        const match = /^(#{1,6})\s+(.+?)\s*$/.exec(line);
        if (match) {
            if (current) sections.push(current);
            current = {
                level: match[1].length,
                heading: match[2].trim(),
                lines: [line],
            };
            continue;
        }
        if (current) current.lines.push(line);
    }
    if (current) sections.push(current);
    return sections;
}

class MarkdownDocsAdapter extends ContextAdapter {
    constructor() {
        super({
            name: 'markdown_docs',
            capabilities: ['markdown_sections', 'citations', 'structural_context'],
        });
    }

    canHandle(input) {
        return Boolean(input && input.projectRoot && input.config?.adapters?.markdown_docs?.enabled !== false);
    }

    async discover(input) {
        const { projectRoot, config } = input;
        const records = [];
        const fileInventory = input.fileInventory || walkFiles(projectRoot, config);
        for (const fullPath of fileInventory) {
            const relativePath = normalizePath(path.relative(projectRoot, fullPath));
            if (path.extname(relativePath).toLowerCase() !== '.md') continue;
            const policy = classifyPath(relativePath, config);
            if (policy.classification !== 'allowed') continue;

            const raw = readAdmittedSource(fullPath, relativePath, config);
            if (raw === null) continue;
            const text = raw.toString('utf8');
            const sections = extractMarkdownSections(text);
            for (const section of sections) {
                const sectionPath = `${relativePath}#${slug(section.heading)}`;
                const sectionText = section.lines.join('\n').trim();
                records.push({
                    id: sourceId(sectionPath),
                    path: sectionPath,
                    type: 'markdown_section',
                    classification: 'allowed',
                    reason: 'markdown section extracted from allowed document',
                    hash: sha256(sectionText),
                    summary: summarizeText(sectionText, fileType(relativePath)),
                    content_preview: previewText(sectionText),
                    heading: section.heading,
                    byte_count: Buffer.byteLength(sectionText),
                    line_count: section.lines.length,
                    provenance: {
                        adapter: this.name,
                        root: projectRoot,
                        source_kind: 'markdown_section',
                        parent_path: relativePath,
                        heading_level: section.level,
                    },
                });
            }
        }
        return records;
    }
}

module.exports = {
    MarkdownDocsAdapter,
    extractMarkdownSections,
};
