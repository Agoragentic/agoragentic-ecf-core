'use strict';

const path = require('node:path');
const { ContextAdapter } = require('./base');
const { readAdmittedSource, walkFiles } = require('./filesystem');
const { sha256, sourceId } = require('../core/hash');
const { classifyPath, normalizePath } = require('../core/policy');

function extractCreateTables(sql) {
    const tables = [];
    const regex = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?["'`[]?([a-zA-Z0-9_.$-]+)["'`\]]?\s*\(([\s\S]*?)\)\s*;/gi;
    let match;
    while ((match = regex.exec(sql)) !== null) {
        const columns = match[2]
            .split(',')
            .map((item) => item.trim())
            .filter(Boolean)
            .map((item) => item.split(/\s+/)[0].replace(/["'`\[\]]/g, ''))
            .filter((name) => name && !/^(CONSTRAINT|PRIMARY|FOREIGN|UNIQUE|CHECK|KEY)$/i.test(name))
            .slice(0, 30);
        tables.push({
            name: match[1],
            columns,
        });
    }
    return tables;
}

class SqliteSummaryAdapter extends ContextAdapter {
    constructor() {
        super({
            name: 'sqlite_summary',
            capabilities: ['sqlite_schema_summary', 'database_boundary'],
        });
    }

    canHandle(input) {
        return Boolean(input && input.projectRoot && input.config?.adapters?.sqlite_summary?.enabled !== false);
    }

    async discover(input) {
        const { projectRoot, config } = input;
        const records = [];
        const fileInventory = input.fileInventory || walkFiles(projectRoot, config);
        for (const fullPath of fileInventory) {
            const relativePath = normalizePath(path.relative(projectRoot, fullPath));
            const ext = path.extname(relativePath).toLowerCase();
            const sqliteSchemaJson = relativePath.endsWith('.sqlite.schema.json') || relativePath.endsWith('.db.schema.json');
            if (ext !== '.sql' && !sqliteSchemaJson) continue;
            const policy = classifyPath(relativePath, config);
            if (policy.classification !== 'allowed') continue;

            const raw = readAdmittedSource(fullPath, relativePath, config);
            if (raw === null) continue;
            const text = raw.toString('utf8');
            const tables = ext === '.sql'
                ? extractCreateTables(text)
                : [];
            if (tables.length === 0 && ext === '.sql') continue;
            const summary = tables.length
                ? `SQLite schema summary: ${tables.map((table) => `${table.name}(${table.columns.join(', ')})`).join('; ')}.`
                : `SQLite schema export file: ${relativePath}.`;
            const virtualPath = `${relativePath}#sqlite-schema-summary`;
            records.push({
                id: sourceId(virtualPath),
                path: virtualPath,
                type: 'sqlite_schema_summary',
                classification: 'allowed',
                reason: 'schema summary extracted from allowed SQLite export, not a live database file',
                hash: sha256(summary),
                summary,
                heading: 'SQLite schema summary',
                byte_count: Buffer.byteLength(summary),
                line_count: tables.length,
                provenance: {
                    adapter: this.name,
                    root: projectRoot,
                    source_kind: 'sqlite_schema_summary',
                    parent_path: relativePath,
                    table_count: tables.length,
                    reads_database_file: false,
                },
            });
        }
        return records;
    }
}

module.exports = {
    SqliteSummaryAdapter,
    extractCreateTables,
};
