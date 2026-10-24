'use strict';

const path = require('node:path');
const { ContextAdapter } = require('./base');
const { readAdmittedSource, walkFiles } = require('./filesystem');
const { sha256, sourceId } = require('../core/hash');
const { classifyPath, normalizePath } = require('../core/policy');

function parseJsonOpenApi(text) {
    try {
        const parsed = JSON.parse(text);
        if (!parsed || typeof parsed !== 'object' || (!parsed.openapi && !parsed.swagger)) return null;
        const paths = Object.entries(parsed.paths || {});
        return paths.flatMap(([route, methods]) => Object.keys(methods || {}).map((method) => ({
            method: method.toUpperCase(),
            path: route,
        })));
    } catch {
        return null;
    }
}

function leadingSpaces(line) {
    let count = 0;
    while (line[count] === ' ') count += 1;
    return count;
}

function yamlRootKey(line) {
    const trimmed = line.trim();
    if (!trimmed.endsWith(':')) return null;
    return trimmed.slice(0, -1).trim();
}

function parseYamlOpenApi(text) {
    const lines = text.split('\n').map((line) => line.endsWith('\r') ? line.slice(0, -1) : line);
    const hasOpenApiHeader = lines.some((line) => {
        const trimmed = line.trimStart();
        return trimmed.startsWith('openapi:') || trimmed.startsWith('swagger:');
    });
    if (!hasOpenApiHeader) return null;
    const endpoints = [];
    let inPaths = false;
    let currentPath = null;
    const methods = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options']);
    for (const line of lines) {
        const indent = leadingSpaces(line);
        const trimmed = line.trim();
        if (yamlRootKey(line) === 'paths') {
            inPaths = true;
            continue;
        }
        if (!inPaths) continue;
        if (indent === 2 && trimmed.startsWith('/') && trimmed.endsWith(':')) {
            currentPath = trimmed.slice(0, -1);
            continue;
        }
        const method = trimmed.endsWith(':') ? trimmed.slice(0, -1).toLowerCase() : '';
        if (indent === 4 && methods.has(method) && currentPath) {
            endpoints.push({
                method: method.toUpperCase(),
                path: currentPath,
            });
        }
    }
    return endpoints;
}

function extractOpenApiEndpoints(text, relativePath) {
    if (path.extname(relativePath).toLowerCase() === '.json') {
        return parseJsonOpenApi(text);
    }
    return parseYamlOpenApi(text);
}

class OpenApiAdapter extends ContextAdapter {
    constructor() {
        super({
            name: 'openapi',
            capabilities: ['api_surface_summary', 'openapi'],
        });
    }

    canHandle(input) {
        return Boolean(input && input.projectRoot && input.config?.adapters?.openapi?.enabled !== false);
    }

    async discover(input) {
        const { projectRoot, config } = input;
        const records = [];
        const fileInventory = input.fileInventory || walkFiles(projectRoot, config);
        for (const fullPath of fileInventory) {
            const relativePath = normalizePath(path.relative(projectRoot, fullPath));
            const filename = path.basename(relativePath).toLowerCase();
            const hasKeyword = filename.includes('openapi') || filename.includes('swagger');
            const hasExtension = filename.endsWith('.json') || filename.endsWith('.yaml') || filename.endsWith('.yml');
            if (!(hasKeyword && hasExtension)) continue;
            const policy = classifyPath(relativePath, config);
            if (policy.classification !== 'allowed') continue;

            const raw = readAdmittedSource(fullPath, relativePath, config);
            if (raw === null) continue;
            const text = raw.toString('utf8');
            const endpoints = extractOpenApiEndpoints(text, relativePath);
            if (!endpoints || endpoints.length === 0) continue;
            const summary = `OpenAPI summary: ${endpoints.slice(0, 30).map((endpoint) => `${endpoint.method} ${endpoint.path}`).join(', ')}.`;
            const virtualPath = `${relativePath}#openapi-summary`;
            records.push({
                id: sourceId(virtualPath),
                path: virtualPath,
                type: 'openapi_summary',
                classification: 'allowed',
                reason: 'API surface summary extracted from allowed OpenAPI document',
                hash: sha256(summary),
                summary,
                heading: 'OpenAPI summary',
                byte_count: Buffer.byteLength(summary),
                line_count: endpoints.length,
                provenance: {
                    adapter: this.name,
                    root: projectRoot,
                    source_kind: 'openapi_summary',
                    parent_path: relativePath,
                    endpoint_count: endpoints.length,
                },
            });
        }
        return records;
    }
}

module.exports = {
    OpenApiAdapter,
    extractOpenApiEndpoints,
};
