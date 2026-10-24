'use strict';

const path = require('node:path');
const { ContextAdapter } = require('./base');
const { readAdmittedSource, walkFiles } = require('./filesystem');
const { sha256, sourceId } = require('../core/hash');
const { classifyPath, normalizePath } = require('../core/policy');

function summarizeMcpJson(text) {
    try {
        const parsed = JSON.parse(text);
        const servers = parsed.mcpServers || parsed.servers || {};
        const serverNames = Array.isArray(servers)
            ? servers.map((server) => server.name).filter(Boolean)
            : Object.keys(servers);
        const tools = parsed.tools || parsed.capabilities?.tools || [];
        const toolNames = Array.isArray(tools)
            ? tools.map((tool) => tool.name || tool.id).filter(Boolean)
            : Object.keys(tools || {});
        if (serverNames.length === 0 && toolNames.length === 0) return null;
        return {
            serverNames,
            toolNames,
            summary: `MCP context summary: servers=${serverNames.slice(0, 12).join(', ') || 'none'}; tools=${toolNames.slice(0, 20).join(', ') || 'none'}.`,
        };
    } catch {
        return null;
    }
}

class McpContextProviderAdapter extends ContextAdapter {
    constructor() {
        super({
            name: 'mcp_context',
            capabilities: ['mcp_context_provider_summary'],
        });
    }

    canHandle(input) {
        return Boolean(input && input.projectRoot && input.config?.adapters?.mcp_context?.enabled !== false);
    }

    async discover(input) {
        const { projectRoot, config } = input;
        const records = [];
        const fileInventory = input.fileInventory || walkFiles(projectRoot, config);
        for (const fullPath of fileInventory) {
            const relativePath = normalizePath(path.relative(projectRoot, fullPath));
            const base = path.basename(relativePath).toLowerCase();
            if (!['mcp.json', '.mcp.json', 'server.json', 'mcp-server.json'].includes(base)) continue;
            const policy = classifyPath(relativePath, config);
            if (policy.classification !== 'allowed') continue;

            const raw = readAdmittedSource(fullPath, relativePath, config);
            if (raw === null) continue;
            const summary = summarizeMcpJson(raw.toString('utf8'));
            if (!summary) continue;
            const virtualPath = `${relativePath}#mcp-context-summary`;
            records.push({
                id: sourceId(virtualPath),
                path: virtualPath,
                type: 'mcp_context_summary',
                classification: 'allowed',
                reason: 'MCP context-provider summary extracted from allowed JSON descriptor',
                hash: sha256(summary.summary),
                summary: summary.summary,
                heading: 'MCP context summary',
                byte_count: Buffer.byteLength(summary.summary),
                line_count: summary.serverNames.length + summary.toolNames.length,
                provenance: {
                    adapter: this.name,
                    root: projectRoot,
                    source_kind: 'mcp_context_summary',
                    parent_path: relativePath,
                    server_count: summary.serverNames.length,
                    tool_count: summary.toolNames.length,
                },
            });
        }
        return records;
    }
}

module.exports = {
    McpContextProviderAdapter,
    summarizeMcpJson,
};
