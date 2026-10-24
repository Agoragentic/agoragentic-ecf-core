'use strict';

const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const { createHash, randomUUID } = require('node:crypto');
const { inspectAgentOsPreview } = require('./agent-os-preview');
const { routeCompiledQuery } = require('./context-router');
const { rankRecords } = require('./core/ranking');
const { sha256 } = require('./core/hash');
const {
    buildEcfCoreContextPack,
    buildEcfCoreResidentStatus,
} = require('./resident');
const {
    buildHandoff,
    buildWorklogStatus,
    readWorklogArtifacts,
} = require('./work-memory');
const { version: packageVersion } = require('../package.json');

const SERVER_NAME = 'agoragentic-ecf-core';
const SERVER_VERSION = packageVersion;

const TOOLS = [
    {
        name: 'ecf_core.search_context',
        description: 'Search compiled ECF Core context-packet sources with deterministic semantic-lite ranking.',
        inputSchema: {
            type: 'object',
            properties: {
                query: { type: 'string' },
                top_k: { type: 'integer', minimum: 1, maximum: 20, default: 5 },
                ranking_provider: { type: 'string', enum: ['semantic_lite', 'lexical', 'local_vector'] },
            },
            required: ['query'],
        },
    },
    {
        name: 'ecf_core.get_source',
        description: 'Read one compiled source record by source_id or path from ECF Core artifacts.',
        inputSchema: {
            type: 'object',
            properties: {
                source_id: { type: 'string' },
                path: { type: 'string' },
            },
        },
    },
    {
        name: 'ecf_core.get_policy',
        description: 'Return the compiled ECF Core policy summary.',
        inputSchema: {
            type: 'object',
            properties: {},
        },
    },
    {
        name: 'ecf_core.get_manifest',
        description: 'Return the compiled ECF Core manifest and artifact counts.',
        inputSchema: {
            type: 'object',
            properties: {},
        },
    },
    {
        name: 'ecf_core.agent_os_preview_check',
        description: 'Run the local Agent OS preview-import readiness check over compiled artifacts.',
        inputSchema: {
            type: 'object',
            properties: {},
        },
    },
    {
        name: 'ecf_core.route_query',
        description: 'Route a question to exact evidence, policy, code symbols, source manifest facts, deterministic stats, or semantic summary.',
        inputSchema: {
            type: 'object',
            properties: {
                query: { type: 'string' },
                top_k: { type: 'integer', minimum: 1, maximum: 20, default: 5 },
                ranking_provider: { type: 'string', enum: ['semantic_lite', 'lexical', 'local_vector'] },
            },
            required: ['query'],
        },
    },
    {
        name: 'ecf_core.status',
        description: 'Return local ECF Core resident status for the compiled artifact root.',
        inputSchema: {
            type: 'object',
            properties: {},
        },
    },
    {
        name: 'ecf_core.context_pack',
        description: 'Return an IDE/Codex-friendly compiled context pack summary without raw source content.',
        inputSchema: {
            type: 'object',
            properties: {
                task: { type: 'string' },
            },
        },
    },
    {
        name: 'ecf_core.worklog_status',
        description: 'Return local ECF Core worklog status for next-session continuity.',
        inputSchema: {
            type: 'object',
            properties: {},
        },
    },
    {
        name: 'ecf_core.handoff',
        description: 'Return the local next-session handoff without writing files.',
        inputSchema: {
            type: 'object',
            properties: {},
        },
    },
    {
        name: 'ecf_core.work_memory',
        description: 'Return local work memory artifacts: worklog status, docs-sync plan, handoff, and latest summary.',
        inputSchema: {
            type: 'object',
            properties: {},
        },
    },
];

const ARTIFACT_FILES = [
    'context-packet.json',
    'source-map.json',
    'source-manifest.json',
    'policy-summary.json',
    'code-index.json',
    'context-router.json',
    'manifest.json',
];

const artifactCache = new Map();
const VERIFIED_TOOLS = new Set([
    'ecf_core.search_context', 'ecf_core.route_query', 'ecf_core.get_source',
    'ecf_core.get_policy', 'ecf_core.get_manifest',
]);
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const refuse = code => { throw Object.assign(new Error(code), { code }); };

function readArtifactSnapshot(resolvedDir) {
    const contents = new Map();
    const signature = ARTIFACT_FILES.map((fileName) => {
        let bytes;
        try {
            bytes = fs.readFileSync(path.join(resolvedDir, fileName));
        } catch (error) {
            if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') throw error;
            bytes = null;
        }
        contents.set(fileName, bytes);
        return `${fileName}:${bytes === null ? 'missing' : sha256(bytes)}`;
    }).join('|');
    return { contents, signature };
}

function indexArtifacts(artifacts) {
    const records = sourceRecords(artifacts.contextPacket || { sources: [] });
    artifacts.records = records;
    artifacts.recordsById = new Map(records.map((record) => [record.id, record]));
    artifacts.recordsByPath = new Map(records.map((record) => [record.path, record]));
    artifacts.citationsBySourceId = new Map((artifacts.contextPacket?.citations || [])
        .map((citation) => [citation.source_id, citation]));
    artifacts.sourceMapById = new Map((artifacts.sourceMap?.sources || [])
        .map((record) => [record.id, record]));
    return artifacts;
}

function loadArtifacts(artifactDir) {
    const resolvedDir = path.resolve(artifactDir || '.ecf-core');
    const { contents, signature } = readArtifactSnapshot(resolvedDir);
    const cached = artifactCache.get(resolvedDir);
    if (cached?.signature === signature) {
        return cached.artifacts;
    }
    // Parse the exact bytes used by the cache key, without a second file read.
    const readJson = (fileName) => {
        const bytes = contents.get(fileName);
        return bytes === null ? null : JSON.parse(bytes.toString('utf8'));
    };
    const artifacts = indexArtifacts({
        artifactDir: resolvedDir,
        contextPacket: readJson('context-packet.json'),
        sourceMap: readJson('source-map.json'),
        sourceManifest: readJson('source-manifest.json'),
        policySummary: readJson('policy-summary.json'),
        codeIndex: readJson('code-index.json'),
        contextRouter: readJson('context-router.json'),
        manifest: readJson('manifest.json'),
    });
    artifactCache.set(resolvedDir, { signature, artifacts });
    return artifacts;
}

function requireArtifact(value, name) {
    if (!value) {
        throw new Error(`${name} is missing. Run ecf-core compile . --agent-os first.`);
    }
}

function sourceRecords(contextPacket) {
    return (contextPacket.sources || []).map((source) => ({
        ...source,
        summary: source.summary || '',
        content_preview: source.content_preview || '',
        provenance: source.provenance || {},
    }));
}

function findCitation(contextPacket, sourceId) {
    return (contextPacket.citations || []).find((citation) => citation.source_id === sourceId) || null;
}

function searchContext(artifacts, args = {}) {
    requireArtifact(artifacts.contextPacket, 'context-packet.json');
    const query = String(args.query || '').trim();
    if (!query) throw new Error('query is required');
    const topLimit = Math.max(1, Math.min(Number(args.top_k || 5), 20));
    const records = artifacts.records || sourceRecords(artifacts.contextPacket);
    const ranking = rankRecords(records, query, topLimit, { provider: args.ranking_provider || 'semantic_lite' });
    const ranked = ranking.hits.map((hit) => {
        const source = artifacts.recordsById?.get(hit.id) || records.find((record) => record.id === hit.id);
        const citation = artifacts.citationsBySourceId?.get(hit.id) || findCitation(artifacts.contextPacket, hit.id);
        return {
            source_id: hit.id,
            path: hit.path,
            score: hit.score,
            type: source?.type || null,
            summary: source?.summary || null,
            content_preview: source?.content_preview || null,
            citation_id: citation?.id || null,
            provenance: source?.provenance || {},
        };
    });
    return {
        schema_version: 'ecf-core.mcp.search-result.v1',
        query,
        top_k: topLimit,
        ranking: {
            mode: ranking.ranking_mode,
            dependency_status: ranking.dependency_status,
        },
        results: ranked,
        boundary: {
            read_only: true,
            live_deploy_allowed: false,
            includes_wallet_or_settlement: false,
            includes_full_ecf_private_internals: false,
        },
    };
}

function getSource(artifacts, args = {}) {
    requireArtifact(artifacts.contextPacket, 'context-packet.json');
    const source = (args.source_id && artifacts.recordsById?.get(args.source_id))
        || (args.path && artifacts.recordsByPath?.get(args.path))
        || null;
    if (!source) {
        throw new Error('source not found by source_id or path');
    }
    return {
        schema_version: 'ecf-core.mcp.source.v1',
        source,
        citation: artifacts.citationsBySourceId?.get(source.id) || findCitation(artifacts.contextPacket, source.id),
        source_map_entry: artifacts.sourceMapById?.get(source.id) || null,
    };
}

function getPolicy(artifacts) {
    requireArtifact(artifacts.policySummary, 'policy-summary.json');
    return {
        schema_version: 'ecf-core.mcp.policy.v1',
        policy_summary: artifacts.policySummary,
        boundary: {
            read_only: true,
            hosted_runtime: false,
            wallet_settlement: false,
            marketplace_routing: false,
            full_ecf_private_internals: false,
        },
    };
}

function getManifest(artifacts) {
    requireArtifact(artifacts.manifest, 'manifest.json');
    return {
        schema_version: 'ecf-core.mcp.manifest.v1',
        manifest: artifacts.manifest,
    };
}

function routeQuery(artifacts, args = {}) {
    requireArtifact(artifacts.contextPacket, 'context-packet.json');
    requireArtifact(artifacts.sourceManifest, 'source-manifest.json');
    requireArtifact(artifacts.codeIndex, 'code-index.json');
    requireArtifact(artifacts.contextRouter, 'context-router.json');
    const query = String(args.query || '').trim();
    if (!query) throw new Error('query is required');
    const topLimit = Math.max(1, Math.min(Number(args.top_k || 5), 20));
    return routeCompiledQuery({
        query,
        contextPacket: artifacts.contextPacket,
        sourceManifest: artifacts.sourceManifest,
        codeIndex: artifacts.codeIndex,
        contextRouter: artifacts.contextRouter,
        topK: topLimit,
        rankingProvider: args.ranking_provider || 'semantic_lite',
    });
}

function callVerifiedTool({ artifactDir, verifiedProjectRoot, name, args }) {
    const reader = module.ecfCapturedReader;
    if (!reader) refuse('verified_reader_not_bound');
    if (typeof verifiedProjectRoot !== 'string' || !verifiedProjectRoot.trim()) refuse('invalid_verified_project');
    if (artifactDir !== undefined) refuse('verified_artifact_override_not_allowed');
    if (!VERIFIED_TOOLS.has(name)) refuse('tool_not_supported_in_verified_mode');
    const requestBytes = JSON.stringify({ name, args: args || {} });
    if (Buffer.byteLength(requestBytes) > 64 * 1024) refuse('verified_request_limit');
    const request = JSON.parse(requestBytes);
    const root = path.resolve(verifiedProjectRoot);
    // Inspection always uses a fresh graph. Never use the ordinary artifact cache
    // or the parent process's cached configuration/policy to authorize a read.
    const { inspectFresh, readBounded } = require('./freshness');
    const inspect = () => {
        const state = inspectFresh(root, { includeVerification: true });
        if (state.state !== 'fresh' || !state.verification) refuse('verified_context_unavailable');
        return state.verification;
    };
    const identity = inspect();
    if (identity.compiler_digest !== reader.digest) refuse('verified_reader_changed');
    const artifactDirForGeneration = path.join(fs.realpathSync(root), '.ecf-core', 'fresh', identity.generation);
    const expected = new Map(identity.artifacts);
    const consumed = [];
    const read = fileName => {
        if (!expected.has(fileName)) refuse('verified_artifact_missing');
        const bytes = readBounded(path.join(artifactDirForGeneration, fileName), 8 * 1024 * 1024);
        const sha256 = digest(bytes);
        if (sha256 !== expected.get(fileName)) refuse('verified_artifact_changed');
        consumed.push([fileName, sha256]);
        return JSON.parse(bytes);
    };
    // Each parsed object is derived from the exact bounded buffer checked here,
    // in this MCP process. No tool in this mode may independently reread disk.
    const artifacts = indexArtifacts({
        artifactDir: artifactDirForGeneration,
        contextPacket: read('context-packet.json'),
        sourceMap: read('source-map.json'),
        sourceManifest: read('source-manifest.json'),
        policySummary: read('policy-summary.json'),
        codeIndex: read('code-index.json'),
        contextRouter: read('context-router.json'),
        manifest: read('manifest.json'),
    });
    const result = dispatchTool(artifacts, request.name, request.args);
    const responseBytes = JSON.stringify(result);
    if (Buffer.byteLength(responseBytes) > 8 * 1024 * 1024) refuse('verified_response_limit');
    // Check again after computing the response. Pointer, source, policy,
    // compiler, seal or any artifact drift discards this response entirely.
    if (JSON.stringify(inspect()) !== JSON.stringify(identity)) refuse('verified_generation_changed');
    return {
        ...JSON.parse(responseBytes),
        verified_consumption: {
            schema_version: 'ecf-core.mcp.verified-consumption.v1',
            request_verified: true,
            host_consumption_verified: false,
            request_id: randomUUID(),
            reader_pid: process.pid,
            request_sha256: digest(requestBytes),
            response_sha256: digest(responseBytes),
            ...identity,
            reader_digest: reader.digest,
            reader_loaded_modules: [...reader.loaded].sort((a, b) => a[0] < b[0] ? -1 : 1),
            consumed_artifacts: consumed,
        },
    };
}

function callTool(options) {
    if (options.verifiedProjectRoot !== undefined) {
        // The controller may be cached A while disk is B. Read, dispatch and
        // receipt creation must execute B's captured buffers in this process,
        // never A's cached consumer/ranking functions relabeled as B.
        const { captureCompiler, capturedGraph } = require('./freshness-worker');
        const identity = captureCompiler();
        const graph = capturedGraph(identity);
        return graph.load(__filename).callVerifiedTool(options);
    }
    return dispatchTool(loadArtifacts(options.artifactDir), options.name, options.args);
}

function dispatchTool(artifacts, name, args = {}) {
    if (name === 'ecf_core.search_context') return searchContext(artifacts, args);
    if (name === 'ecf_core.route_query') return routeQuery(artifacts, args);
    if (name === 'ecf_core.get_source') return getSource(artifacts, args);
    if (name === 'ecf_core.get_policy') return getPolicy(artifacts);
    if (name === 'ecf_core.get_manifest') return getManifest(artifacts);
    if (name === 'ecf_core.agent_os_preview_check') return inspectAgentOsPreview(artifacts.artifactDir);
    if (name === 'ecf_core.status') {
        return buildEcfCoreResidentStatus({
            projectRoot: path.dirname(artifacts.artifactDir),
            artifactDir: artifacts.artifactDir,
        });
    }
    if (name === 'ecf_core.context_pack') {
        return buildEcfCoreContextPack({
            projectRoot: path.dirname(artifacts.artifactDir),
            artifactDir: artifacts.artifactDir,
            task: args.task,
        });
    }
    if (name === 'ecf_core.worklog_status') {
        return buildWorklogStatus({
            projectRoot: path.dirname(artifacts.artifactDir),
            artifactDir: artifacts.artifactDir,
        });
    }
    if (name === 'ecf_core.handoff') {
        return buildHandoff({
            projectRoot: path.dirname(artifacts.artifactDir),
            artifactDir: artifacts.artifactDir,
        });
    }
    if (name === 'ecf_core.work_memory') {
        return readWorklogArtifacts({
            projectRoot: path.dirname(artifacts.artifactDir),
            artifactDir: artifacts.artifactDir,
        });
    }
    throw new Error(`unknown tool: ${name}`);
}

function textResult(value) {
    return {
        content: [
            {
                type: 'text',
                text: JSON.stringify(value, null, 2),
            },
        ],
    };
}

function errorResponse(id, error) {
    return {
        jsonrpc: '2.0',
        id,
        error: {
            code: -32000,
            message: error.message || String(error),
        },
    };
}

function handleMcpRequest(request, options = {}) {
    if (!request || request.jsonrpc !== '2.0') {
        throw new Error('invalid JSON-RPC request');
    }
    if (!Object.prototype.hasOwnProperty.call(request, 'id')) {
        return null;
    }
    if (request.method === 'initialize') {
        return {
            jsonrpc: '2.0',
            id: request.id,
            result: {
                protocolVersion: '2024-11-05',
                capabilities: {
                    tools: { listChanged: false },
                },
                serverInfo: {
                    name: SERVER_NAME,
                    version: SERVER_VERSION,
                },
            },
        };
    }
    if (request.method === 'tools/list') {
        return {
            jsonrpc: '2.0',
            id: request.id,
            result: { tools: options.verifiedProjectRoot === undefined ? TOOLS
                : TOOLS.filter(tool => VERIFIED_TOOLS.has(tool.name)) },
        };
    }
    if (request.method === 'tools/call') {
        const params = request.params || {};
        const value = callTool({
            artifactDir: options.artifactDir,
            verifiedProjectRoot: options.verifiedProjectRoot,
            name: params.name,
            args: params.arguments || {},
        });
        return {
            jsonrpc: '2.0',
            id: request.id,
            result: textResult(value),
        };
    }
    throw new Error(`unsupported MCP method: ${request.method}`);
}

function runMcpServer(options = {}) {
    const readerOptions = options.verifiedProjectRoot === undefined
        ? { artifactDir: path.resolve(options.artifactDir || '.ecf-core') }
        : { verifiedProjectRoot: options.verifiedProjectRoot, ...(options.artifactDir === undefined ? {} : { artifactDir: options.artifactDir }) };
    const input = options.input || process.stdin;
    const output = options.output || process.stdout;
    const rl = readline.createInterface({ input });

    rl.on('line', (line) => {
        if (!line.trim()) return;
        let response = null;
        try {
            const request = JSON.parse(line);
            response = handleMcpRequest(request, readerOptions);
        } catch (error) {
            let id = null;
            try {
                id = JSON.parse(line).id ?? null;
            } catch (_) {
                id = null;
            }
            response = errorResponse(id, error);
        }
        if (response) {
            output.write(`${JSON.stringify(response)}\n`);
        }
    });
}

module.exports = {
    TOOLS,
    callTool,
    handleMcpRequest,
    runMcpServer,
    // Internal captured-graph entry; public callers use callTool/handleMcpRequest.
    callVerifiedTool,
};
