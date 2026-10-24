'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { ContextAdapter } = require('./base');
const { sha256, sourceId } = require('../core/hash');
const { classifyPath, normalizePath, shouldSkipDirectory } = require('../core/policy');
const { extractCodeFacts } = require('../context-router');

const TEXT_EXTENSIONS = new Set([
    '.cjs',
    '.cs',
    '.css',
    '.csv',
    '.go',
    '.html',
    '.java',
    '.js',
    '.json',
    '.jsx',
    '.kt',
    '.kts',
    '.md',
    '.mjs',
    '.php',
    '.ps1',
    '.py',
    '.rb',
    '.rs',
    '.sh',
    '.sql',
    '.swift',
    '.ts',
    '.tsx',
    '.txt',
    '.yaml',
    '.yml',
]);

function fileType(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    if (ext === '.md') return 'markdown';
    if (ext === '.json') return 'json';
    if (ext === '.yaml' || ext === '.yml') return 'yaml';
    if (ext === '.sql') return 'sql';
    if (['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.py', '.rb', '.rs', '.sh', '.ps1', '.go', '.java', '.cs', '.php', '.swift', '.kt', '.kts'].includes(ext)) return 'code';
    if (['.html', '.css'].includes(ext)) return 'web';
    if (['.txt', '.csv'].includes(ext)) return 'text';
    return 'file';
}

function isTextFile(filePath) {
    return TEXT_EXTENSIONS.has(path.extname(filePath).toLowerCase());
}

// One effective metadata disposition shared by compilation and freshness.
// A policy allow does not imply content admission: format and size still apply.
function metadataDisposition(relativePath, config, stat, actualSize = stat.size) {
    const policy = classifyPath(relativePath, config);
    const stamp = `${relativePath}:${stat.size}:${Math.trunc(stat.mtimeMs)}`;
    if (policy.classification !== 'allowed') {
        return { ...policy, hash: sha256(`${policy.classification}:${stamp}`), summary: policy.reason };
    }
    if (!isTextFile(relativePath)) {
        return {
            classification: 'review_required',
            reason: 'allowed path matched, but file type is not text-readable by the baseline adapter',
            hash: sha256(`review:${stamp}`),
            summary: 'Non-text file requires an explicit adapter.',
        };
    }
    if (actualSize > config.max_file_bytes) {
        return {
            classification: 'review_required',
            reason: `file exceeds max_file_bytes=${config.max_file_bytes}`,
            hash: sha256(`oversize:${stamp}`),
            summary: 'Oversized file requires explicit review or a specialized adapter.',
        };
    }
    return null;
}

// Summary adapters share the baseline adapter's effective content admission.
// Check metadata before opening, then retain the post-read size check for growth
// between stat and read. A null result means the source remains metadata-only.
function readAdmittedSource(fullPath, relativePath, config) {
    const stat = fs.statSync(fullPath);
    if (metadataDisposition(relativePath, config, stat)) return null;
    const raw = fs.readFileSync(fullPath);
    if (metadataDisposition(relativePath, config, stat, raw.length)) return null;
    return raw;
}

function summarizeJson(text) {
    try {
        const parsed = JSON.parse(text);
        if (Array.isArray(parsed)) return `JSON array with ${parsed.length} items.`;
        if (parsed && typeof parsed === 'object') return `JSON object with keys: ${Object.keys(parsed).slice(0, 12).join(', ')}.`;
    } catch {
        return null;
    }
    return null;
}

function firstMarkdownHeading(text) {
    const line = text.split(/\r?\n/).find((item) => /^#{1,6}\s+/.test(item.trim()));
    return line ? line.replace(/^#{1,6}\s+/, '').trim() : null;
}

function meaningfulLines(text) {
    return text
        .split(/\r?\n/)
        .map((item) => item.trim())
        .filter(Boolean);
}

function stripMarkdownHeading(line) {
    return line.replace(/^#{1,6}\s+/, '').trim();
}

const SENSITIVE_KEY_PATTERN = /\b(api[_-]?key|access[_-]?token|auth[_-]?token|authorization|bearer|client[_-]?secret|connection[_-]?string|connectionstrings?|password|passwd|private[_-]?key|secret|token|webhook[_-]?secret|azurewebjobsstorage|openai)\b/i;
const SENSITIVE_VALUE_PATTERN = /\b(sk-(?:live|test|proj)?-?[A-Za-z0-9_-]{8,}|gh[opsu]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,}|AKIA[0-9A-Z]{12,}|xox[baprs]-[A-Za-z0-9-]{8,})\b/g;

function isSensitiveKey(key) {
    return SENSITIVE_KEY_PATTERN.test(String(key || ''));
}

function redactSensitiveLine(line) {
    const text = String(line || '');
    const jsonPair = text.match(/^(\s*"([^"]+)"\s*:\s*)("(?:\\.|[^"\\])*"|[^,\r\n}]*)(.*)$/);
    if (jsonPair && isSensitiveKey(jsonPair[2])) {
        return `${jsonPair[1]}"[REDACTED]"${jsonPair[4]}`;
    }

    const yamlPair = text.match(/^(\s*([A-Za-z0-9_.-]+)\s*:\s*)(.*)$/);
    if (yamlPair && isSensitiveKey(yamlPair[2])) {
        return `${yamlPair[1]}[REDACTED]`;
    }

    const assignment = text.match(/^(\s*([A-Za-z0-9_.-]+)\s*=\s*)(.*)$/);
    if (assignment && isSensitiveKey(assignment[2])) {
        return `${assignment[1]}[REDACTED]`;
    }

    return text.replace(SENSITIVE_VALUE_PATTERN, '[REDACTED]');
}

function redactSensitiveText(text) {
    return String(text || '')
        .split('\n')
        .map((line) => redactSensitiveLine(line))
        .join('\n');
}

function previewText(text, maxChars = 1600) {
    const normalized = redactSensitiveText(text)
        .replace(/\r\n/g, '\n')
        .split('\n')
        .map((line) => line.trimEnd())
        .join('\n')
        .trim();
    if (!normalized) return '';
    return normalized.length > maxChars ? `${normalized.slice(0, maxChars - 1).trimEnd()}…` : normalized;
}

function summarizeText(text, type) {
    if (type === 'json') {
        const jsonSummary = summarizeJson(text);
        if (jsonSummary) return jsonSummary;
    }
    const lines = meaningfulLines(text);
    if (lines.length === 0) return 'Empty text file.';
    const heading = type === 'markdown' && /^#{1,6}\s+/.test(lines[0])
        ? stripMarkdownHeading(lines[0])
        : null;
    const bodyLine = lines.find((line, index) => !(index === 0 && /^#{1,6}\s+/.test(line)));
    const summary = heading && bodyLine
        ? `${heading}: ${bodyLine.replace(/^#{1,6}\s+/, '').trim()}`
        : (heading || lines[0]);
    return summary.length > 240 ? `${summary.slice(0, 237)}...` : summary;
}

function recordSkippedDirectory(root, dir, error, state) {
    if (!state || !Array.isArray(state.skippedDirectories)) return;
    state.skippedDirectories.push({
        path: normalizePath(path.relative(root, dir)),
        code: error.code || 'unreadable',
        reason: error.message,
    });
}

function isNestedGitRepository(root, dir) {
    if (path.resolve(root) === path.resolve(dir)) return false;
    try {
        return fs.existsSync(path.join(dir, '.git'));
    } catch {
        return false;
    }
}

function normalizeArtifactPath(relativePath) {
    const withForwardSlashes = String(relativePath || '').split('\\').join('/');
    let end = withForwardSlashes.length;
    while (end > 0 && withForwardSlashes[end - 1] === '/') {
        end -= 1;
    }
    return end === withForwardSlashes.length
        ? withForwardSlashes
        : withForwardSlashes.slice(0, end);
}

function isGeneratedEcfArtifactPath(relativePath) {
    const normalized = normalizeArtifactPath(relativePath);
    return normalized === '.ecf-core'
        || normalized.startsWith('.ecf-core/')
        || normalized === '.micro-ecf'
        || normalized.startsWith('.micro-ecf/');
}

function walkFiles(root, config, dir = root, output = [], state = null) {
    let entries = [];
    try {
        entries = fs.readdirSync(dir, { withFileTypes: true })
            .sort((a, b) => a.name.localeCompare(b.name));
    } catch (error) {
        recordSkippedDirectory(root, dir, error, state);
        return output;
    }
    for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        const relativePath = normalizePath(path.relative(root, fullPath));
        if (entry.isDirectory()) {
            if (shouldSkipDirectory(relativePath, config) || isNestedGitRepository(root, fullPath)) {
                if (state && isGeneratedEcfArtifactPath(relativePath)) {
                    state.generatedArtifactsExcluded = (state.generatedArtifactsExcluded || 0) + 1;
                    state.generatedArtifactPaths = state.generatedArtifactPaths || [];
                    state.generatedArtifactPaths.push(relativePath);
                }
            } else {
                walkFiles(root, config, fullPath, output, state);
            }
            continue;
        }
        if (entry.isFile()) output.push(fullPath);
    }
    return output;
}

class FilesystemAdapter extends ContextAdapter {
    constructor() {
        super({
            name: 'filesystem',
            capabilities: ['local_files', 'source_map', 'citations'],
        });
    }

    canHandle(input) {
        return Boolean(input && input.projectRoot && fs.existsSync(input.projectRoot));
    }

    async discover(input) {
        const { projectRoot, config } = input;
        const records = [];
        const fileInventory = input.fileInventory || walkFiles(projectRoot, config);
        for (const fullPath of fileInventory) {
            const relativePath = normalizePath(path.relative(projectRoot, fullPath));
            let stat;
            try {
                stat = fs.statSync(fullPath);
            } catch (error) {
                records.push({
                    id: sourceId(relativePath),
                    path: relativePath,
                    type: fileType(relativePath),
                    classification: 'review_required',
                    reason: `file metadata could not be read: ${error.code || 'unreadable'}`,
                    byte_count: 0,
                    line_count: 0,
                    hash: sha256(`stat-error:${relativePath}:${error.code || error.message}`),
                    summary: 'File metadata requires explicit review before inclusion.',
                    provenance: {
                        adapter: this.name,
                        root: projectRoot,
                        source_kind: 'local_file',
                    },
                });
                continue;
            }
            const policy = classifyPath(relativePath, config);
            const type = fileType(relativePath);
            const baseRecord = {
                id: sourceId(relativePath),
                path: relativePath,
                type,
                classification: policy.classification,
                reason: policy.reason,
                byte_count: stat.size,
                line_count: 0,
                provenance: {
                    adapter: this.name,
                    root: projectRoot,
                    source_kind: 'local_file',
                },
            };

            const disposition = metadataDisposition(relativePath, config, stat);
            if (disposition) {
                records.push({ ...baseRecord, ...disposition });
                continue;
            }

            let raw;
            try {
                raw = fs.readFileSync(fullPath);
            } catch (error) {
                records.push({
                    ...baseRecord,
                    classification: 'review_required',
                    reason: `allowed path matched, but file could not be read: ${error.code || 'unreadable'}`,
                    hash: sha256(`read-error:${relativePath}:${stat.size}:${Math.trunc(stat.mtimeMs)}:${error.code || error.message}`),
                    summary: 'Unreadable file requires explicit review before inclusion.',
                });
                continue;
            }
            // Retain the post-read check: a file can grow after stat admission.
            const afterRead = metadataDisposition(relativePath, config, stat, raw.length);
            if (afterRead) {
                records.push({ ...baseRecord, ...afterRead });
                continue;
            }

            const text = raw.toString('utf8');
            const redactedText = redactSensitiveText(text);
            records.push({
                ...baseRecord,
                hash: sha256(text),
                summary: summarizeText(redactedText, type),
                content_preview: previewText(text),
                code_facts: type === 'code' ? extractCodeFacts(redactedText, relativePath) : null,
                heading: firstMarkdownHeading(redactedText),
                line_count: text.length ? text.split(/\r?\n/).length : 0,
            });
        }
        return records;
    }
}

module.exports = {
    FilesystemAdapter,
    fileType,
    isTextFile,
    metadataDisposition,
    readAdmittedSource,
    isGeneratedEcfArtifactPath,
    previewText,
    redactSensitiveText,
    summarizeText,
    walkFiles,
};
