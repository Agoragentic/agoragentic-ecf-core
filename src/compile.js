'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { AdapterRegistry } = require('./adapters/base');
const { FilesystemAdapter, readAdmittedSource, walkFiles } = require('./adapters/filesystem');
const { MarkdownDocsAdapter } = require('./adapters/markdown-docs');
const { McpContextProviderAdapter } = require('./adapters/mcp-context');
const { OpenApiAdapter } = require('./adapters/openapi');
const { SqliteSummaryAdapter } = require('./adapters/sqlite-summary');
const { loadConfig } = require('./core/config');
const { sha256 } = require('./core/hash');
const {
    buildEvidenceUnits,
    buildContextCompactionReport,
    buildContextEvidenceUnits,
} = require('./evidence-units');
const { buildContextIndexes } = require('./context-index');
const {
    buildCodeIndex,
    buildContextRouter,
    buildSourceManifest,
} = require('./context-router');

function nowIso() {
    return new Date().toISOString();
}

function writeJson(filePath, value) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function relativeArtifact(projectRoot, outDir, fileName) {
    return path.relative(projectRoot, path.join(outDir, fileName)).replace(/\\/g, '/');
}

const GENERATED_MICRO_ECF_ROOT_FILES = new Set([
    'AGENTS.md',
    'ECF.md',
    'MICRO_ECF_LLM_BOOTSTRAP.md',
]);

function rootSourcePath(sourcePath) {
    return String(sourcePath || '').split('#')[0];
}

function looksLikeGeneratedMicroEcfFile(projectRoot, sourcePath, config) {
    const rootPath = rootSourcePath(sourcePath);
    if (!GENERATED_MICRO_ECF_ROOT_FILES.has(rootPath)) return false;
    const filePath = path.join(projectRoot, rootPath);
    if (!fs.existsSync(filePath)) return false;
    let text = '';
    try {
        const raw = readAdmittedSource(filePath, rootPath, config);
        if (raw === null) return false;
        text = raw.toString('utf8');
    } catch {
        return false;
    }
    if (rootPath === 'MICRO_ECF_LLM_BOOTSTRAP.md') return /Micro ECF LLM Bootstrap/i.test(text);
    if (rootPath === 'AGENTS.md') return /uses Micro ECF as a local context wedge/i.test(text);
    if (rootPath === 'ECF.md') {
        return /^---\s*\n[\s\S]{0,400}version:\s*["']?0\.1["']?/m.test(text)
            && /Micro ECF Contract|local context wedge/i.test(text);
    }
    return false;
}

function filterGeneratedEcfArtifacts(records, projectRoot, config) {
    const generated = [];
    const kept = [];
    const markerDecisions = new Map();
    for (const record of records) {
        const sourcePath = rootSourcePath(record.path);
        if (sourcePath.startsWith('.ecf-core/') || sourcePath.startsWith('.micro-ecf/')) {
            generated.push(record);
            continue;
        }
        if (GENERATED_MICRO_ECF_ROOT_FILES.has(sourcePath) && !markerDecisions.has(sourcePath)) {
            markerDecisions.set(sourcePath, looksLikeGeneratedMicroEcfFile(projectRoot, sourcePath, config));
        }
        if (markerDecisions.get(sourcePath)) {
            generated.push(record);
            continue;
        }
        kept.push(record);
    }
    return { kept, generated };
}

function buildPolicySummary(config) {
    return {
        schema_version: 'ecf-core.policy-summary.v1',
        allowed_sources: config.allow,
        blocked_sources: config.block,
        tool_limits: config.tool_limits,
        handoff: config.handoff,
    };
}

function baseBoundary() {
    return {
        includes_hosted_runtime: false,
        includes_wallet_or_settlement: false,
        includes_full_ecf_private_internals: false,
        includes_marketplace_routing: false,
    };
}

function buildReadinessChecks({ contextPacket, sourceMap, config }) {
    const sourceIds = new Set(contextPacket.sources.map((source) => source.id));
    const citationIds = new Set(contextPacket.citations.map((citation) => citation.source_id));
    const missingCitationIds = [...sourceIds].filter((id) => !citationIds.has(id));
    const blockedInPacket = contextPacket.sources.filter((source) => (
        sourceMap.sources.some((mapped) => mapped.id === source.id && mapped.classification === 'blocked')
    ));
    return [
        {
            id: 'no_spend_or_settlement',
            status: 'pass',
            detail: 'ECF Core exports are preview-only and do not authorize wallet, x402, or settlement actions.',
        },
        {
            id: 'live_deploy_disabled',
            status: config.handoff.live_deploy_allowed === false ? 'pass' : 'fail',
            detail: 'ECF Core can prepare Agent OS preview artifacts, but live deploy remains disabled.',
        },
        {
            id: 'citation_coverage',
            status: missingCitationIds.length === 0 ? 'pass' : 'warn',
            detail: `${contextPacket.citations.length}/${contextPacket.sources.length} sources have citations.`,
            missing_source_ids: missingCitationIds,
        },
        {
            id: 'blocked_sources_excluded',
            status: blockedInPacket.length === 0 ? 'pass' : 'fail',
            detail: `${blockedInPacket.length} blocked sources appeared in the context packet.`,
            blocked_source_ids: blockedInPacket.map((source) => source.id),
        },
    ];
}

function buildContextIndexReadiness(contextIndexes, evidenceUnits = null) {
    if (!contextIndexes) return null;
    const { pageIndex, treeIndex, retrievalPlan } = contextIndexes;
    const nodes = treeIndex?.summary?.node_count || 0;
    const evidenceUnitCount = Array.isArray(evidenceUnits?.units)
        ? evidenceUnits.units.length
        : pageIndex?.summary?.section_count || 0;
    return {
        providers: pageIndex?.providers || [],
        files: {
            evidence_units: 'evidence-units.json',
            page_index: 'page-index.json',
            tree_index: 'tree-index.json',
            retrieval_plan: 'retrieval-plan.json',
        },
        source_count: pageIndex?.summary?.source_count || 0,
        page_count: pageIndex?.summary?.page_count || 0,
        tree_node_count: nodes,
        evidence_unit_count: evidenceUnitCount,
        retrieval_query_count: retrievalPlan?.summary?.query_count || 0,
        unsupported_questions: retrievalPlan?.unsupported_questions || [],
        sources_requiring_public_exposure_review: (treeIndex?.nodes || [])
            .filter((node) => node.source_id && node.policy_flags?.requires_public_exposure_review)
            .map((node) => node.source_path),
        dependency_status: pageIndex?.dependency_status || 'builtin_local_only',
    };
}

function buildCompileReadinessSummary({ contextPacket, sourceMap, evidenceUnits, contextIndexes, groundingSummary = null, checks = [] }) {
    const totalSources = sourceMap?.sources?.length || 0;
    const allowedSources = contextPacket?.sources?.length || 0;
    const blockedSources = (sourceMap?.sources || []).filter((source) => source.classification === 'blocked');
    const reviewRequiredSources = (sourceMap?.sources || []).filter((source) => source.classification === 'review_required');
    const blockedInPacket = contextPacket?.sources?.filter((source) => (
        blockedSources.some((blocked) => blocked.id === source.id)
    )) || [];
    const units = evidenceUnits?.units || [];
    const reviewRequiredUnits = units.filter((unit) => unit.policy?.requires_review).length;
    const citedUnits = units.filter((unit) => Array.isArray(unit.citations) && unit.citations.length > 0).length;
    const citationCoverage = units.length ? citedUnits / units.length : 1;
    const groundingTotal = groundingSummary?.summary?.queries || 0;
    const groundingPassRate = groundingTotal ? groundingSummary.summary.grounded / groundingTotal : null;
    const blockingFailure = checks.some((check) => check.status === 'fail');
    const contextReadinessPercent = Math.round(Math.max(0, Math.min(1, (
        (blockedInPacket.length === 0 ? 0.35 : 0)
        + (citationCoverage * 0.25)
        + (contextIndexes?.treeIndex?.summary?.node_count > 0 ? 0.20 : 0)
        + (groundingPassRate === null ? 0.10 : groundingPassRate * 0.20)
    ))) * 100);
    return {
        label: 'ECF Compile Stage',
        context_readiness_percent: contextReadinessPercent,
        sources_compiled: allowedSources,
        total_sources_seen: totalSources,
        evidence_units: units.length,
        review_required_unit_count: reviewRequiredUnits,
        grounded_queries: groundingTotal ? `${groundingSummary.summary.grounded}/${groundingTotal}` : null,
        grounding_pass_rate: groundingPassRate === null ? null : Number(groundingPassRate.toFixed(4)),
        blocked_sources_excluded: blockedInPacket.length === 0,
        blocked_source_count: blockedSources.length,
        review_required_sources: reviewRequiredSources.length,
        public_safe_context: reviewRequiredUnits === 0 && blockedInPacket.length === 0 ? 'partial' : 'needs_review',
        ready_for_preview: !blockingFailure,
        ready_for_live_deployment: 'needs_owner_review',
        context_compile_verdict: !blockingFailure && blockedInPacket.length === 0 ? 'preview_ready' : 'blocked',
    };
}

function buildDeploymentPreview({
    contextPacket,
    sourceMap,
    config,
    evidenceUnits = null,
    contextIndexes = null,
    sourceManifest = null,
    codeIndex = null,
    contextRouter = null,
    groundingSummary = null,
}) {
    const checks = buildReadinessChecks({ contextPacket, sourceMap, config });
    const contextIndexReadiness = buildContextIndexReadiness(contextIndexes, evidenceUnits);
    if (contextIndexReadiness) {
        checks.push({
            id: 'context_index',
            status: contextIndexReadiness.tree_node_count > 0 ? 'pass' : 'warn',
            detail: `${contextIndexReadiness.tree_node_count} tree nodes and ${contextIndexReadiness.evidence_unit_count} indexed sections generated.`,
            dependency_status: contextIndexReadiness.dependency_status,
        });
    }
    if (groundingSummary) {
        checks.push({
            id: 'grounding_eval',
            status: groundingSummary.verdict === 'pass' ? 'pass' : 'warn',
            detail: `${groundingSummary.summary.grounded}/${groundingSummary.summary.queries} grounding queries passed.`,
            hallucination_risk: groundingSummary.summary.hallucination_risk,
        });
    }
    const contextCompileReadiness = buildCompileReadinessSummary({
        contextPacket,
        sourceMap,
        evidenceUnits,
        contextIndexes,
        groundingSummary,
        checks,
    });
    return {
        schema_version: 'ecf-core.deployment-preview.v1',
        mode: 'agent_os_preview',
        live_deploy_allowed: false,
        checks,
        artifacts: {
            context_packet: 'context-packet.json',
            source_map: 'source-map.json',
            source_manifest: sourceManifest ? 'source-manifest.json' : null,
            policy_summary: 'policy-summary.json',
            evidence_units: 'evidence-units.json',
            context_evidence_units: 'context-evidence-units.json',
            context_compaction_report: 'context-compaction-report.json',
            page_index: contextIndexes ? 'page-index.json' : null,
            tree_index: contextIndexes ? 'tree-index.json' : null,
            retrieval_plan: contextIndexes ? 'retrieval-plan.json' : null,
            code_index: codeIndex ? 'code-index.json' : null,
            context_router: contextRouter ? 'context-router.json' : null,
            grounding_eval: groundingSummary ? 'grounding-eval.json' : null,
        },
        context_compile_readiness: contextCompileReadiness,
        context_index_readiness: contextIndexReadiness,
        next_step: checks.every((check) => check.status !== 'fail')
            ? 'review_agent_os_preview'
            : 'fix_failed_checks_before_preview',
    };
}

function buildAgentOsHarness({ deploymentPreview }) {
    return {
        schema_version: 'ecf-core.agent-os-harness.v1',
        generated_by: 'ecf-core',
        context_layer: 'ecf_core',
        artifacts: {
            context_packet: 'context-packet.json',
            source_map: 'source-map.json',
            source_manifest: deploymentPreview.artifacts.source_manifest,
            policy_summary: 'policy-summary.json',
            evidence_units: 'evidence-units.json',
            context_evidence_units: 'context-evidence-units.json',
            context_compaction_report: 'context-compaction-report.json',
            page_index: deploymentPreview.artifacts.page_index,
            tree_index: deploymentPreview.artifacts.tree_index,
            retrieval_plan: deploymentPreview.artifacts.retrieval_plan,
            code_index: deploymentPreview.artifacts.code_index,
            context_router: deploymentPreview.artifacts.context_router,
            deployment_preview: 'deployment-preview.json',
            grounding_eval: deploymentPreview.artifacts.grounding_eval,
        },
        boundary: baseBoundary(),
        readiness: {
            live_deploy_allowed: false,
            checks: deploymentPreview.checks,
        },
        context_compile_readiness: deploymentPreview.context_compile_readiness,
        context_index_readiness: deploymentPreview.context_index_readiness,
        agent_os_preview: {
            allowed: deploymentPreview.checks.every((check) => check.status !== 'fail'),
            requires_user_review: true,
        },
    };
}

function buildAgentOsImport({ deploymentPreview }) {
    const requiredFiles = [
        'context-packet.json',
        'source-map.json',
        'source-manifest.json',
        'policy-summary.json',
        'evidence-units.json',
        'context-evidence-units.json',
        'context-compaction-report.json',
        'code-index.json',
        'context-router.json',
        'deployment-preview.json',
        'agent-os-harness.json',
        'agent-os-handoff.json',
    ];
    for (const artifact of ['page_index', 'tree_index', 'retrieval_plan']) {
        if (deploymentPreview.artifacts[artifact]) requiredFiles.push(deploymentPreview.artifacts[artifact]);
    }
    if (deploymentPreview.artifacts.grounding_eval) requiredFiles.push(deploymentPreview.artifacts.grounding_eval);
    return {
        schema_version: 'ecf-core.agent-os-import.v1',
        import_mode: 'preview_only',
        live_deploy_allowed: false,
        required_files: requiredFiles,
        acceptance_checks: deploymentPreview.checks.map((check) => ({
            id: check.id,
            required_status: check.id === 'citation_coverage' ? ['pass', 'warn'] : ['pass'],
        })),
        boundary: baseBoundary(),
        evidence: {
            evidence_units: deploymentPreview.artifacts.evidence_units,
            context_evidence_units: deploymentPreview.artifacts.context_evidence_units,
            context_compaction_report: deploymentPreview.artifacts.context_compaction_report,
            source_manifest: deploymentPreview.artifacts.source_manifest,
            page_index: deploymentPreview.artifacts.page_index,
            tree_index: deploymentPreview.artifacts.tree_index,
            retrieval_plan: deploymentPreview.artifacts.retrieval_plan,
            code_index: deploymentPreview.artifacts.code_index,
            context_router: deploymentPreview.artifacts.context_router,
            grounding_eval: deploymentPreview.artifacts.grounding_eval,
        },
        context_compile_readiness: deploymentPreview.context_compile_readiness,
        context_index_readiness: deploymentPreview.context_index_readiness,
        next_step: 'agent_os_preview_import',
    };
}

function buildAgentOsHandoff({
    contextPacketPath,
    sourceMapPath,
    sourceManifestPath,
    policySummaryPath,
    pageIndexPath,
    treeIndexPath,
    retrievalPlanPath,
    codeIndexPath,
    contextRouterPath,
    evidenceUnitsPath,
    deploymentPreviewPath,
    agentOsHarnessPath,
    config,
}) {
    return {
        schema_version: 'ecf-core.agent-os-handoff.v1',
        context_packet: contextPacketPath,
        source_map: sourceMapPath,
        source_manifest: sourceManifestPath,
        policy_summary: policySummaryPath,
        evidence_units: evidenceUnitsPath,
        page_index: pageIndexPath,
        tree_index: treeIndexPath,
        retrieval_plan: retrievalPlanPath,
        code_index: codeIndexPath,
        context_router: contextRouterPath,
        deployment_preview: deploymentPreviewPath,
        agent_os_harness: agentOsHarnessPath,
        agent_os_preview: {
            allowed: Boolean(config.handoff.agent_os_preview_allowed),
            live_deploy_allowed: false,
            recommended_next_step: 'review_in_agent_os_preview',
        },
        boundary: baseBoundary(),
    };
}

function applyGroundingReadiness(summary, grounding) {
    if (!summary) return summary;
    const total = grounding.summary?.queries || 0;
    const passRate = total ? grounding.summary.grounded / total : null;
    const readinessDelta = passRate === null ? 0 : Math.round((passRate - 0.5) * 20);
    return {
        ...summary,
        grounded_queries: total ? `${grounding.summary.grounded}/${total}` : null,
        grounding_pass_rate: passRate === null ? null : Number(passRate.toFixed(4)),
        context_readiness_percent: Math.max(0, Math.min(100, Number(summary.context_readiness_percent || 0) + readinessDelta)),
        context_compile_verdict: grounding.verdict === 'pass' && summary.context_compile_verdict !== 'blocked'
            ? 'preview_ready'
            : summary.context_compile_verdict,
    };
}

function applyGroundingEvidence({ outDir, grounding }) {
    const deploymentPreviewPath = path.join(outDir, 'deployment-preview.json');
    const agentOsHarnessPath = path.join(outDir, 'agent-os-harness.json');
    const agentOsImportPath = path.join(outDir, 'agent-os-import.json');
    const manifestPath = path.join(outDir, 'manifest.json');
    const retrievalPlanPath = path.join(outDir, 'retrieval-plan.json');
    if (!fs.existsSync(deploymentPreviewPath) || !fs.existsSync(agentOsHarnessPath) || !fs.existsSync(agentOsImportPath)) {
        return;
    }
    const deploymentPreview = JSON.parse(fs.readFileSync(deploymentPreviewPath, 'utf8'));
    const agentOsHarness = JSON.parse(fs.readFileSync(agentOsHarnessPath, 'utf8'));
    const agentOsImport = JSON.parse(fs.readFileSync(agentOsImportPath, 'utf8'));
    const check = {
        id: 'grounding_eval',
        status: grounding.verdict === 'pass' ? 'pass' : 'warn',
        detail: `${grounding.summary.grounded}/${grounding.summary.queries} grounding queries passed.`,
        hallucination_risk: grounding.summary.hallucination_risk,
    };
    const unsupportedQuestions = (grounding.questions || [])
        .filter((question) => question.status !== 'grounded')
        .map((question) => ({
            question: question.question,
            status: question.status,
            suggested_fix: question.suggested_fix,
        }));
    deploymentPreview.artifacts.grounding_eval = 'grounding-eval.json';
    deploymentPreview.checks = [
        ...deploymentPreview.checks.filter((item) => item.id !== 'grounding_eval'),
        check,
    ];
    if (deploymentPreview.context_index_readiness) {
        deploymentPreview.context_index_readiness.unsupported_questions = unsupportedQuestions;
    }
    deploymentPreview.context_compile_readiness = applyGroundingReadiness(
        deploymentPreview.context_compile_readiness,
        grounding
    );
    agentOsHarness.artifacts.grounding_eval = 'grounding-eval.json';
    agentOsHarness.readiness.checks = [
        ...agentOsHarness.readiness.checks.filter((item) => item.id !== 'grounding_eval'),
        check,
    ];
    if (agentOsHarness.context_index_readiness) {
        agentOsHarness.context_index_readiness.unsupported_questions = unsupportedQuestions;
    }
    agentOsHarness.context_compile_readiness = applyGroundingReadiness(
        agentOsHarness.context_compile_readiness,
        grounding
    );
    if (!agentOsImport.required_files.includes('grounding-eval.json')) {
        agentOsImport.required_files.push('grounding-eval.json');
    }
    agentOsImport.evidence = {
        ...(agentOsImport.evidence || {}),
        grounding_eval: 'grounding-eval.json',
    };
    if (agentOsImport.context_index_readiness) {
        agentOsImport.context_index_readiness.unsupported_questions = unsupportedQuestions;
    }
    agentOsImport.context_compile_readiness = applyGroundingReadiness(
        agentOsImport.context_compile_readiness,
        grounding
    );
    writeJson(deploymentPreviewPath, deploymentPreview);
    writeJson(agentOsHarnessPath, agentOsHarness);
    writeJson(agentOsImportPath, agentOsImport);
    if (fs.existsSync(retrievalPlanPath)) {
        const retrievalPlan = JSON.parse(fs.readFileSync(retrievalPlanPath, 'utf8'));
        retrievalPlan.unsupported_questions = unsupportedQuestions;
        writeJson(retrievalPlanPath, retrievalPlan);
    }
    if (fs.existsSync(manifestPath)) {
        const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
        manifest.files.grounding_eval = 'grounding-eval.json';
        writeJson(manifestPath, manifest);
    }
}

function validateSchemaVersion(value, expected, fileName, errors) {
    if (!value || value.schema_version !== expected) {
        errors.push(`${fileName} missing schema_version=${expected}`);
    }
}

function readJsonIfPresent(filePath, errors) {
    if (!fs.existsSync(filePath)) {
        errors.push(`${filePath} does not exist`);
        return null;
    }
    try {
        return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch (error) {
        errors.push(`${filePath} is not valid JSON: ${error.message}`);
        return null;
    }
}

function validateCompiledArtifacts(artifactDir) {
    const errors = [];
    const contextPacket = readJsonIfPresent(path.join(artifactDir, 'context-packet.json'), errors);
    const sourceMap = readJsonIfPresent(path.join(artifactDir, 'source-map.json'), errors);
    const policySummary = readJsonIfPresent(path.join(artifactDir, 'policy-summary.json'), errors);
    const groundingEvalPath = path.join(artifactDir, 'grounding-eval.json');
    const evidenceUnitsPath = path.join(artifactDir, 'context-evidence-units.json');
    const compactionReportPath = path.join(artifactDir, 'context-compaction-report.json');
    const pageIndexPath = path.join(artifactDir, 'page-index.json');
    const treeIndexPath = path.join(artifactDir, 'tree-index.json');
    const retrievalPlanPath = path.join(artifactDir, 'retrieval-plan.json');
    const sourceManifestPath = path.join(artifactDir, 'source-manifest.json');
    const codeIndexPath = path.join(artifactDir, 'code-index.json');
    const contextRouterPath = path.join(artifactDir, 'context-router.json');
    const compileStageEvidenceUnitsPath = path.join(artifactDir, 'evidence-units.json');

    validateSchemaVersion(contextPacket, 'ecf-core.context-packet.v1', 'context-packet.json', errors);
    validateSchemaVersion(sourceMap, 'ecf-core.source-map.v1', 'source-map.json', errors);
    validateSchemaVersion(policySummary, 'ecf-core.policy-summary.v1', 'policy-summary.json', errors);

    if (contextPacket && !Array.isArray(contextPacket.sources)) errors.push('context-packet.json sources must be an array');
    if (contextPacket && !Array.isArray(contextPacket.citations)) errors.push('context-packet.json citations must be an array');
    if (sourceMap && !Array.isArray(sourceMap.sources)) errors.push('source-map.json sources must be an array');
    if (policySummary && !Array.isArray(policySummary.allowed_sources)) errors.push('policy-summary.json allowed_sources must be an array');
    if (policySummary && !Array.isArray(policySummary.blocked_sources)) errors.push('policy-summary.json blocked_sources must be an array');
    if (fs.existsSync(groundingEvalPath)) {
        const groundingEval = readJsonIfPresent(groundingEvalPath, errors);
        validateSchemaVersion(groundingEval, 'ecf-core.grounding-eval.v1', 'grounding-eval.json', errors);
        if (groundingEval && !Array.isArray(groundingEval.questions)) errors.push('grounding-eval.json questions must be an array');
        if (groundingEval && !groundingEval.summary) errors.push('grounding-eval.json summary is required');
    }
    if (fs.existsSync(evidenceUnitsPath)) {
        const evidenceUnits = readJsonIfPresent(evidenceUnitsPath, errors);
        validateSchemaVersion(evidenceUnits, 'ecf-core.context-evidence-units.v1', 'context-evidence-units.json', errors);
        if (evidenceUnits && !Array.isArray(evidenceUnits.units)) errors.push('context-evidence-units.json units must be an array');
    }
    if (fs.existsSync(compileStageEvidenceUnitsPath)) {
        const evidenceUnits = readJsonIfPresent(compileStageEvidenceUnitsPath, errors);
        validateSchemaVersion(evidenceUnits, 'ecf-core.evidence-units.v1', 'evidence-units.json', errors);
        if (evidenceUnits && !Array.isArray(evidenceUnits.units)) errors.push('evidence-units.json units must be an array');
    }
    if (fs.existsSync(compactionReportPath)) {
        const compactionReport = readJsonIfPresent(compactionReportPath, errors);
        validateSchemaVersion(compactionReport, 'ecf-core.context-compaction-report.v1', 'context-compaction-report.json', errors);
        if (compactionReport && !compactionReport.retrieval_preservation) errors.push('context-compaction-report.json retrieval_preservation is required');
    }
    if (fs.existsSync(pageIndexPath)) {
        const pageIndex = readJsonIfPresent(pageIndexPath, errors);
        validateSchemaVersion(pageIndex, 'ecf-core.page-index.v1', 'page-index.json', errors);
        if (pageIndex && !Array.isArray(pageIndex.sources)) errors.push('page-index.json sources must be an array');
        if (pageIndex && !pageIndex.summary) errors.push('page-index.json summary is required');
    }
    if (fs.existsSync(treeIndexPath)) {
        const treeIndex = readJsonIfPresent(treeIndexPath, errors);
        validateSchemaVersion(treeIndex, 'ecf-core.tree-index.v1', 'tree-index.json', errors);
        if (treeIndex && !Array.isArray(treeIndex.nodes)) errors.push('tree-index.json nodes must be an array');
        if (treeIndex && !Array.isArray(treeIndex.edges)) errors.push('tree-index.json edges must be an array');
    }
    if (fs.existsSync(retrievalPlanPath)) {
        const retrievalPlan = readJsonIfPresent(retrievalPlanPath, errors);
        validateSchemaVersion(retrievalPlan, 'ecf-core.retrieval-plan.v1', 'retrieval-plan.json', errors);
        if (retrievalPlan && !Array.isArray(retrievalPlan.queries)) errors.push('retrieval-plan.json queries must be an array');
    }
    if (fs.existsSync(sourceManifestPath)) {
        const sourceManifest = readJsonIfPresent(sourceManifestPath, errors);
        validateSchemaVersion(sourceManifest, 'ecf-core.source-manifest.v1', 'source-manifest.json', errors);
        if (sourceManifest && !Array.isArray(sourceManifest.entries)) errors.push('source-manifest.json entries must be an array');
        if (sourceManifest && !sourceManifest.summary) errors.push('source-manifest.json summary is required');
    }
    if (fs.existsSync(codeIndexPath)) {
        const codeIndex = readJsonIfPresent(codeIndexPath, errors);
        validateSchemaVersion(codeIndex, 'ecf-core.code-index.v1', 'code-index.json', errors);
        if (codeIndex && !Array.isArray(codeIndex.sources)) errors.push('code-index.json sources must be an array');
        if (codeIndex && !codeIndex.summary) errors.push('code-index.json summary is required');
    }
    if (fs.existsSync(contextRouterPath)) {
        const contextRouter = readJsonIfPresent(contextRouterPath, errors);
        validateSchemaVersion(contextRouter, 'ecf-core.context-router.v1', 'context-router.json', errors);
        if (contextRouter && !Array.isArray(contextRouter.routes)) errors.push('context-router.json routes must be an array');
        if (contextRouter && !contextRouter.artifact_summary) errors.push('context-router.json artifact_summary is required');
    }

    return {
        ok: errors.length === 0,
        artifact_dir: artifactDir,
        errors,
    };
}

async function compileProject(options = {}) {
    const projectRoot = path.resolve(options.projectRoot || '.');
    const outDir = path.resolve(options.outDir || path.join(projectRoot, '.ecf-core'));
    const config = loadConfig({ projectRoot, configPath: options.configPath });
    const createdAt = nowIso();

    const registry = new AdapterRegistry();
    registry.register(new FilesystemAdapter());
    registry.register(new MarkdownDocsAdapter());
    registry.register(new SqliteSummaryAdapter());
    registry.register(new OpenApiAdapter());
    registry.register(new McpContextProviderAdapter());
    for (const adapter of options.adapters || []) registry.register(adapter);

    const walkState = { skippedDirectories: [] };
    const fileInventory = walkFiles(projectRoot, config, projectRoot, [], walkState);
    const discoveredRecords = await registry.discoverAll({ projectRoot, config, fileInventory, walkState });
    const generatedArtifactFilter = filterGeneratedEcfArtifacts(discoveredRecords, projectRoot, config);
    const records = generatedArtifactFilter.kept;
    const allowed = records.filter((record) => record.classification === 'allowed');
    const blocked = records.filter((record) => record.classification === 'blocked');
    const reviewRequired = records.filter((record) => record.classification === 'review_required');

    const sources = allowed.map((record) => ({
        id: record.id,
        path: record.path,
        type: record.type,
        hash: record.hash,
        summary: record.summary,
        content_preview: record.content_preview || null,
        code_facts: record.code_facts || null,
        heading: record.heading || null,
        byte_count: record.byte_count,
        line_count: record.line_count,
        provenance: record.provenance,
    }));

    const citations = allowed.map((record, index) => ({
        source_id: record.id,
        label: `[${index + 1}] ${record.path}`,
        path: record.path,
        heading: record.heading || null,
    }));

    const packetHash = sha256(`${config.project_name}:${allowed.map((record) => `${record.path}:${record.hash}`).join('|')}`);
    const contextPacket = {
        schema_version: 'ecf-core.context-packet.v1',
        packet_id: `ctx_${packetHash.slice(0, 16)}`,
        scope: config.scope,
        created_at: createdAt,
        sources,
        citations,
        policy: {
            allowed_context: config.allow,
            blocked_context: config.block,
            tool_limits: config.tool_limits,
            handoff: config.handoff,
        },
    };

    const sourceMap = {
        schema_version: 'ecf-core.source-map.v1',
        sources: records.map((record) => ({
            id: record.id,
            path: record.path,
            hash: record.hash,
            classification: record.classification,
            reason: record.reason,
            type: record.type,
            provenance: record.provenance,
        })),
    };

    const policySummary = buildPolicySummary(config);
    const evidenceUnits = buildContextEvidenceUnits({ contextPacket, createdAt });
    const compileStageEvidenceUnits = buildEvidenceUnits({ contextPacket, createdAt });
    const compactionReport = buildContextCompactionReport({
        contextPacket,
        evidenceUnits,
        queries: Array.isArray(config.eval?.queries) ? config.eval.queries : [],
        topKSize: Number.isFinite(Number(config.eval?.top_k)) ? Math.max(1, Number(config.eval.top_k)) : 3,
        evalConfig: config.eval || {},
    });
    const contextIndexes = buildContextIndexes({
        contextPacket,
        sourceMap,
        config,
        createdAt,
    });
    const codeIndex = buildCodeIndex({ contextPacket, createdAt });
    const sourceManifest = buildSourceManifest({
        records,
        generatedRecords: generatedArtifactFilter.generated,
        walkState,
        contextPacket,
        codeIndex,
        createdAt,
    });
    const contextRouter = buildContextRouter({
        sourceManifest,
        codeIndex,
        retrievalPlan: contextIndexes.retrievalPlan,
        createdAt,
    });

    const contextPacketPath = path.join(outDir, 'context-packet.json');
    const sourceMapPath = path.join(outDir, 'source-map.json');
    const policySummaryPath = path.join(outDir, 'policy-summary.json');
    writeJson(contextPacketPath, contextPacket);
    writeJson(sourceMapPath, sourceMap);
    writeJson(policySummaryPath, policySummary);
    writeJson(path.join(outDir, 'evidence-units.json'), compileStageEvidenceUnits);
    writeJson(path.join(outDir, 'context-evidence-units.json'), evidenceUnits);
    writeJson(path.join(outDir, 'context-compaction-report.json'), compactionReport);
    writeJson(path.join(outDir, 'page-index.json'), contextIndexes.pageIndex);
    writeJson(path.join(outDir, 'tree-index.json'), contextIndexes.treeIndex);
    writeJson(path.join(outDir, 'retrieval-plan.json'), contextIndexes.retrievalPlan);
    writeJson(path.join(outDir, 'source-manifest.json'), sourceManifest);
    writeJson(path.join(outDir, 'code-index.json'), codeIndex);
    writeJson(path.join(outDir, 'context-router.json'), contextRouter);

    let agentOsHandoff = null;
    let deploymentPreview = null;
    let agentOsHarness = null;
    let agentOsImport = null;
    if (options.emitAgentOs) {
        deploymentPreview = buildDeploymentPreview({
            contextPacket,
            sourceMap,
            config,
            evidenceUnits: compileStageEvidenceUnits,
            contextIndexes,
            sourceManifest,
            codeIndex,
            contextRouter,
        });
        agentOsHarness = buildAgentOsHarness({ deploymentPreview });
        agentOsImport = buildAgentOsImport({ deploymentPreview });
        writeJson(path.join(outDir, 'deployment-preview.json'), deploymentPreview);
        writeJson(path.join(outDir, 'agent-os-harness.json'), agentOsHarness);
        writeJson(path.join(outDir, 'agent-os-import.json'), agentOsImport);
        agentOsHandoff = buildAgentOsHandoff({
            contextPacketPath: 'context-packet.json',
            sourceMapPath: 'source-map.json',
            sourceManifestPath: 'source-manifest.json',
            policySummaryPath: 'policy-summary.json',
            evidenceUnitsPath: 'evidence-units.json',
            pageIndexPath: 'page-index.json',
            treeIndexPath: 'tree-index.json',
            retrievalPlanPath: 'retrieval-plan.json',
            codeIndexPath: 'code-index.json',
            contextRouterPath: 'context-router.json',
            deploymentPreviewPath: 'deployment-preview.json',
            agentOsHarnessPath: 'agent-os-harness.json',
            config,
        });
        writeJson(path.join(outDir, 'agent-os-handoff.json'), agentOsHandoff);
    }

    const manifest = {
        schema_version: 'ecf-core.manifest.v1',
        created_at: createdAt,
        project_root: projectRoot,
        out_dir: outDir,
        files: {
            context_packet: relativeArtifact(projectRoot, outDir, 'context-packet.json'),
            source_map: relativeArtifact(projectRoot, outDir, 'source-map.json'),
            source_manifest: relativeArtifact(projectRoot, outDir, 'source-manifest.json'),
            policy_summary: relativeArtifact(projectRoot, outDir, 'policy-summary.json'),
            evidence_units: relativeArtifact(projectRoot, outDir, 'evidence-units.json'),
            context_evidence_units: relativeArtifact(projectRoot, outDir, 'context-evidence-units.json'),
            context_compaction_report: relativeArtifact(projectRoot, outDir, 'context-compaction-report.json'),
            page_index: relativeArtifact(projectRoot, outDir, 'page-index.json'),
            tree_index: relativeArtifact(projectRoot, outDir, 'tree-index.json'),
            retrieval_plan: relativeArtifact(projectRoot, outDir, 'retrieval-plan.json'),
            code_index: relativeArtifact(projectRoot, outDir, 'code-index.json'),
            context_router: relativeArtifact(projectRoot, outDir, 'context-router.json'),
            agent_os_handoff: agentOsHandoff ? relativeArtifact(projectRoot, outDir, 'agent-os-handoff.json') : null,
            deployment_preview: deploymentPreview ? relativeArtifact(projectRoot, outDir, 'deployment-preview.json') : null,
            agent_os_harness: agentOsHarness ? relativeArtifact(projectRoot, outDir, 'agent-os-harness.json') : null,
            agent_os_import: agentOsImport ? relativeArtifact(projectRoot, outDir, 'agent-os-import.json') : null,
        },
        counts: {
            total_sources: records.length,
            discovered_sources: discoveredRecords.length,
            allowed_sources: allowed.length,
            blocked_sources: blocked.length,
            review_required_sources: reviewRequired.length,
            generated_sources_excluded: generatedArtifactFilter.generated.length + Number(walkState.generatedArtifactsExcluded || 0),
            citations: citations.length,
            evidence_units: compileStageEvidenceUnits.units.length,
            context_evidence_units: evidenceUnits.units.length,
            page_index_sources: contextIndexes.pageIndex.summary.source_count,
            tree_index_nodes: contextIndexes.treeIndex.summary.node_count,
            retrieval_plan_queries: contextIndexes.retrievalPlan.summary.query_count,
            code_index_sources: codeIndex.summary.source_count,
            code_index_symbols: codeIndex.summary.symbol_count,
            context_router_routes: contextRouter.routes.length,
        },
    };
    writeJson(path.join(outDir, 'manifest.json'), manifest);

    return {
        config,
        contextPacket,
        sourceMap,
        policySummary,
        evidenceUnits,
        compileStageEvidenceUnits,
        compactionReport,
        contextIndexes,
        sourceManifest,
        codeIndex,
        contextRouter,
        pageIndex: contextIndexes.pageIndex,
        treeIndex: contextIndexes.treeIndex,
        retrievalPlan: contextIndexes.retrievalPlan,
        agentOsHandoff,
        deploymentPreview,
        agentOsHarness,
        agentOsImport,
        manifest,
        records,
    };
}

module.exports = {
    buildAgentOsHarness,
    buildAgentOsHandoff,
    buildAgentOsImport,
    buildDeploymentPreview,
    compileProject,
    applyGroundingEvidence,
    validateCompiledArtifacts,
};
