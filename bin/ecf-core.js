#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {
    compileProject,
    createDefaultConfig,
    loadConfig,
    runEvaluation,
    runMcpServer,
    validateCompiledArtifacts,
    inspectAgentOsPreview,
    buildEcfCoreResidentStatus,
    writeEcfCoreResidentStatus,
    buildEcfCoreContextPack,
    writeEcfCoreContextPack,
    buildEcfCoreMcpConfig,
    writeEcfCoreMcpConfig,
    beginWorklog,
    buildHandoff,
    buildWorklogStatus,
    checkpointWorklog,
    finishWorklog,
    planDocsSync,
    writeHandoff,
} = require('../src');

function printHelp() {
    console.log(`ECF Core

Usage:
  ecf-core init [project] [--force]
  ecf-core compile [project] [--config ecf.config.json] [--out .ecf-core] [--json] [--agent-os]
  ecf-core eval [project] [--config ecf.config.json] [--out .ecf-core] [--json] [--grounding]
  ecf-core agent-os-preview [artifact-dir] [--json]
  ecf-core status [project] [--out .ecf-core] [--write] [--json]
  ecf-core context-pack [project] [--out .ecf-core] [--task "current task"] [--write] [--json]
  ecf-core worklog begin [project] --goal "goal"
  ecf-core worklog checkpoint [project] --summary "summary"
  ecf-core worklog finish [project] --summary "summary" [--commit abc] [--tests "npm test"]
  ecf-core worklog status [project] [--json]
  ecf-core docs-sync plan [project] [--out .ecf-core] [--json]
  ecf-core handoff [project] [--out .ecf-core] [--write] [--json]
  ecf-core mcp-config --target codex [project] [--out .ecf-core] [--write] [--install-codex]
  ecf-core serve-mcp [artifact-dir]
  ecf-core serve-mcp --verified-project /path/to/project
  ecf-core validate [artifact-dir]
  ecf-core version

Commands:
  init      Write a safe starter ecf.config.json.
  compile   Build context-packet, source-map, policy-summary, evidence, and index artifacts.
  eval      Compile and write deterministic JSON/Markdown evaluation reports.
  agent-os-preview
            Check compiled ECF Core artifacts before Agent OS preview import.
  status    Print or write local resident status for IDE/Codex context handoff.
  context-pack
            Print or write a local IDE/Codex context-pack summary.
  worklog   Persist local session continuity under .ecf-core/worklog/.
  docs-sync Plan documentation updates without auto-editing docs.
  handoff   Print or write the next-session handoff under .ecf-core/.
  mcp-config
            Generate or install a workspace-specific Codex MCP server entry.
  serve-mcp Serve compiled ECF Core artifacts over a local stdio MCP tool surface.
  validate  Validate required compiled artifacts exist and have expected schema versions.
  version   Print package version.
`);
}

function readFlag(args, name, fallback = null) {
    const index = args.indexOf(name);
    if (index === -1) return fallback;
    const value = args[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`${name} requires a value`);
    return value;
}

function positional(args) {
    return args.filter((arg, index) => {
        if (arg.startsWith('--')) return false;
            const previous = args[index - 1];
        return !(previous
            && previous.startsWith('--')
            && previous !== '--json'
            && previous !== '--agent-os'
            && previous !== '--force'
            && previous !== '--grounding'
            && previous !== '--write'
            && previous !== '--install-codex');
    });
}

function ensureDir(dir) {
    fs.mkdirSync(dir, { recursive: true });
}

function writeJson(filePath, value, force = false) {
    if (fs.existsSync(filePath) && !force) {
        throw new Error(`${filePath} already exists. Re-run with --force to overwrite.`);
    }
    fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

async function main() {
    const [command = 'help', ...args] = process.argv.slice(2);

    if (command === 'help' || command === '--help' || command === '-h') {
        printHelp();
        return;
    }

    if (command === 'eval') {
        const [projectArg = '.'] = positional(args);
        const projectRoot = path.resolve(projectArg);
        const configPath = readFlag(args, '--config');
        const outDir = readFlag(args, '--out', '.ecf-core');
        const report = await runEvaluation({
            projectRoot,
            configPath: configPath && configPath !== true ? path.resolve(configPath) : null,
            outDir: path.resolve(projectRoot, outDir),
            grounding: args.includes('--grounding'),
        });
        if (args.includes('--json')) {
            console.log(JSON.stringify(report.summary, null, 2));
        } else {
            console.log(`ECF Core packet-readiness verdict: ${report.summary.verdict}`);
            console.log(`JSON report: ${report.files.json}`);
            console.log(`Markdown report: ${report.files.markdown}`);
        }
        return;
    }

    if (command === 'version' || command === '--version' || command === '-v') {
        const pkg = require('../package.json');
        console.log(pkg.version);
        return;
    }

    if (command === 'init') {
        const [projectArg = '.'] = positional(args);
        const projectRoot = path.resolve(projectArg);
        const force = args.includes('--force');
        ensureDir(projectRoot);
        const configPath = path.join(projectRoot, 'ecf.config.json');
        writeJson(configPath, createDefaultConfig({ projectName: path.basename(projectRoot) || 'local-project' }), force);
        console.log(`Wrote ${configPath}`);
        return;
    }

    if (command === 'compile') {
        const [projectArg = '.'] = positional(args);
        const projectRoot = path.resolve(projectArg);
        const configPath = readFlag(args, '--config');
        const outDir = readFlag(args, '--out', '.ecf-core');
        const result = await compileProject({
            projectRoot,
            configPath: configPath && configPath !== true ? path.resolve(configPath) : null,
            outDir: path.resolve(projectRoot, outDir),
            emitAgentOs: args.includes('--agent-os'),
        });
        if (args.includes('--json')) {
            console.log(JSON.stringify(result.manifest, null, 2));
        } else {
            console.log(`Compiled ${result.manifest.counts.allowed_sources} allowed sources into ${result.manifest.out_dir}`);
            console.log(`Blocked ${result.manifest.counts.blocked_sources} sources and marked ${result.manifest.counts.review_required_sources} for review.`);
        }
        return;
    }

    if (command === 'validate') {
        const [artifactArg = '.ecf-core'] = positional(args);
        const artifactDir = path.resolve(artifactArg);
        const report = validateCompiledArtifacts(artifactDir);
        if (!report.ok) {
            console.error(JSON.stringify(report, null, 2));
            process.exitCode = 1;
            return;
        }
        console.log(JSON.stringify(report, null, 2));
        return;
    }

    if (command === 'agent-os-preview') {
        const [artifactArg = '.ecf-core'] = positional(args);
        const report = inspectAgentOsPreview(path.resolve(artifactArg));
        if (args.includes('--json')) {
            console.log(JSON.stringify(report, null, 2));
        } else {
            console.log(`Agent OS preview import: ${report.ok ? 'ready' : 'not ready'}`);
            console.log(`Artifact dir: ${report.artifact_dir}`);
            console.log(`Boundary safe: ${report.boundary_safe}`);
            if (report.errors.length) {
                console.log('Errors:');
                for (const error of report.errors) console.log(`- ${error}`);
            }
            console.log(`Next step: ${report.next_step}`);
            console.log(`Agent OS start: ${report.next_step_url}`);
        }
        if (!report.ok) process.exitCode = 1;
        return;
    }

    if (command === 'status') {
        const [projectArg = '.'] = positional(args);
        const projectRoot = path.resolve(projectArg);
        const outDir = readFlag(args, '--out', '.ecf-core');
        const options = {
            projectRoot,
            artifactDir: path.resolve(projectRoot, outDir),
        };
        const report = args.includes('--write')
            ? writeEcfCoreResidentStatus(options)
            : buildEcfCoreResidentStatus(options);
        if (args.includes('--json') || args.includes('--write')) {
            console.log(JSON.stringify(report, null, 2));
        } else {
            console.log(`ECF Core resident: ${report.resident_state}`);
            console.log(`Artifact dir: ${report.artifact_dir}`);
            console.log(`Context pack available: ${report.context_pack.available}`);
        }
        if (!report.ok) process.exitCode = 1;
        return;
    }

    if (command === 'context-pack') {
        const [projectArg = '.'] = positional(args);
        const projectRoot = path.resolve(projectArg);
        const outDir = readFlag(args, '--out', '.ecf-core');
        const task = readFlag(args, '--task', '') || '';
        const options = {
            projectRoot,
            artifactDir: path.resolve(projectRoot, outDir),
            task,
        };
        const pack = args.includes('--write')
            ? writeEcfCoreContextPack(options)
            : buildEcfCoreContextPack(options);
        if (args.includes('--json') || args.includes('--write')) {
            console.log(JSON.stringify(pack, null, 2));
        } else {
            console.log(`ECF Core context pack: ${pack.ok ? 'ready' : 'attention required'}`);
            console.log(`Task: ${pack.task}`);
            console.log(`Sources: ${pack.summary.source_counts.allowed_sources}`);
        }
        if (!pack.ok) process.exitCode = 1;
        return;
    }

    if (command === 'worklog') {
        const [worklogCommand = 'status', projectArg = '.'] = positional(args);
        const projectRoot = path.resolve(projectArg);
        const outDir = readFlag(args, '--out', '.ecf-core');
        const options = {
            projectRoot,
            artifactDir: path.resolve(projectRoot, outDir),
            goal: readFlag(args, '--goal', '') || '',
            summary: readFlag(args, '--summary', '') || '',
            workId: readFlag(args, '--id', readFlag(args, '--work-id', null)),
            decisions: readFlag(args, '--decisions', ''),
            files: readFlag(args, '--files', ''),
            validation: readFlag(args, '--validation', ''),
            tests: readFlag(args, '--tests', ''),
            unfinished: readFlag(args, '--unfinished', ''),
            nextPrompt: readFlag(args, '--next-prompt', ''),
            commit: readFlag(args, '--commit', ''),
        };
        let result;
        if (worklogCommand === 'begin') {
            result = beginWorklog(options);
        } else if (worklogCommand === 'checkpoint') {
            result = checkpointWorklog(options);
        } else if (worklogCommand === 'finish') {
            result = finishWorklog(options);
        } else if (worklogCommand === 'status') {
            result = buildWorklogStatus(options);
        } else {
            throw new Error(`unknown worklog command: ${worklogCommand}`);
        }
        if (args.includes('--json') || worklogCommand !== 'status') {
            console.log(JSON.stringify(result, null, 2));
        } else {
            console.log(`ECF Core worklog: ${result.active ? 'active' : 'inactive'}`);
            console.log(`History events: ${result.history_count}`);
            console.log(`Checkpoints: ${result.checkpoint_count}`);
        }
        return;
    }

    if (command === 'docs-sync') {
        const [docsCommand = 'plan', projectArg = '.'] = positional(args);
        if (docsCommand !== 'plan') throw new Error(`unknown docs-sync command: ${docsCommand}`);
        const projectRoot = path.resolve(projectArg);
        const outDir = readFlag(args, '--out', '.ecf-core');
        const plan = planDocsSync({
            projectRoot,
            artifactDir: path.resolve(projectRoot, outDir),
        });
        if (args.includes('--json')) {
            console.log(JSON.stringify(plan, null, 2));
        } else {
            console.log(`ECF Core docs-sync plan: ${plan.recommended_updates.length} recommended updates`);
            console.log(`Plan: ${plan.plan_path}`);
            console.log('Auto-edit enabled: false');
        }
        return;
    }

    if (command === 'handoff') {
        const [projectArg = '.'] = positional(args);
        const projectRoot = path.resolve(projectArg);
        const outDir = readFlag(args, '--out', '.ecf-core');
        const options = {
            projectRoot,
            artifactDir: path.resolve(projectRoot, outDir),
            goal: readFlag(args, '--goal', '') || '',
        };
        const handoff = args.includes('--write')
            ? writeHandoff(options)
            : buildHandoff(options);
        if (args.includes('--json') || args.includes('--write')) {
            console.log(JSON.stringify(handoff, null, 2));
        } else {
            console.log(`ECF Core handoff: ${handoff.work.status || 'unknown'}`);
            console.log('Run with --write to persist .ecf-core/handoff.md and .ecf-core/next-session.md');
        }
        return;
    }

    if (command === 'mcp-config') {
        const [projectArg = '.'] = positional(args);
        const projectRoot = path.resolve(projectArg);
        const outDir = readFlag(args, '--out', '.ecf-core');
        const options = {
            projectRoot,
            artifactDir: path.resolve(projectRoot, outDir),
            target: readFlag(args, '--target', 'codex') || 'codex',
            codexHome: readFlag(args, '--codex-home', null),
            serverName: readFlag(args, '--server-name', null),
            installCodex: args.includes('--install-codex'),
        };
        const config = (args.includes('--write') || args.includes('--install-codex'))
            ? writeEcfCoreMcpConfig(options)
            : buildEcfCoreMcpConfig(options);
        console.log(JSON.stringify(config, null, 2));
        return;
    }

    if (command === 'serve-mcp') {
        const verifiedProjectRoot = readFlag(args, '--verified-project');
        if (verifiedProjectRoot !== null) {
            if (positional(args).length) throw new Error('verified mode does not accept an artifact directory');
            runMcpServer({ verifiedProjectRoot: path.resolve(verifiedProjectRoot) });
        } else {
            const [artifactArg = '.ecf-core'] = positional(args);
            runMcpServer({ artifactDir: path.resolve(artifactArg) });
        }
        return;
    }

    if (command === 'print-config') {
        const [projectArg = '.'] = positional(args);
        console.log(JSON.stringify(loadConfig({ projectRoot: path.resolve(projectArg) }), null, 2));
        return;
    }

    printHelp();
    process.exitCode = 1;
}

main().catch((error) => {
    console.error(`ecf-core: ${error.message}`);
    process.exitCode = 1;
});
