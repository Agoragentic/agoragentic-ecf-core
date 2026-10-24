# ECF Core CLI Reference

The `ecf-core` CLI compiles and serves local/self-hosted context-governance artifacts. It does not deploy agents, provision hosted runtime, fund wallets, publish marketplace listings, execute x402 payments, or expose private Full ECF internals.

```bash
ecf-core --help
```

Project arguments default to `.`. Artifact-directory arguments default to `.ecf-core`. `--out` is resolved relative to the selected project, while a `--config` path is resolved from the shell's current working directory.

## Compile And Evaluate

| Command | Purpose | Options and output |
|---|---|---|
| `ecf-core init [project]` | Write a starter `ecf.config.json`. | `--force` overwrites an existing config; otherwise the command fails closed. |
| `ecf-core compile [project]` | Compile allowed, blocked, review-required, evidence, index, router, and manifest artifacts. | `--config <path>`, `--out <dir>`, `--agent-os`, `--json`. Human output reports source counts; JSON output prints the manifest. |
| `ecf-core eval [project]` | Compile and write deterministic JSON/Markdown evaluation reports. | `--config <path>`, `--out <dir>`, `--grounding`, `--json`. |
| `ecf-core validate [artifact-dir]` | Validate required artifacts, schema versions, and expected shapes. | Prints a JSON report and exits nonzero when `ok` is false. |
| `ecf-core agent-os-preview [artifact-dir]` | Inspect a compiled Agent OS preview/import handoff. | `--json`; exits nonzero when the handoff is not ready or boundary-safe. This does not deploy. |
| `ecf-core print-config [project]` | Print the resolved local config as JSON for diagnostics. | Implemented diagnostic command; currently not listed in `--help`. |

`eval` writes reports even when the packet-readiness verdict needs review or the grounding report warns. Treat the report verdict and findings as evidence; the command does not map every review/warn result to a nonzero exit code.

## Resident Context And Work Memory

| Command | Purpose | Options and output |
|---|---|---|
| `ecf-core status [project]` | Print or write local resident-artifact status. | `--out`, `--write`, `--json`; exits `1` when `ok` is false. |
| `ecf-core context-pack [project]` | Print or write a bounded local IDE/session context pack. | `--out`, `--task`, `--write`, `--json`; exits `1` when `ok` is false. |
| `ecf-core worklog begin [project]` | Start local session continuity. | Requires `--goal`; supports `--out`. |
| `ecf-core worklog checkpoint [project]` | Record progress for an active worklog. | Requires `--summary`; supports the work-memory fields below. |
| `ecf-core worklog finish [project]` | Close the active worklog and record validation/handoff facts. | Requires `--summary`; commonly uses `--commit` and `--tests`. |
| `ecf-core worklog status [project]` | Print active/history/checkpoint status. | `--out`, `--json`. |
| `ecf-core docs-sync plan [project]` | Build a local docs-update plan without auto-editing documentation. | `--out`, `--json`. |
| `ecf-core handoff [project]` | Build a next-session handoff; `--write` persists it under `.ecf-core`. | `--out`, `--goal`, `--write`, `--json`. |

Work-memory fields accepted where relevant are `--goal`, `--summary`, `--id`/`--work-id`, `--decisions`, `--files`, `--validation`, `--tests`, `--unfinished`, `--next-prompt`, and `--commit`.

## Local MCP

| Command | Purpose | Options and output |
|---|---|---|
| `ecf-core mcp-config --target codex [project]` | Preview a Codex MCP entry, write workspace guidance, or install the entry into a selected Codex home. | `--out`, `--target`, `--codex-home`, `--server-name`, `--write`, `--install-codex`; JSON output. Only `codex` is supported. |
| `ecf-core serve-mcp [artifact-dir]` | Serve compiled local artifacts through a stdio MCP surface. | Compile first. Stdout is reserved for protocol messages. |
| `ecf-core serve-mcp --verified-project /path/to/project` | Opt in to per-request verified generation reads. | Never compile/refresh or alter installed host configuration. See [fresh-context limits](./FRESH_CONTEXT.md#opt-in-verified-mcp-consumption). |

MCP tool errors are returned per request as JSON-RPC errors; they are not CLI process exit codes. Restart the MCP client after changing an installed configuration.

## Version

`ecf-core version`, `ecf-core --version`, and `ecf-core -v` print the package version.

## Exit Behavior

- Help, version, and successfully completed commands exit `0`.
- `validate`, `agent-os-preview`, `status`, and `context-pack` set exit code `1` when their returned contract is not ready.
- An unknown command prints help and exits `1`.
- Invalid JSON/configuration, missing flag values, an existing init target without `--force`, missing worklog requirements, and other thrown errors print `ecf-core: <message>` to stderr and exit `1`.
- Evaluation verdicts such as review, and grounding warning states, must be read from the generated report; they do not necessarily change the process exit code.

See [Troubleshooting](./TROUBLESHOOTING.md), [Install](./INSTALL.md), and [Local MCP Server](./MCP_SERVER.md) for common workflows.
