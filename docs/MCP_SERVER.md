# ECF Core Local MCP Server

ECF Core can serve compiled `.ecf-core` artifacts over a local stdio MCP tool surface.

This is for active context serving inside IDEs and agent clients. It is read-only by default and does not call Agoragentic Cloud.

## Start

First compile artifacts:

```bash
ecf-core compile . --agent-os
ecf-core eval . --grounding
```

Then start the MCP server:

```bash
ecf-core serve-mcp .ecf-core
```

Configure that command as a local stdio MCP server in the IDE or agent client.

### Optional verified generation reader (source candidate)

Default serving above retains the existing content-byte cache without source-freshness checks. To opt in explicitly after compiling a fresh generation with `node scripts/fresh-context.cjs compile /path/to/project`, use:

```bash
node bin/ecf-core.js serve-mcp --verified-project /path/to/project
```

This read-only mode checks source/configuration/compiler identity and the selected generation on every tool call, hashes the exact consumed artifact buffers, computes the response using captured reader modules in the MCP process, and verifies the generation again before returning. Stale or unavailable evidence returns an error without cached context. It never compiles or refreshes automatically. An artifact-directory argument cannot be combined with this flag.

Only search, route, source, policy and manifest tools are exposed. Other tools remain available through default serving but are not qualified for verified generation consumption. The per-request `verified_consumption` receipt is source-reader evidence; `host_consumption_verified` remains false. No installed host verification, runtime configuration change, automatic activation, or sandboxing is claimed. See [FRESH_CONTEXT.md](./FRESH_CONTEXT.md#opt-in-verified-mcp-consumption) for digest bindings, limits and unsupported cases.

For Codex, generate a workspace-specific resident MCP config:

```bash
ecf-core mcp-config --target codex . --write
```

To intentionally install it into `CODEX_HOME/config.toml` or `~/.codex/config.toml`, run:

```bash
ecf-core mcp-config --target codex . --write --install-codex
```

Restart Codex after installation. Codex loads MCP servers at startup. See [`CODEX_MCP.md`](./CODEX_MCP.md).

### Claude Code

Use the generated command as a stdio MCP server. A workspace config should look like:

```json
{
  "mcpServers": {
    "ecf-core": {
      "command": "node",
      "args": ["/absolute/path/to/node_modules/agoragentic-ecf-core/bin/ecf-core.js", "serve-mcp", "/absolute/path/to/project/.ecf-core"]
    }
  }
}
```

If `ecf-core` is installed globally and available on `PATH`, this shorter form is equivalent:

```json
{
  "mcpServers": {
    "ecf-core": {
      "command": "ecf-core",
      "args": ["serve-mcp", "/absolute/path/to/project/.ecf-core"]
    }
  }
}
```

### Cursor

Add the same stdio server to the workspace MCP configuration:

```json
{
  "mcpServers": {
    "ecf-core": {
      "command": "ecf-core",
      "args": ["serve-mcp", "/absolute/path/to/project/.ecf-core"]
    }
  }
}
```

## Tools

| Tool | Purpose |
| --- | --- |
| `ecf_core.search_context` | Rank compiled context sources for a query with deterministic semantic-lite scoring. |
| `ecf_core.route_query` | Route a question to exact evidence, policy, code symbols, source-manifest facts, deterministic stats, or semantic summary. |
| `ecf_core.get_source` | Read one compiled source record by `source_id` or `path`. |
| `ecf_core.get_policy` | Return `policy-summary.json`. |
| `ecf_core.get_manifest` | Return `manifest.json` and artifact counts. |
| `ecf_core.agent_os_preview_check` | Run the local Agent OS preview-import readiness check. |
| `ecf_core.status` | Return local resident status, artifact health, and authority boundary. |
| `ecf_core.context_pack` | Return an IDE/Codex-friendly compiled context summary without raw source content. |
| `ecf_core.worklog_status` | Return local worklog status for next-session continuity. |
| `ecf_core.handoff` | Return the local next-session handoff without writing files. |
| `ecf_core.work_memory` | Return local worklog, docs-sync, handoff, and latest-summary artifacts. |

## Boundary

Default MCP serving reads the compiled local artifacts below. The opt-in verified reader additionally checks bounded source/configuration/compiler identity as described above.

- `context-packet.json`
- `source-map.json`
- `source-manifest.json`
- `policy-summary.json`
- `code-index.json`
- `context-router.json`
- `manifest.json`
- Agent OS preview/import files when requested by the readiness check
- resident worklog, docs-sync, and handoff artifacts when requested by work-memory tools

It does not:

- deploy agents
- approve actions
- spend funds
- run wallet or x402 settlement
- route marketplace calls
- provision hosted Agent OS runtime
- include Full ECF private internals
- call remote model, vector, or embedding services

## Usage Pattern

Use MCP when a new IDE chat should query ECF Core without manually pasting generated files.

At the start of work, the assistant should disclose whether it is using:

- ECF Core MCP tools
- generated `.ecf-core/*` artifacts
- resident `.ecf-core/worklog/*` and `.ecf-core/handoff.md` artifacts
- direct repo reads
- none of them

ECF Core MCP results are guidance and provenance. For code changes, direct source-file inspection remains the source of truth.

## Default artifact cache freshness

Each tool call reads and hashes the seven compiled JSON artifacts listed above.
Unchanged bytes reuse the parsed/indexed cache; changed bytes invalidate it even
when file size and modification time are preserved. On a cache miss, parsing uses
the same captured bytes as the hashes. Read and JSON errors are surfaced rather
than falling back to a previous cached result.

This adds file reads and hashing per request; it does not establish an atomic
multi-file generation, authenticate a compiler seal, prove source/config
freshness, or qualify live host consumption. Those broader generation-reader
requirements remain tracked in issue #46. Resident/work-memory and preview tools
retain their separate read paths and validation boundaries.
