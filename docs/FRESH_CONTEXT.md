# Opt-in current-context compilation and retrieval

Status: implementation candidate. This is a local CLI path over the existing ECF compiler, not a replacement compiler, database, automatic refresh daemon, or production context service. Existing `ecf-core` commands and default MCP retrieval are unchanged. They do not acquire freshness guarantees merely because this module exists. The explicitly selected verified MCP reader below is default-off.

## Commands

Run from this source checkout using Node 20 or newer:

```sh
node scripts/fresh-context.cjs compile /path/to/project
node scripts/fresh-context.cjs status /path/to/project
node scripts/fresh-context.cjs read /path/to/project
```

`compile` is an explicit local write. It invokes the canonical `compileProject` in a fresh Node child with the project's `ecf.config.json`, writes ordinary ECF artifacts into a new private generation under `.ecf-core/fresh/`, checks source/configuration/compiler identity before and after, hashes the output artifacts, and atomically selects the generation only after those checks pass. The parent owns the lock and selected pointer. After the compiler child exits successfully, a second fresh child checks source/configuration and artifacts again without invoking the compiler, covering pending compiler callbacks that ran after compilation returned.

`status` checks the selected generation without returning source content. `read` additionally returns its ordinary `ecf-core.context-packet.v1` only when the checks pass. Neither command refreshes or changes the selected generation. Stale or unavailable evidence returns `context:null`; non-fresh CLI results exit 2. Compilation failures exit 1.

For **content-hashed sources**, same-size edits are detected even when timestamps are restored. Source additions/deletions, changed configuration, changed canonical source metadata, changed compiler/dependency bytes or changed Node runtime identity invalidate the corresponding fingerprint. Artifact substitution invalidates the selected generation. Old snapshots are not silently relabeled current. A dependency-injected test compiler is marked test-only and is refused by current-context retrieval.

For **metadata-only sources**, content is deliberately not hashed: a same-size content edit with the canonical modification timestamp restored can remain undetected. This includes blocked/review-only paths and policy-allowed files that the canonical filesystem adapter downgrades because they are non-text or exceed `max_file_bytes`. Their effective classification, reason, size, truncated modification time and canonical metadata fingerprint are sealed. An mtime-only change therefore invalidates their generation even when bytes stay the same. This is metadata consistency, not verification of restricted content.

## Scope and limits

The source inventory reuses Core's allow/block and directory-skip functions and the canonical filesystem adapter's `metadataDisposition` helper. Only effectively content-admitted files are content-hashed. Metadata-only sources are inventoried without opening their contents, and built-in summary adapters apply the same admission before opening a source. The local configuration is independently content-hashed because compilation consumes it even when its source disposition is restricted; the same 2 MiB per-file bound applies to it. Nested Git repositories and generated ECF directories are excluded. Limits are 10,000 encountered entries, 2 MiB per content-hashed source, and 64 MiB total content-read bytes, with a separate bounded metadata inventory. A large metadata-only file does not require content allocation. Unreadable content-admitted inputs or exceeded freshness bounds fail rather than silently becoming fresh. Output verification is bounded to 32 JSON artifacts of at most 8 MiB each.

The compiler fingerprint covers installed `src/**/*.js` and `src/**/*.json`, package metadata, a lockfile when present, and Node executable bytes plus runtime version/platform/architecture metadata. The child executes the exact captured JavaScript/JSON buffers in a new CommonJS graph and records each loaded local module's digest in the seal's `execution` field. The bootstrap is also bound to the exact bytes supplied to Node. Local code is bounded to 2,000 encountered entries, 2 MiB per file and 64 MiB total; the executable is streamed with a 256 MiB ceiling. External dependencies, native addons, dynamic imports and other source file types fail closed in this opt-in path. The current canonical compiler has no external package dependencies. Node builtins are bound through the executable/runtime identity; dynamically linked OS libraries are not inventoried. This is not a signed package or operating-system attestation.

The child inherits neither parent Node flags nor `NODE_OPTIONS`/`NODE_PATH`. Configuration, policy, filesystem disposition and both source snapshots use the same fresh graph as compilation. `inspectFresh` also runs in a fresh child so a parent's cached policy/configuration cannot authorize retrieval. Compiler/runtime identity is checked again after the child finishes. Pre-isolation seals require an explicit refresh.

Only the canonical built-in local compilation path is supported; custom/external adapters, alternate config paths, distributed filesystems, and hostile concurrent filesystem writers are not qualified. The buffered module loader establishes execution identity, not a sandbox for malicious compiler code or its builtins.

Every compiler, verification and inspection worker starts with the [Node permission model](https://nodejs.org/api/permissions.html) enabled and no permission to create child processes or worker threads. This enforces the canonical compiler's single-process lifecycle on Windows and POSIX, including detached processes and inherited stdio. Filesystem access remains available to the canonical compiler; this is not a filesystem sandbox. The bootstrap checks the restriction before loading compiler modules, records `execution.lifecycle: "node_permission_no_descendants"`, and refuses unsupported runtimes rather than falling back to unrestricted execution. Node 20 uses the experimental permission flag; newer supported runtimes use its stable spelling. A denied capability fails with `compiler_capability_denied`. Native addons and other unsupported execution paths remain disallowed. Like Node's permission model, this boundary is for trusted code and does not contain a malicious replacement compiler.

The seal detects local consistency changes, not authorship or malicious replacement by an actor controlling the entire private workspace. File/directory checks reduce accidental aliasing; they are not a sandbox or a defense against a privileged concurrent local attacker. Source reads are bounded observations rather than a filesystem-wide transactional snapshot. A process can change the source after a successful read. Downstream execution must retain its own current policy/authority checks.

Generations may contain private source previews and local paths. Keep `.ecf-core` ignored and never publish it or its output by default. The status result is not certification, agent completion, context consumption, deployment, or payment proof. `host_consumption_verified` remains false. POSIX creation modes are owner-only where supported; Windows ACL equivalence is not claimed.

## Recovery

Only one cooperating refresh may own `.ecf-core/fresh/.lock`. A conflicting refresh fails instead of stealing it. Each refresh records a random owner token and checks it and the original directory identity before promotion or lock removal. A replaced lock is left untouched. Normal failure removes only the attempt's unselected generation, after its child has closed; the existing selected pointer remains unchanged.

`compileFresh(root, { timeoutMs, signal })` accepts an integer deadline of 1-300,000 ms (default 30,000 ms) across the compiler and verification child stages, and an optional standard `AbortSignal`. Timeout/cancellation forcibly terminates the child and waits for `close` before cleanup. Denying descendant creation prevents inherited descendant pipes from keeping `close` pending and prevents detached descendants from writing after cleanup. This is an enforced single-process contract, not general process-tree termination. Child stdout is limited to 4 MiB and stderr to 64 KiB; diagnostics are discarded and failures return bounded error codes. Synchronous inspection has a 30-second child timeout and 10 MiB buffer limit. Local fingerprinting and cleanup also take bounded work outside the child timer.

Killing the parent or machine can still leave a lock and an unselected partial generation; inspect process and artifact state before an owner removes a stale lock. There is no stale-lock stealing, automatic last-good fallback, or universal power-loss durability guarantee.

## Verification and next integration

### Opt-in verified MCP consumption

After an explicit successful fresh compile, a source-checkout MCP process can be started manually with:

```sh
node bin/ecf-core.js serve-mcp --verified-project /path/to/project
```

The equivalent source API is `runMcpServer({ verifiedProjectRoot: projectRoot })`, or `callMcpTool({ verifiedProjectRoot: projectRoot, name, args })`. This option selects only the canonical project's `.ecf-core/fresh/current.json`; an artifact-directory override is refused. No configuration generator or installed host entry is changed. Starting or querying the reader never compiles, refreshes, installs, writes Memory, or activates a host integration.

Only `search_context`, `route_query`, `get_source`, `get_policy`, and `get_manifest` are listed/accepted in this mode. Resident status, context-pack, preview and work-memory tools independently read other files and are deliberately unavailable. Default artifact-directory serving keeps its existing tool surface and content-byte cache; it has no source-freshness or verified-consumption claim.

Each verified call captures a bounded compiler/reader graph and executes read, ranking/routing, and receipt construction from those exact buffers in a private CommonJS graph **inside the MCP process**, without a parent `require` cache fallback or process-global loader changes. A fresh restricted inspection worker checks the selected generation before and after response computation. The reader hashes every one of the seven consumed JSON artifact buffers before parsing it and bypasses the ordinary artifact cache. Both inspections must agree on generation, seal hash, snapshot/source/configuration/compiler digests, and the complete artifact inventory; the reader graph digest must equal that compiler digest. Any unavailable evidence or detected drift discards the entire response with a JSON-RPC error, without last-good fallback. An explicit refresh can supply a new generation on the next request in the same MCP process.

The `verified_consumption` receipt binds those identities, the exact consumed artifact hashes, captured reader module hashes, request/response SHA-256 digests, reader PID, and a distinct request ID. `request_verified: true` describes this request's bounded read/response interval only; `host_consumption_verified` remains **false**, both in receipts and generation seals. Response hashing covers the result object before adding the receipt. This is source/API and disposable-process test evidence, not proof that an installed IDE/agent used the response. It grants no downstream authority and makes no sandbox claim. Another process may change files after the final observation; hostile filesystem writers and restricted same-metadata content edits retain the limits above.

Verified argument JSON is limited to 64 KiB and the result before its receipt to 8 MiB. Each consumed artifact retains the 8 MiB bound, and both isolated inspections retain their source/inventory, 30-second timeout and output bounds. This does not add a general-purpose stdio transport or machine-attestation boundary.

```sh
node --test tests/freshness-snapshot.test.js tests/freshness-compile.test.js tests/freshness-review.test.js tests/freshness-disposition.test.js tests/freshness-isolation.test.js
node --test tests/mcp-verified.test.js
npm test
npm run check
npm run docs:check
```

The disposition regressions compare real canonical records against snapshot metadata hashes, exercise binary/oversized mtime-only stale-read refusal, forbid metadata-only content opens through the real compiler and every built-in summary adapter, cover sparse sources above the content-read ceiling, retain post-read growth checks, enforce the configuration boundary, and explicitly test the restored-timestamp limitation. Full current-head CI and independent review are required before merge; earlier local source-subset test counts are historical, not current-head execution evidence.

`tests/freshness-isolation.test.js` addresses issue #46 using disposable copies of the real compiler: parent loads A, disk changes to compiler/dependency B, and refresh executes B with bound bytes. It covers JS and JSON dependencies, source/config/compiler drift, pending child work, failure cleanup, timeout/cancellation, replacement locks, output bounds and preload exclusion. Lifecycle probes exercise actual Node process APIs for inherited-pipe and detached descendants, alternate spawning APIs, worker threads, verifier/inspection dependencies and bootstrap refusal without permissions. They assert bounded termination, no descendant writes, failed-generation cleanup and pointer/replacement-lock preservation. The same tests run locally on Windows and in the Node 20/22/24 POSIX CI matrix; CI evidence must name its literal checkout SHA, including a PR merge ref when applicable. Filesystem-spy assertions for canonical source admission and marker read counts still invoke the real `compileProject` locally; parent spies do not claim to observe a child's reads.

Compiler isolation and the opt-in verified reader are implementation candidates requiring exact-head CI and review. `tests/mcp-verified.test.js` exercises one persistent MCP reader across requests, source/configuration/artifact drift including same-size restored timestamps, a primed ordinary artifact cache, explicit refresh, generation changes during response computation, substitution restored before final inspection, and parent-cached reader/ranking A versus captured B. These tests qualify the source implementation's consumption interval; installed host verification remains pending. Do not generalize the claim to default MCP serving or unsupported tools. Memory may consume the bounded status/generation reference through its existing explicit evidence path; this patch does not silently inject or write Memory context.
