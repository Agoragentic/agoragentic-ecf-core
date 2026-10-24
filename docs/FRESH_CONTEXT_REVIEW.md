# Fresh-context independent-review corrections

PR #45 now applies directory-skip rules only to directories, matching `walkFiles`. Allowed regular files such as `temp-context.js` are included and content changes invalidate the generation.

Snapshots also seal a bounded `restricted_inventory` of path, policy classification/reason, size and truncated modification time for blocked and review-required regular files. These are the metadata fields used by the canonical filesystem adapter; their content is neither opened nor hashed. Adding, removing, resizing or changing the classification of such a source invalidates the old canonical artifacts. Generated directories and directories skipped by the canonical walker remain excluded. The 10,000-entry bound and a 1 MiB serialized inventory ceiling apply before sealing. This is not a fingerprint of restricted file contents: same-metadata blocked-content changes are deliberately not detectable, because the canonical restricted record does not contain that content either.

Existing snapshots have no restricted inventory and must be explicitly refreshed. No automatic migration or default MCP activation is added. The source CLI continues to report fresh with exit 0 and stale/unknown with exit 2; returned stale context is null.

`tests/freshness-review.test.js` adds four snapshot regressions, canonical walker parity, two real-compiler regressions, and a source CLI end-to-end test. The local source-subset run exercised the four snapshot cases using the unchanged policy blob `9925b908f3d0222988c4d1473687cd96bcd8a79d`; canonical compiler/CLI verification belongs to current-head CI, not that local result.

## Compiler isolation candidate — issue #46

The new isolation regression reproduces the prior defect on disposable source copies: loading configuration A (`max_calls: 10`), editing disk to B (`23`), then refreshing used to emit `10` with `state: fresh`. Refresh now runs the real compiler from captured bytes in a fresh child graph and emits B. Source/configuration and artifact stability are checked again after the child exits, including delayed child callbacks. The seal binds loaded JS/JSON modules, the worker bootstrap and Node executable/runtime identity. Inspection uses a fresh graph too.

The parent retains generation selection and token-bound lock ownership. Failed, timed-out or cancelled children must close before cleanup; their partial generation is removed and the prior pointer is preserved. Invalid cancellation objects are rejected before spawning. Output bounds, dependency rejection, inherited-preload exclusion and replacement-lock preservation have dedicated regressions. Existing CLI exit 0/2, artifact substitution and source-disposition checks remain required.

Parent review of `bbfc915` found that direct-PID termination alone did not cover descendants: inherited pipes could delay `close`, and detached children could write after cleanup. Disposable compiler probes reproduced both on Windows; the canonical compiler itself does not spawn descendants. Workers now enforce Node's permission model before loading compiler modules, denying process/thread creation on both Windows and POSIX. Regressions exercise inherited/ignored stdio, detached writers, alternate spawning APIs, timeout/cancellation, bootstrap refusal, and verification/inspection workers. This qualifies the supported single-process lifecycle, not a general subprocess-tree manager or malicious-code sandbox.

CI associated with `bbfc915` actually checked merge ref `098f3b5817d491494a0c405af14537fcc129a628`, not detached `bbfc915f11c7828cbea30a1e3607cc3b5a1e7333`. JavaScript source/tests were identical; the .NET project file differed. Report literal checkout refs separately from PR head metadata for subsequent validation.

The filesystem instrumentation tests invoke the canonical compiler directly as well as checking isolated output, preserving meaningful admission/read-count assertions across the new process boundary. Internal compiler behavior is not replaced with artifact mocks in the isolation tests.

See [FRESH_CONTEXT.md](FRESH_CONTEXT.md) for execution limits and recovery behavior. This remains an opt-in implementation candidate. Review and current-head CI are still required; no automatic MCP activation, host-consumption proof, OS sandbox, signed package attestation, publication or deployment is introduced.
