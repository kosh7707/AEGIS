# AEGIS — Repository-local Agent Instructions

## Documentation

- The current documentation lives in this repository under `docs/`.
- Start with `README.md`, then `docs/README.md` and `docs/overview.md`.
- Read `docs/runbook.md` before installing, running, testing or restoring data.
- Read `docs/invariants.md` and the relevant `docs/contracts/*.md` before changing service boundaries.
- Use `docs/limitations.md` to distinguish supported behavior, experiments and unverified paths.
- Source code, schemas and regression tests determine current behavior. Update the matching local documentation with interface changes.
- No separate documentation checkout, wiki server, session-history system, lane router or work-request workflow is required.

## Changes

- Follow the user's task scope. Inspect relevant code across service boundaries when needed.
- Keep changes small and preserve API fields, states, error codes and evidence semantics unless their change is explicitly requested.
- Write a bounded plan before cleanup/refactoring; run relevant existing regression tests before behavior-affecting edits.
- Reuse existing code and add no dependencies without an explicit request.
- Keep current operating guidance in `docs/`; do not recreate session/WR archives or duplicate API schemas in prose.
- Keep secrets, real `.env` files, uploads, DBs, virtual environments and local tool state such as `.omx/` and `.omc/` out of commits.

## Verification

- Run the smallest relevant service tests and typechecks, then inspect the output.
- `npm test` invokes all installed service suites; inspect skipped suites and optional tool/data tests.
- Check changed documentation links and code/schema references; run `git diff --check` before committing.
- Report checks actually run and any remaining limits. Mock output, open ports and process liveness do not establish real analysis readiness.
- Commit using an intent-first message with relevant native Git trailers (`Tested:`, `Not-tested:`, `Constraint:`, `Confidence:`).

## Optional tools

- `.mcp.json` configures `log-analyzer` for runtime log diagnosis and `stitch` for its design tooling.
- Tool availability depends on the current client and local installation. Read Markdown and source directly when a tool is unavailable.
- The log analyzer's interpreter is `tools/log-analyzer/.venv/bin/python`; it reads `logs/`. It is not needed to run or read the product documentation.
