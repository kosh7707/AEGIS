# AEGIS local bootstrap router

> Canonical agent-facing documentation lives in the sibling repo **`aegis-static-wiki`**.
> Path conventions in this file:
> - `wiki/...` — path inside the `aegis-static-wiki` repo
> - `services/...`, `docs/...`, `scripts/...` — path inside the AEGIS repo (this repo)
>
> **Local bootstrap set**
> 1. `docs/AEGIS.md` — route from the AEGIS repo into the right wiki surface
> 2. `docs/mcp.md` — explain the local MCPs available at startup

## Start here

1. Read **this file** for local bootstrap routing.
2. Read `docs/mcp.md` for the locally available MCP surfaces.
3. Enter the canonical wiki at `wiki/system/index.md` (inside the `aegis-static-wiki` repo).
4. Continue to `wiki/canon/charter/aegis.md`.
5. If a lane is explicitly declared, continue to `wiki/canon/handoff/{lane}/readme.md`.
6. Use `wiki/canon/work-requests/` for new canonical WR handling.
7. Legacy WRs under the AEGIS repo `docs/work-requests/` directory are archive-only and out-of-scope for WR MCP runtime behavior.

## Lane bootstrap contract

Use this file as the deterministic router when the user explicitly declares a lane, for example:

- `너는 S1이야`
- `너는 S2야`
- `이번엔 S4로 진행해`

Routing rules:

1. Read this file first.
2. Match only explicit lane tokens: `S1`, `S1-QA`, `S2`, `S3`, `S4`, `S5`, `S6`, `S7`.
3. If multiple lane tokens appear in one prompt, **the last explicit lane token wins**.
4. If the same lane is declared repeatedly, suppress duplicate bootstrap work.
5. If the lane changes, reroute cleanly to the new lane.
6. If no lane is declared, do not force a lane bootstrap.

### Machine-readable lane map

The JSON map below is **authoritative**. All `wiki_handoff` / `design_system_ref` paths are `aegis-static-wiki` repo-root relative. All `owned_code_paths` are AEGIS repo-root relative. The following human-readable table is an intentional mirror for quick inspection.

<!-- LANE_BOOTSTRAP_MAP:START -->
```json
{
  "precedence_rule": "last-token-wins",
  "idempotent_on_same_lane": true,
  "path_conventions": {
    "wiki_handoff": "aegis-static-wiki repo root",
    "design_system_ref": "aegis-static-wiki repo root",
    "owned_code_paths": "AEGIS repo root"
  },
  "lanes": {
    "S1": {
      "wiki_handoff": "wiki/canon/handoff/s1/readme.md",
      "design_system_ref": "wiki/canon/design-system/readme.md",
      "owned_code_paths": [
        "services/frontend"
      ]
    },
    "S1-QA": {
      "wiki_handoff": "wiki/canon/handoff/s1/qa-guide.md",
      "design_system_ref": "wiki/canon/design-system/readme.md",
      "owned_code_paths": [],
      "notes": "Do not read frontend source for QA bootstrap; use browser/Playwright verification only."
    },
    "S2": {
      "wiki_handoff": "wiki/canon/handoff/s2/readme.md",
      "owned_code_paths": [
        "services/backend",
        "services/shared",
        "scripts"
      ]
    },
    "S3": {
      "wiki_handoff": "wiki/canon/handoff/s3/readme.md",
      "owned_code_paths": [
        "services/analysis-agent",
        "services/build-agent",
        "services/shared-py"
      ]
    },
    "S4": {
      "wiki_handoff": "wiki/canon/handoff/s4/readme.md",
      "owned_code_paths": [
        "services/sast-runner"
      ]
    },
    "S5": {
      "wiki_handoff": "wiki/canon/handoff/s5/readme.md",
      "owned_code_paths": [
        "services/knowledge-base"
      ]
    },
    "S6": {
      "wiki_handoff": "wiki/canon/handoff/s6/readme.md",
      "owned_code_paths": [
        "services/adapter",
        "services/ecu-simulator"
      ]
    },
    "S7": {
      "wiki_handoff": "wiki/canon/handoff/s7/readme.md",
      "owned_code_paths": [
        "services/llm-gateway"
      ]
    }
  }
}
```
<!-- LANE_BOOTSTRAP_MAP:END -->

### Human-readable lane map

| Lane | Wiki handoff | Design system ref | Owned code paths |
|---|---|---|---|
| `S1` | `wiki/canon/handoff/s1/readme.md` | `wiki/canon/design-system/readme.md` | `services/frontend` |
| `S1-QA` | `wiki/canon/handoff/s1/qa-guide.md` | `wiki/canon/design-system/readme.md` | none — browser/Playwright verification only |
| `S2` | `wiki/canon/handoff/s2/readme.md` | — | `services/backend`, `services/shared`, `scripts` |
| `S3` | `wiki/canon/handoff/s3/readme.md` | — | `services/analysis-agent`, `services/build-agent`, `services/shared-py` |
| `S4` | `wiki/canon/handoff/s4/readme.md` | — | `services/sast-runner` |
| `S5` | `wiki/canon/handoff/s5/readme.md` | — | `services/knowledge-base` |
| `S6` | `wiki/canon/handoff/s6/readme.md` | — | `services/adapter`, `services/ecu-simulator` |
| `S7` | `wiki/canon/handoff/s7/readme.md` | — | `services/llm-gateway` |

## Canonical paths

All paths below are inside the `aegis-static-wiki` repo unless noted otherwise.

- Wiki index: `wiki/system/index.md`
- Platform charter: `wiki/canon/charter/aegis.md`
- Migration map: `wiki/system/migration-map.md`
- Session history policy: `wiki/system/session-history-policy.md`
- Test evidence policy: `wiki/system/test-evidence-policy.md`
- Lane handoff: `wiki/canon/handoff/{lane}/readme.md`
- Lane roadmap: `wiki/canon/roadmap/{lane}-roadmap.md`
- API contracts: `wiki/canon/api/*.md`
- Specs: `wiki/canon/specs/*.md`
- Design system canonical: `wiki/canon/design-system/**`
- Feedback archive: `wiki/canon/feedback/**`
- Work requests: `wiki/canon/work-requests/*.md`

## What this file is for

Use `docs/AEGIS.md` when you need to answer:

- what should I read first from the AEGIS repo?
- where is the canonical wiki?
- how do I map a lane declaration to the right handoff page?
- what code surface belongs to that lane?
- where is the design system canonical reference?

Do **not** use this file as a deep knowledge base for specs, APIs, handoff history, or policy detail. Those remain in the wiki.

## Local residual surface in `docs/**` (AEGIS repo)

Only these paths remain local after the cutover:

- `docs/AEGIS.md`
- `docs/mcp.md`

Everything else under the previous `docs/**` tree is canonicalized in the `aegis-static-wiki` repo.

## Legacy path resolution

Some repo comments, READMEs, or historical notes may still mention old local paths such as `docs/api/...`, `docs/specs/...`, `docs/sN-handoff/...`, or `docs/외부피드백/...`.

Treat those as legacy references and resolve them through:

- `wiki/system/migration-map.md` (inside the `aegis-static-wiki` repo)

That file is the authoritative old-path → wiki-path ledger for the cutover.

## Work-request rule

Work requests are now read and maintained through the canonical wiki surface:

- `wiki/canon/work-requests/` (inside the `aegis-static-wiki` repo)

Legacy archived WR markdown may exist under:

- `docs/work-requests/` (inside the AEGIS repo)

Those archived docs WRs are reference-only and out of scope for WR MCP runtime behavior.

## Cutover note

- Durable documentation maintenance now happens in the wiki first.
- Sessions launched from the AEGIS repo should use the local `aegis-static-wiki` MCP server defined in `.mcp.json`.
- Tool availability and MCP usage guidance live in `docs/mcp.md`.
- This file exists only to give a deterministic bootstrap path from the AEGIS repo into the wiki-managed surface.
