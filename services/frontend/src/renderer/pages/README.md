# Renderer page directory contract

This directory is mid-refactor toward a page-per-directory layout.

## Current contract

Each non-trivial page should own a directory with this shape:

- `PageName/PageName.tsx` — page entry component
- `PageName/PageName.css` — page-local styles
- `PageName/PageName.test.tsx` — regression tests for page behavior
- `PageName/components/*` — page-local subcomponents
- `PageName/*Model.ts` or similar helpers — page-local view-model/data helpers

Follow the existing explicit import pattern from `src/renderer/App.tsx`:

- `./pages/DashboardPage/DashboardPage`
- `./pages/OverviewPage/OverviewPage`
- `./pages/ProjectSettingsPage/ProjectSettingsPage`

Avoid widening shared ownership unless a helper is reused by multiple pages.

## Integration checklist for the remaining refactors

### AnalysisHistoryPage

- Add a page-local regression test before or with the move (no current `AnalysisHistoryPage` test file exists)
- Move `AnalysisHistoryPage.tsx` to `AnalysisHistoryPage/AnalysisHistoryPage.tsx`
- Move `AnalysisHistoryPage.css` to `AnalysisHistoryPage/AnalysisHistoryPage.css`
- Rewrite `../` imports to `../../` from the new folder depth
- Prefer a temporary compatibility stub at `pages/AnalysisHistoryPage.tsx` so `App.tsx` can stay stable until final integration

Audit note: the current file has **6** relative imports that will need depth updates after the move.

### ApprovalsPage

- Move `ApprovalsPage.tsx` to `ApprovalsPage/ApprovalsPage.tsx`
- Move `ApprovalsPage.css` to `ApprovalsPage/ApprovalsPage.css`
- Move `ApprovalsPage.test.tsx` to `ApprovalsPage/ApprovalsPage.test.tsx`
- Rewrite page `../` imports to `../../` from the new folder depth
- Rewrite test imports/mocks (`./ApprovalsPage`, `../api/*`, `../contexts/*`) for the new folder depth
- Prefer a temporary compatibility stub at `pages/ApprovalsPage.tsx` so `App.tsx` can stay stable until final integration

Audit note: the current page file has **7** relative imports, and the current test file has **4** relative import/mock paths that will need depth updates after the move.

### FilesPage

- Move `FilesPage.tsx` to `FilesPage/FilesPage.tsx`
- Move `FilesPage.css` to `FilesPage/FilesPage.css`
- Add page-local regression tests before or with the move
- Rewrite `../` imports to `../../` from the new folder depth
- Reconcile the route import in `App.tsx` during final integration

Audit note: the current file has **16** relative imports that will need depth updates after the move.

### VulnerabilitiesPage

- Move `VulnerabilitiesPage.tsx` to `VulnerabilitiesPage/VulnerabilitiesPage.tsx`
- Move `VulnerabilitiesPage.css` to `VulnerabilitiesPage/VulnerabilitiesPage.css`
- Add page-local regression tests before or with the move
- Rewrite `../` imports to `../../` from the new folder depth
- Reconcile the route import in `App.tsx` during final integration

Audit note: the current file has **10** relative imports that will need depth updates after the move.

## Shared-file merge risk

`src/renderer/App.tsx` is the only current shared import hotspot for the remaining page-per-directory moves:

- `import { AnalysisHistoryPage } from "./pages/AnalysisHistoryPage";`
- `import { ApprovalsPage } from "./pages/ApprovalsPage";`
- `import { FilesPage } from "./pages/FilesPage";`
- `import { VulnerabilitiesPage } from "./pages/VulnerabilitiesPage";`

To keep worker ownership narrow, page-local moves should happen inside each page folder first. When possible, leave a thin compatibility stub (`export { PageName } from "./PageName/PageName";`) in the flat page file so `App.tsx` does not need to change during each worker slice. Any remaining `App.tsx` import updates should be applied once during integration.

## Verification baseline

Use these checks after each page move:

- `npx tsc --noEmit --pretty false --project services/frontend/tsconfig.json`
- `npm --workspace services/frontend run test -- src/renderer/pages/<PageName>/<PageName>.test.tsx`
- `npm --workspace services/frontend run build`

There is currently no dedicated frontend lint script or ESLint config in this workspace, so lint verification must be added separately if linting becomes a release gate.
