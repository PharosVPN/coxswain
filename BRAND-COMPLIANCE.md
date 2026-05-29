# Brand Compliance

**bodaay Branding Guide Version:** 0.2.0
**Last Reviewed:** 2026-05-18
**Surface:** coxswain admin Web UI (`web/`)

The coxswain admin UI implements the bodaay design system: dark + light themes,
exact token values, self-hosted Cairo, the 4dp grid, teal-anchored components,
WCAG AA contrast, focus-visible rings, and reduced-motion support.

## Deviations

| # | Guide | Deviation | Justification |
|---|-------|-----------|---------------|
| 1 | 09 — Iconography | Uses a small set of custom inline SVG icons (theme-toggle sun/moon) instead of the Material Symbols font. | The UI needs only a couple of icons; bundling a full icon font is disproportionate. Custom icons follow §9.6 (24×24 viewBox, `currentColor`). Will adopt Material Symbols if the icon set grows. |
| 2 | 02 / 06 / 12 — surfaces | Dark card surface uses `--c-gray-900` (`#1F2528`). | The guide is internally inconsistent: §02.1 and the §10 contrast table use `#262E32` (`--c-gray-850`); §06.2 and §12.4 use `#1F2528` (`--c-gray-900`). coxswain follows the implementation guides (§12 Web gives `.card { background: var(--c-gray-900) }` literally; §06 agrees). Flagged for the guide maintainers to reconcile. |
