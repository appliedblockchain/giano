# Version deferrals

A pin held back from its latest qualifying release (openspec: `dependency-freshness`). The weekly stale-pins run
(`.github/workflows/stale-pins.yml`) reports a pin as stale when a newer stable release is at least 7 days old, unless a
row below holds it. A row past its review date holds nothing, so the pin is reported again and the row is revisited.

- **Name:** the npm package, the action's `owner/repo`, or the tool name in `scripts/check-stale-pins.mjs` (`TOOLS`).
- **Held version:** the exact version pinned (`3.24.4`), or a major (`4.x`). A major still expects its newest release.
  Our own `@appliedblockchain/*` packages are compared with the workspace, which knows only their current version, so
  hold them at an exact version.
- **Owner:** one person. **Review-by:** `YYYY-MM-DD`, at most 180 days ahead.

| Name | Held version | Reason | Owner | Review-by |
|------|--------------|--------|-------|-----------|
