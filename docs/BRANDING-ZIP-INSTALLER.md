# Automatic branding ZIP installation

OUTPOST opts into the [shared SUN branding installer](https://github.com/sunstriker2009/sun-foundry/blob/main/docs/BRANDING-ZIP-INSTALLER.md).

1. Create a feature branch from main after the opt-in PR has merged. Older branches must first include `.github/workflows/branding-auto-install.yml`.
2. Commit exactly one unnumbered ZIP directly under `branding/revisions/`, keeping its original filename. Create the directory if needed.
3. Push as `sunstriker2009`. The action validates the package and appends an installation commit on the same branch.
4. Inspect the installed artwork and passing backend/frontend checks, then squash-merge the PR. Branding PRs are not automatically merged.

Packages contain `branding/assets/` at the root or beneath one enclosing export folder, with a landscape PNG banner, square PNG symbol and PNG icons at 16, 24, 32, 48, 64, 128, 256, 512 and 1024 pixels. See the shared guide for complete validation and size limits.

The first installation backs up current assets as `branding/revisions/v1.zip` and saves the resulting asset tree as `v2.zip`; subsequent changes create the next numbered snapshot. The original upload is removed only on successful installation. Numbered snapshots are immutable and ignored by upload detection. Invalid, multiple or identical uploads stay intact; identical assets consume no revision. Concurrent branch changes are refused without force-pushing.

The installer updates active assets and revision history. It replaces the active icons directory with the supplied PNG icon set and retains other assets/references unless matching paths are supplied. Product identity, guides, application-specific asset copies/configuration and legacy archives require separate reviewed changes.

The hook uses the repository-scoped GitHub token and the reviewed FOUNDRY action pinned at `c1680fc22fb35f9542b65dfb1b79449c0970a154`. If a PR is already open, it dispatches `ci.yml` after the token-authored installation commit so backend and frontend validation run for that commit. Opening a PR after installation triggers normal PR checks. The dispatch runs the same jobs as ordinary CI.

Merging the branding PR approves its canonical symbol for the existing daily/manual Ecosystem reconciliation. Rollback uses the manual SUN Branding ZIP Installer workflow to restore a snapshot through a new revision and reviewed PR; historical snapshots remain intact.

Opt-in does not change approved product identity or resume paused functional-development schedules. No live OUTPOST upload or rollback is claimed by this setup.
