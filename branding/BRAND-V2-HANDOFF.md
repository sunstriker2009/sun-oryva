# ORYVA Solar Coral Orbit — Brand v2 Handoff

**Status:** Owner-approved visual direction; raster repository upload pending.

## Approved identity
- **Product:** ORYVA by Sun (SUN-001)
- **Tagline:** Identity. Trust. Protection.
- **Symbol:** Illuminated orbital ring forming **O**, sunrise flare, four-point star.
- **Palette direction:** Aubergine, coral, magenta, solar gold, warm ivory.
- **Restrictions:** No mountains, shields, padlocks, fingerprint motifs or independently regenerated substitutions.

## Source of truth
The owner-approved banner is the exact 2172 × 724 PNG from the Solar Coral Orbit approval. Its SHA-256 is:

`9fe596f08bfb96cbe2f13fb3d1f48b3cca9fab9e770e6da77aef36f2a695f9e0`

Required paths after binary upload:
- `branding/assets/readme-banner-v2.png`
- `branding/archive/originals/readme-banner-v2.png` (byte-identical original)

A raster handoff package was prepared outside the repository. **Do not switch README to the PNG path until the PNG is actually committed.** Existing SVG assets remain active until replacement and QA.

## Pending production work
- Commit the original PNG bytes through an authorized binary upload.
- Derive and visually validate a truly transparent standalone symbol. Crops of the flattened banner are not transparent masters.
- Create compact `symbol-*.svg`, `lockup-*.svg` and small-size icons from the approved ring, not the retired mountain symbol.
- Validate 16–32 px icons, light/dark usage, accessibility, README mobile legibility.
- Update `branding/BRAND-GUIDE.md`, README and archive references in the same completing PR.
- Retire prior mountain SVG banner only after the raster banner is live.

**Current PR is a handoff/checklist, not a completed brand migration.**
