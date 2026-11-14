# ORYVA by Sun — Brand Guide

**Product:** SUN-001  
**Approved visual identity:** Solar Coral Orbit (v2)  
**Tagline:** Identity. Trust. Protection.

## Identity and approval
The owner approved the Solar Coral Orbit concept. A luminous orbital ring forms the letter **O**, with a SUN-family sunrise flare and four-point star. The palette is aubergine, coral/magenta, warm solar gold and ivory. The previous mountain/sunrise identity is retired. Do not introduce mountains, shields, padlocks, keyholes or fingerprint symbols into the primary mark.

The approved high-resolution image is the visual source of truth. Vector lockups and symbols must be intentionally designed, reviewed adaptations—not claimed as pixel-identical extractions.

## Active asset
| Path | Role |
|---|---|
| `branding/assets/readme-banner-v2.png` | Approved high-resolution raster README banner |

The exact same Git blob is preserved at `branding/archive/originals/readme-banner-v2.png`. This is an exact byte-for-byte archival copy of the committed approved banner, **not** a claim that a layered/transparent source exists.

## Retired legacy assets
The former mountain-era SVGs are archived at:
- `branding/archive/retired/readme-banner-v1.svg`
- `branding/archive/retired/lockup-dark.svg`
- `branding/archive/retired/app-icon.svg`

The earlier alternative panorama remains in `branding/archive/intermediate/`. The old banner also has a historical copy in `branding/archive/originals/readme-banner-v1.svg`; that file is an SVG adaptation, not the original raster concept.

**Do not use retired SVGs in new production UI.** New v2 SVG adaptations have been proposed in a separate review PR; they are not yet owner-approved.


## Uploaded PNG icon exports (v2 symbol proposal)

Nine PNG icon exports were supplied by the owner and are organized under `branding/assets/icons/`:

| Size | Asset |
|---|---|
| 16 | [icon-16.png](assets/icons/icon-16.png) |
| 24 | [icon-24.png](assets/icons/icon-24.png) |
| 32 | [icon-32.png](assets/icons/icon-32.png) |
| 48 | [icon-48.png](assets/icons/icon-48.png) |
| 64 | [icon-64.png](assets/icons/icon-64.png) |
| 128 | [icon-128.png](assets/icons/icon-128.png) |
| 256 | [icon-256.png](assets/icons/icon-256.png) |
| 512 | [icon-512.png](assets/icons/icon-512.png) |
| 1024 | [icon-1024.png](assets/icons/icon-1024.png) |

These are the uploaded *symbol-proposal* PNG exports, distinct from the already approved panoramic banner. Their presence does not establish approval of a canonical transparent symbol or optical quality at small sizes. The old `app-icon.svg` is retired, not a current replacement.

## Pending production derivatives
- Establish a transparent canonical ring symbol from a genuine source or separately approved artwork. A crop of the flattened banner is not a transparent source.
- Design `symbol-dark.svg`, `symbol-light.svg`, `symbol-mono.svg`, `symbol-small.svg` and `lockup-dark.svg`, `lockup-light.svg`, `lockup-mono.svg` as v2 adaptations.
- Review and optically validate the uploaded 16–1024 px PNG icon exports before declaring them final.
- Document approved exact color tokens, typography, contrast and minimum sizes after derivative visual review.
- Validate README legibility on GitHub mobile and desktop.

See [SUN Product Branding Standard](https://github.com/sunstriker2009/sun-ecosystem/blob/main/docs/governance/PRODUCT-BRANDING.md).

## Proposed compact SVG variants (pending visual approval)

| Asset | Intended use |
|---|---|
| [symbol-dark.svg](assets/symbol-dark.svg) | Color orbit on dark UI |
| [symbol-light.svg](assets/symbol-light.svg) | Color orbit on light UI |
| [symbol-mono.svg](assets/symbol-mono.svg) | Single-color fallback on dark UI |
| [symbol-small.svg](assets/symbol-small.svg) | Reduced-detail small mark |
| [lockup-dark.svg](assets/lockup-dark.svg) | Wordmark on dark UI |
| [lockup-light.svg](assets/lockup-light.svg) | Wordmark on light UI |
| [lockup-mono.svg](assets/lockup-mono.svg) | Single-color wordmark |

These are newly constructed **vector interpretations**, not tracings or exports from the original raster layers. The lockup uses generic system typography; it is not a pixel-faithful recreation of the approved banner wordmark. All require owner review before use in product interfaces. The existing README PNG and nine PNG icons are unchanged.

### Vector color tokens (provisional)
- Solar gold: `#FFD66C`
- Warm coral: `#FF8A42`
- Orbit pink: `#EE477E`
- Orchid: `#A43A9C`
- Aubergine: `#241525`
- Warm ivory: `#FFF6EE`

These are manually selected working values, not sampled or certified values from a layered master. Check contrast against actual UI backgrounds before production.
