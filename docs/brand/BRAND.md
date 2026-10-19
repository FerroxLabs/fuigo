# Fuigo brand system

This file is the single reference for how Fuigo looks and sounds in public: the README, the social preview, release notes, the npm page and anything Ferrox Labs publishes about the engine. Keep it short and keep it true.

## Idea

A fuigo (鞴, ふいご) is the bellows of a Japanese forge: it drives air into the fire. The name is the brand. The mark is wind, three strokes of air moving in one direction; the colour is the ember that air feeds. Fuigo is the thing that makes the model burn hotter, not the fire itself. The field stays dark and quiet so the terminal screenshots, which are the real product, carry the page.

In art: air is pale, translucent, horizontal; fire is orange, concentrated, to the right. Never draw a literal bellows, anvil or hammer; the glyph and the glow say enough.

## Palette

Two themes. The README banner, the mark and every illustration must read correctly in both, because GitHub switches with the reader's system setting.

### Dark (primary)

| Token | Hex | Use |
| --- | --- | --- |
| `ink` | `#0B0D12` | Page and banner background. Opaque; never pure black. |
| `surface` | `#12151C` | Panels, code blocks, the terminal frame in screenshots. |
| `line` | `#232833` | Hairlines, borders, dividers. |
| `text` | `#F2EFE9` | Primary text and the wordmark. Warm white, not blue-white. |
| `muted` | `#A3A8B3` | Secondary text, captions. |
| `ember` | `#FF6A1A` | The brand orange. Mark, accents, links on dark. |
| `ember-hot` | `#FF9A4D` | Highlight on the mark's glow and hover states. |
| `ember-deep` | `#C94A0A` | Shadow side of the mark, pressed states. |
| `ok` | `#4CC38A` | Success, passing tests. |
| `warn` | `#F5B544` | Warnings. |
| `danger` | `#E5484D` | Errors, rejected tool calls. |

### Light

| Token | Hex | Use |
| --- | --- | --- |
| `paper` | `#FAF8F5` | Page and banner background. Warm off-white. |
| `surface` | `#FFFFFF` | Panels and code blocks. |
| `line` | `#E6E1DA` | Hairlines and borders. |
| `text` | `#16181D` | Primary text and the wordmark. |
| `muted` | `#5B6070` | Secondary text. |
| `ember` | `#E85D0C` | The brand orange on light. Large text and the mark only (3.6:1 on paper). |
| `ember-text` | `#B8420A` | Orange for body-size text and links on light (5.6:1 on paper). |
| `ok` | `#1F8A5A` | Success. |
| `warn` | `#B7791F` | Warnings. |
| `danger` | `#C62828` | Errors. |

Rules: `ember` never appears as body text on light; use `ember-text`. Never put orange text on orange. Never tint the backgrounds orange; the field stays neutral so the mark is the only warm object.

## Type

| Role | Face | Weight and setting |
| --- | --- | --- |
| Wordmark | Sora | 700, uppercase `FUIGO`, tracking +0.06 em |
| Headings and UI | Inter | 600, normal tracking |
| Body | Inter | 400, 1.5 line height |
| Code and terminal | JetBrains Mono (fallback: SF Mono, Menlo, Consolas) | 400 |

Both Sora and Inter are open fonts (SIL Open Font License). Rendered artwork embeds them as pixels; nothing in the repo depends on the reader having them installed. Markdown pages use GitHub's own fonts and need no styling.

## The mark

The mark is the [Lucide "wind" icon](https://lucide.dev/icons/wind): three horizontal strokes of air, each curling back on itself at the leading end. It is used with its paths unchanged (lucide-static 1.59.0, ISC licence; the licence text is in `docs/assets/lucide-LICENSE.txt` and the attribution stays in the README). What Fuigo adds is the stroke: weight 2.25 on the 24-unit grid and the `ember` gradient, hot on the left where the air enters and deep on the right where it meets the fire.

Files:

- `docs/assets/brand/mark.svg`: the master. Fixed colours, so it renders the same on any background. Use it at 24 px and above.
- `docs/assets/brand/mark.png`: 512 x 512 raster with transparent background, for places that cannot take SVG (npm, app icons, chat avatars).

Usage:

- Minimum size 24 px. Below that use the plain Lucide icon in a single colour (`ember` on dark, `ember-text` on light).
- Clear space around the mark equals the height of one stroke's curl on every side.
- The strokes always run left to right. Never mirror the mark; the air goes into the fire, not out of it.
- Single-colour version: solid `ember` (dark) or `ember-text` (light). No glow on light backgrounds.
- Do not rotate it, add a fourth stroke, outline it, or put it inside a circle or a rounded square.
- Do not place it next to the Grok, xAI, OpenAI, Anthropic or any provider logo as if they were partners. Provider names appear in text only.

Lock-ups:

- Horizontal: mark, then `FUIGO` wordmark, gap equal to half the mark's height, mark height equal to the wordmark's cap height.
- Stacked (social preview, avatars): mark above the wordmark, centred.

## Voice

Plain, precise, calm. Fuigo describes what it does and lets the screenshots prove it.

- Short sentences. Active voice. Concrete nouns: tools, sessions, permissions, memory.
- No hype adjectives (powerful, blazing, seamless, next-generation, revolutionary). No exclamation marks.
- Verified claims only. If a feature has a limit, say the limit in the same breath.
- Name the model providers the product supports; never imply endorsement by them.
- Lineage is stated once, plainly: a derivative of Grok Build, independently maintained, not affiliated with xAI.
- Second person for instructions ("run", "set"), third person for the product ("Fuigo asks before it runs a command").

## Taglines

| Candidate | Reads as | Notes |
| --- | --- | --- |
| **The model is the fire. Fuigo is the bellows.** (pick) | The name explained in one line: Fuigo is not the model, it is what makes any model work harder | Ties the brand to the bellows story and to the multi-provider position; the art (air into fire) illustrates it literally. |
| Act. Collaborate. Remember. | The three things the engine does: tools, subagents and ACP, memory | The previous hero line. Three verbs, no claim to defend; keep for section-level copy and release posts. |
| One engine. Any model. Every surface. | The multi-provider, three-surface positioning | Accurate but says nothing about memory. Use as a sub-line in long copy. |
| The agent engine that remembers. | Memory-first | Strong single hook but narrows the product to one feature. |

Pick: **The model is the fire. Fuigo is the bellows.** (approved 2026-10-19). Sub-line under it: *The open coding agent that holds its own with the best, on any model.* The sub-line is a positioning statement, not a benchmark claim; do not attach numbers to it.

## Assets index

| File | Purpose | Spec |
| --- | --- | --- |
| `docs/assets/brand/banner-dark.png` | README header, dark theme | 1800 x 600, under 400 KB, opaque `ink` |
| `docs/assets/brand/banner-light.png` | README header, light theme | 1800 x 600, under 400 KB, opaque `paper` |
| `docs/assets/brand/social-preview.png` | GitHub social preview (repo Settings) | 1280 x 640, under 1 MB, opaque, 40 px safe margin |
| `docs/assets/brand/mark.svg` | Master mark | Scales from 24 px |
| `docs/assets/brand/mark.png` | Raster mark | 512 x 512, transparent |
| `docs/assets/screens/*.png`, `demo.gif` | Real terminal captures | 2320 x 1400 source, see `docs/assets/screens/SHOTS.md` |
