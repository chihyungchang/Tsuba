# Tsuba UI Style Guide

v4, 2026-10-28. Style: **samurai armor, held back**: black lacquer and hammered iron (dark) or washi and sumi ink (light), gold rims, vermilion seals. Only the materials and craft of armor and sword fittings; no cherry blossoms, brush fonts or ninjas, and evidence stays as readable as ever. The palette follows the tsuba mark: vermilion, black iron, gold (the guard's rim) and steel white. The home page combines four directions: the dashboard skeleton (U1) + the guardian tsuba (U4) + the bento summary (U6) + the terminal log at the bottom (U3), and the App opens through the guard in the splash. Details follow the Apple Human Interface Guidelines (macOS).

Implementation: all styles are tokens in `src/App.css`; components only reference tokens and never use raw color values. Brand graphics (the guardian, the splash) are in `src/brand.tsx`.

> History: v1 and v2 were liquid glass, but once glass was layered over the page the transparency was barely visible, and it required macOS private APIs; v3 was a graphite dashboard whose cyan accent had nothing to do with the mark. Variable names like `--glass` were kept and now all point to solid panels.

The App ships in English and Simplified Chinese. UI copy quoted below is given in English with the Chinese in parentheses.

## 0. Principles

1. **Status at a glance, the main action in one step.** The home page answers two questions: am I protected right now? Is there anything I need to deal with?
2. **Solid panels; hierarchy comes from light and dark and hairlines.** No transparency and no large shadows. Dark is black lacquer, light is washi paper: the same structure with a different set of tokens.
3. **Color only carries meaning.** Gold is the main action; green, amber and red only mean Allow, Warn and Block, and always come with text or an icon; vermilion is used only for the mark and the guardian's halo, and is kept apart in hue from "Block red".
4. **Safety status is recognizable at a glance.** When protection is paused, every page must feel like "there is no protection right now": the guard leaves the laptop's screen, the screen turns red with a hacker in it, and the halo turns dark red.
5. **Evidence must be readable first.** Commands, paths and code snippets sit on a one-step-darker "well" background in a monospaced font.

## 0.5 Mark

**The guard**: a tsuba (鍔) is the hand guard of a Japanese sword, sitting between the blade and the hand holding it, which matches "stepping in for you before the code runs". The mark is a four-lobed (mokko) iron guard with a gold rim (fukurin), a raised seppa-dai and its three holes: the tang hole in the middle, the kozuka and kogai holes either side. The holes make it read as a tsuba rather than a flower or a badge.

- **App icon**: a 3D render of the guard on a vermilion gradient plate, on the macOS icon grid (1024 canvas, 824 rounded square). `src-tauri/icons/source/tsuba.py` models and renders it in Blender, `compose.swift` puts it on the plate, and `pnpm tauri icon` makes the full set; the steps are at the top of `tsuba.py`.
- **Small in-UI mark** (`TsubaMark`): the guard's white silhouette, pierced, in a vermilion rounded square.
- **Dashboard** (`GuardianTsuba`): the same render facing the camera (`src/assets/tsuba.png`, `tsuba.py … art`), as a shield on a 3D laptop's screen.
- **Menu bar**: the guard's silhouette as a template icon (`icons/tray-template.png`, from `icons/source/tray-template.svg`), filling the canvas so the holes still show at 18px; the paused icon is the same shape faded. The system tints it to match the menu bar.
- **Splash**: the same render; the App opens out of its tang hole.

## 1. Layout

```
┌ Title bar 40px: traffic lights · …………………… tsuba mark Tsuba / red Resume button when paused ┐
│  ╭────────╮  ● Protection is on · all four defenses are working                        │
│  │guardian│  AI Active Defense                                                         │
│  ╰────────╯  ✓Terminal ✓Installers ✓Extensions ✓AI Tools  [Check a Folder]  Scan · Health Check · Pause │
│  ┌ 3 need attention ──┬ 128 checks ┬ 1 in quarantine ┬ 234K threat intel ┐  ← bento grid  │
├ ⌄ tsuba ▸ protected 4/4 ……………………………………………………………………… All History → ┤ ← terminal log │
│  3 min ago  BLOCK  curl … | bash · install script of fake meeting software …            │
└ Bottom bar 36px: tsuba mark TSUBA · judgment mode ………… ⌘2 History ⌘3 Scan ⌘4 Health Check · ⚙ Settings ┘
```

- **The window is fixed at 1000 × 700** and cannot be resized or zoomed; every page is laid out for this size, with no responsive layout. The content area is 1000 × 624 (minus the 40px title bar and the 36px bottom bar).
- **No sidebar.** Home → bento grid / links / log → detail page. The ⌘1–4 and ⌘, shortcuts work as before, with hints in the bottom bar.
- **Back is not in the title bar**: a button next to the traffic lights looks out of place. The title bar has only the traffic lights, the centered page name and the tsuba mark on the right; detail pages have a "‹ Home" (‹ 首页) breadcrumb in the top-left corner of the header card (on the History page it sits at the top of the list column), and Esc also goes back home.
- **Dashboard**:
  1. Main area: the guardian tsuba on the left (280px, see Components); on the right the status pill, the title "AI Active Defense" (AI 主动防御, 30px), a one-line introduction, the four defenses, the gold main button "Check a Folder" (检查一个文件夹) and three text buttons "Scan · Health Check · Pause" (扫描 · 体检 · 暂停). When paused, the title is "Active Defense Paused" (主动防御已暂停). Files can be dragged onto anywhere in the window to be checked.
  2. Bento summary: one row of four cells, widths 2 : 1 : 1 : 1.25. "Needs attention" (需要处理) is the widest and shows the latest item; the others are the check count, quarantine and threat intel.
  3. The main area and the bento grid are centered vertically in the remaining space; the terminal log sticks to the bottom.
- **Detail pages**: at the top is a header card (`PageHeader` with `icon`): a 56px colored icon tile, the status, the title and description, the main action on the right, and a row of key numbers below. The status color follows the verdict: green when normal, amber when there's a problem, red when paused, gold otherwise. History is a split view: the list column on the left is one step darker than the content area.
- **Health Check page**: it has content even before it has ever run: the header shows the time and result of the last Health Check (stored locally), and each check card lists exactly what it checks; the descriptions must match what the engine actually checks.
- **The defense switches come first on the Settings page**; the dashboard only shows whether each defense is on, and clicking one jumps to Settings.

## 2. Color

### Surfaces

| token | Dark (black lacquer) | Light (washi) | Use |
|---|---|---|---|
| `--window` | `#131114` | `#f3eee3` | Window and content area background, under `--texture` (hammered iron grain / washi fibers, inline SVG noise) |
| `--bar` | `#0d0c0e` | `#e9e2d3` | Title bar, bottom bar, History list column |
| `--panel` | `#211e22` | `#fcf9f2` | Cards, grouped lists, bento grid |
| `--raised` | `#2c292d` | `#fffdf8` | Buttons, hovered cells, selected items |
| `--well` | `#0c0b0d` | `#eee7d9` | Terminal log, commands, code snippets, input fields (wells) |

In dark mode, panels have a 1px 5% white inner highlight on top and a 1px black border all around. Light mode only uses a faint 1px border.

### Text and lines

| token | Dark | Light |
|---|---|---|
| `--text` | `#f3efe6` | `#1f1c17` |
| `--text-2` | `#c4bdb0` | `#4e483e` |
| `--text-3` | `#8f887c` | `#857d70` |
| `--line` | warm white 8% | warm black 10% |
| `--gold-line` | gold 30% | gold 35% (fine gold line) |

All text has a slightly warm tint to go with black lacquer and washi; no pure black or pure white.

### Semantic colors

| token | Dark | Light | Use |
|---|---|---|---|
| `--cta` | `#d8b36a` (dark text `#1d1408`) | `#b4873a` (white text) | Main action, selection, keyboard focus; matches the guard's gold rim |
| `--allow` | `#7ccb8f` | `#2a7a47` (pine needle) | Allow, Protection is on, switch on |
| `--warn` | `#f2b441` | `#a46500` (yamabuki) | Warn, defense off |
| `--block` | `#ff6a57` | `#b8261b` (hi scarlet) | Block, delete, paused (text and icons) |
| `--alarm` | `#c42a1d` | `#c42a1d` | White-on-red buttons (Resume Protection, confirm delete) |
| `--brand` | `#e5532f` | `#c9401f` | Brand mark only |

"Block red" leans deep red and brand vermilion leans orange; the two are never mixed.

## 3. Typography

System font: SF Pro + PingFang. Monospace: SF Mono. Base size 13px. Titles (every `h1`) and the report verdict use Mincho (`--serif`: Hiragino Mincho ProN; Songti SC when the UI is Chinese), weight 600 with +0.02em tracking; both ship with macOS. Nothing else changes font: body, commands and evidence stay in the system fonts.

| Style | Size / line height | Weight | Use |
|---|---|---|---|
| Display | 26 / 31 | 700 | Dashboard title; only one in the whole App |
| Title | 24 / 30 | 700 | Detail page title, one per page |
| Headline | 17 / 24 | 600 | Report verdict |
| Number | 28 / 31 | 700 | Numbers in the bento grid |
| Section | 13 / 18 | 600 | Section headings (`--text-2`) |
| Body | 13 / 20 | 400 | Body text |
| Caption | 11.5–12 / 17 | 400 | Cell descriptions, metadata, bottom bar |
| Mono | 11.5 / 24 | 400 | Terminal log (SF Mono); the description part still uses the system font |

Numbers always use `tabular-nums`. Commands, paths and error messages are never truncated (except the "latest item" on the dashboard; click through to see the full text).

## 4. Corner radius and spacing

| Value | token | Used for (tight corners: lacquer boxes and iron plates, not soft app cards) |
|---|---|---|
| 8px | `--r-xl` | Drop target when dragging files in |
| 6px | `--r-lg` | Grouped lists, cards, bento grid |
| 5px | `--r-md` | Code blocks, banners, list items |
| 4px | `--r-sm` | Buttons, input fields, icon tiles |
| Pill | `--r-pill` | Status pill, verdict tags, switches, the Resume button in the title bar |

Spacing follows a 4px rhythm: 4 / 8 / 12 / 16 / 20 / 24 / 32. 18 between dashboard sections, 10 between bento cells, 28 between detail page sections, 24–40 for the page's left and right margins.

## 5. Motion

- Duration 160–240ms (380–420ms for entrances), easing `--ease: cubic-bezier(.2,.8,.2,1)`.
- Splash (about 1.8 s): the guard rises out of the dark, `tsuba ▸ protected 4/4` (`tsuba ▸ 守护中 4/4`) is typed out like a terminal, then the view rushes through the guard's tang hole into the App.
- Entrance: the home page's main area and the four bento cells rise in one after another, 40ms apart; the same goes for a detail page's header card and check cards.
- Guardian: the halo breathes, the guard floats in 3D as a shield on the laptop's screen while a line scans the code (see Components). Coming back on resume overshoots a little and never flashes.
- Bento cells lift 2px with a shadow on hover and settle back when pressed; the main button's halo brightens on hover.
- While protection is on, the status dot breathes slowly (once every 2.8 s); it does not breathe when paused or when some defenses are off.
- Buttons shrink to 0.97 when pressed; switch knobs widen when pressed.
- Tasks in progress: a sweep along the card's bottom edge or a spinner, never a full-page overlay.
- When paused, the Resume button in the title bar breathes slowly (once every 2.4 s).
- Everything is turned off when the system's "Reduce motion" setting is on.

## 6. Interaction guidelines (UX)

1. **Unrelated tasks never interrupt each other.** Each task has its own in-progress, error and done states and can run concurrently (the three Health Check checks). "All" only starts the ones that aren't already running.
2. **Leaving a page doesn't lose progress.** Pages with long-running tasks (Health Check) are not unmounted when you switch away.
3. **Show errors where they happen.** An error is shown on the item that failed.
4. **Dangerous states must be "loud".** When protection is paused:
   - Dashboard: the guard drops off the laptop's screen, the screen turns red and a hacker glitches into it, the halo turns dark red, the status pill turns red, the title reads "Protection is off. The blade is sheathed." (保护已关闭，刀已入鞘。), it spells out what won't be checked right now, and the main button becomes the red "Resume Protection" (恢复守护); the terminal log shows "paused 0/4" (已暂停 0/4);
   - The top-right corner of the title bar becomes a red "Protection paused · Click to resume" (守护已暂停 · 点击恢复), so protection can be resumed in one click from any page;
   - A faint red glow lies over the top of the window.
5. **Irreversible actions take two clicks and are kept apart from other buttons.** They go at the far right of the toolbar; the first click turns the button into "Click Again to Delete Permanently" (再点一下，永久删除), and only a second click within three seconds executes it. Prefer reversible actions (Move to Quarantine).
6. **Deletion has guardrails.** Only the specific file or project in the record can be deleted; the home directory, its first-level subdirectories and system directories are always refused. The guardrails live in the engine (`quarantine::delete_path`).
7. **Every action gets feedback.** When it's done, show a short message (toast); on failure, state the reason and the next step.
8. **Don't be a nuisance.** The dashboard has only one main action; warnings appear only when something is actually wrong, never as a barrage.

## 7. Components

### Buttons

Corner radius 8px, height 30px (38px for the dashboard main button), weight 500–650.

| Variant | Appearance | Use |
|---|---|---|
| Default | Solid `--raised` + hairline border | Secondary actions |
| `primary` / `cta` | Solid `--cta` | At most one main action per screen |
| `cta-alarm` | Solid `--alarm`, white text | Resume Protection |
| `danger` | Default appearance, `--block` text; solid `--alarm` when `is-armed` | Delete-type actions, two clicks |
| `link` | No background | Light inline actions (Pause Protection, Remove) |
| `back` | Default appearance, small | "‹ Back" (‹ 返回) in the title bar |
| `icon-button` | No background, 28px | Must have `aria-label` and `title` |

Disabled: opacity 0.4. Keyboard focus: a 3px `--focus` outer ring.

### Status pill

Height 24, pill-shaped: a soft status-color background + a 1px status-color border + a glowing dot + text. Green when protection is on, amber when some defenses are off, red when paused.

### Guardian (`GuardianTsuba`)

280px. A graphite laptop (`src/assets/laptop.png`, rendered by `src-tauri/icons/source/laptop.py` with the same materials and light as the App icon) with a halo behind it. The render's frame is 1.4x the laptop so its shadow fades out inside the image; `.guardian-stage` overhangs the 280px box by 20% to match. Its screen is drawn in CSS over the render's screen rectangle (`laptop.py` prints it; `.guardian-screen` uses it): scrolling code, a scan line, and the guard (`src/assets/tsuba.png`) standing in front of it like a shield. No outer ring: how many defenses are on is shown by the status pill and the four check marks beside it. Its colors are fixed and don't change with the theme (it is an object).

Each state's layers are always present and switch via transitions, so the switch itself is the animation:

| State | Motion |
|---|---|
| Protection on (steady) | The screen is calm: code scrolls up (16 s loop) and a gold scan line sweeps down every 3.2 s. The guard floats and sways ±12° in 3D over 6 s with a gold glow pulsing behind it (3 s) and a band of light sweeping across it (4.2 s). The halo breathes every 4.5 s and leans amber when some defenses are off |
| Paused (transition) | Told as cause and effect: the guard drops off the bottom of the screen like a lowered shield (0.45 s) and the scan and glow go out; at 0.35 s the screen flickers red; at 0.6 s a hooded hacker with glowing eyes glitches in, then glitches every few seconds while the red pulses; the halo turns dark red |
| Resumed (transition) | The guard springs up from below and overshoots; as it lands (0.28 s) a gold ring bursts out, the hacker is knocked out and the red drains away; then the glow and the scan come back |

Opacity always moves by transition, never by animation (removing an animation makes it jump); the guard's drop is a transition on its box and the float is an animation on its children: both animate `transform`, and on one element removing the animation would skip the transition. When the system's "Reduce motion" setting is on, none of these animations play; only the state itself is shown.

### Bento grid

Solid `--panel`, corner radius 12, minimum height 104, padding 14×16, the whole cell is clickable. Numbers 28/700, descriptions 11.5 `--text-3`. When "Needs attention" (需要处理) has warnings, its background takes a tint of Block red, the number turns red, and the latest item is written below in a monospaced font; the threat intel number is gold, with a faint gold ring in the bottom-right corner.

### Terminal log (`TermLog`)

Sticks to the bottom of the content area (sticky), with a `--well` background and a hairline on top. Header row: `⌄ tsuba ▸ protected 4/4` (`⌄ tsuba ▸ 守护中 4/4`), with "All History →" (全部记录 →) on the right; clicking the header row collapses or expands it, and the state is stored locally. One line per entry: time · tag · title (monospaced) · description (system font, truncated); clicking a line opens that record. Tags: `BLOCK` in Block red, `WARN` in amber, `QUAR` / `DEL` in gold, `PASS` in gray.

### Splash (`Splash`)

About 1.8 s, entering through the guard: on a dark warm gradient the guard rises (0.5 s), with the App already showing through its three holes; TSUBA and the status (`tsuba ▸ protected 4/4`) are typed below. At 1.05 s the view rushes into the tang hole (an accelerating 170× zoom) and the App opens out of it. The dark is one huge shape with the guard's holes cut out, in the same SVG as the guard, so they zoom together and the App is only ever seen through the holes. Not shown when the system's "Reduce motion" setting is on.

### Input fields, switches, segmented controls, grouped lists, verdict tags, banners

- **Input fields**: `--well` background, corner radius 8, height 32; the border turns `--cta` on focus.
- **Switches**: 38 × 22, `--allow` when on.
- **Segmented controls**: `--fill` well background, selected segment `--raised`.
- **Grouped lists**: `--panel` cards, minimum row height 54, inset hairlines between rows.
- **Verdict tags**: pills with a soft status-color background + status-color text + an icon, always labeled "Allow / Warn / Block" (放行 / 提醒 / 拦截).
- **Banners**: soft status-color background, corner radius 10, placed near where the error happened.

## 8. Light / dark

- Settings → Appearance (外观): System / Light / Dark (跟随系统 / 浅色 / 深色), stored locally (`tsuba-theme` in `localStorage`).
- `<html data-theme="light|dark">` is written by `src/theme.ts` before rendering; it also sets the window appearance (title bar, traffic lights, system dialogs) and listens for system changes.
- Take screenshots of both themes after every style change; add `?paused` to the dev preview URL to see the paused state directly.

## 9. Accessibility

- Body text contrast ≥ 4.5:1; `--text-3` is used only for secondary information at 11.5px or larger.
- Every interactive element has a keyboard focus style; icon buttons have names; ⌘1 goes home, ⌘2–4 open each page, ⌘, opens Settings, and the up and down arrow keys move through History.
- No animations when the system's "Reduce motion" setting is on.
