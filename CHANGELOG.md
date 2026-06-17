# Changelog

Notable changes to GreyIQ.

## v0.9.6

### Changed
- **Dark mode is now the default.** New installs and the browser fallback open in
  dark. An explicit theme choice (via the header toggle) is remembered and always
  wins; users who never picked — including those with a stale light preference from
  the old default — now open in dark.

## v0.9.5

### Added
- **Delete personalities and local models.** A "Delete this bot" button in the bot
  editor removes a personality along with its chat history, learned memory, and
  backend AI core (always keeping at least one). The Coding brain panel now lists
  installed Ollama models with a **Remove** button to free their disk space.

## v0.9.4

### Added
- **Out-of-the-box GPU acceleration for the local model (Ollama).** NVIDIA (CUDA)
  is bundled and used automatically. AMD (ROCm) is auto-provisioned on first run:
  when an AMD GPU is detected, GreyIQ downloads Ollama's ROCm runtime (~1 GB,
  one-time) and overlays it on a writable copy of the bundled runtime. Any failure
  falls back to the bundled runtime, so GPU setup can never break the app.
- A **"Local model GPU: …"** status line in the Coding brain panel (desktop) showing
  the detected GPU vendor and the active runtime (CUDA/ROCm), or CPU.

### Fixed
- Restored the bundled **CUDA** runner on Linux. A prior release pruned it to fit
  GitHub's 2 GiB asset cap, which disabled NVIDIA acceleration; the CPU-only torch
  wheel already keeps assets small, so the prune was unnecessary.

### Docs
- Clarified GPU support in the README and the package description.

## v0.9.3

### Added
- **Pentest & OSINT Toolkit** — a curated, queryable catalog of 172 tools across 10
  categories (from [awesome-pentest](https://github.com/enaqx/awesome-pentest),
  CC-BY 4.0, and [awesome-osint](https://github.com/jivoi/awesome-osint), MIT),
  mapped to BugHunter's vuln classes, surfaced in a browsable panel, in BugHunter
  "Recommended tooling", and via an agent skill.

### Fixed (release CI, Linux)
- Ollama's Linux asset moved to `.tar.zst`; download/extract updated (was a 404).
- Free ~30 GB on the runner before the build (was "No space left on device").
- CPU-only torch + slimmer bundle so release assets stay under GitHub's 2 GiB
  per-asset limit.

## v0.9.2
- Workbench: collapsible, readable file tree.

## v0.9.1
- QA/QC: fixed BugHunter vuln-class mapping and assorted cleanups.

## v0.9.0
- Agent security red-team; Workbench slide-to-dock; GreyNOC-IQ rename.
