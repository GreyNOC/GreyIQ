# GreyIQ

GreyIQ (GreyNOC-IQ) is a **local-first AI** desktop/web app. It's a GreyNOC product that runs as its own experience, separate from the GreyNOC SOC interface — your data stays on your machine.

It includes:

- **DevOps/server setup playbooks** for PM2 ecosystem files, Ubuntu VPS setup, Nginx reverse proxies, environment variables/secrets, and `DEPLOY.md` runbooks.
- **Editable bots** with name, color, persona, style, and response variation, kept in one **bot
  store** the app, the CLI and the agent studio all drive: make, edit, clone, teach, train and
  delete bots, pick which one is live (it answers you *and* plans your hunts), and plug in a
  Hugging Face bot.
- A pluggable **coding brain** — answer with a local model (Ollama), Claude, or any OpenAI-compatible endpoint; falls back to the bundled local engine.
- **Agent mode + the Workbench IDE** — let the brain read, edit, and (optionally) run things in a workspace folder, with a file explorer, code preview, diffs, agent steps, and verification output.
- **BugHunter** — a static/passive security scanner, a **bug-bounty hunt** that writes reports with attack plans, and an **agent security red-team** that tests GreyIQ's own agent.
- Personal training from preferences, source-specific data, and 👍/👎 feedback; folder ingestion (PDF/DOCX/text/OCR).
- Browser fallback (CPU/WebGPU) when the Python service isn't running, plus an Electron launcher that boots the backend and fetches a **GPU-accelerated** Ollama runtime on first use of the local model — NVIDIA (CUDA) works out of the box; AMD (ROCm) is auto-provisioned on first run.

## Run

Browser-only fallback:

```powershell
npm start
```

Open [http://localhost:4173](http://localhost:4173).

Full local engine:

```powershell
python -m backend.greyiq_api
```

Open [http://localhost:8766](http://localhost:8766).

Desktop:

```powershell
npm install
npm run desktop
```

The desktop cockpit includes a **TACNOC** option beside **AI Studio**. It opens
the companion TACNOC application in its own sandboxed desktop process. GreyIQ
detects standard TACNOC installs and the normal `GreyNOC Belcher` development
checkout on the current user's Desktop; set `GREYIQ_TACNOC_PATH` to a TACNOC
executable or project directory for any other layout.

## Linux (Debian, Ubuntu, Kali, Parrot)

### The CLI from a git clone

The `gn` bug-bounty CLI needs **nothing but the distribution's `python3`** (3.11
or newer). Its whole boot path is stdlib-only — no venv, no pip, no root, no
package — so a clone is the install:

```bash
git clone https://github.com/GreyNOC/GreyIQ.git
cd GreyIQ
./scripts/install-cli.sh
gn dashboard
```

`./gn <command>` already works inside the checkout; `install-cli.sh` only puts a
launcher in `~/.local/bin` (it prints the one `export PATH=…` line if that
directory is not on your PATH yet) and `git pull` then updates the command in
place. Flags: `--extras`, `--bin-dir DIR`, `--name NAME` (Google's GN build tool
also installs a `gn`), `--force`; `--help` lists them.

The same CLI now includes **local defender monitoring** alongside bug discovery:
`gn defend inventory`, `gn defend baseline create --accept-current-state`,
`gn defend scan`, `gn defend watch`, `gn defend dash`, and `gn defend trace --pid PID`. Optional,
explicitly authorized Nmap and TShark adapters add bounded local network and
packet-metadata observations. See the [Defender CLI guide](docs/defender-cli.md)
for scope gates, baseline trust, examples, and detection limits.

That stdlib-only guarantee is enforced, not assumed:
`backend/test_gn_cli_stdlib_boot.py` runs the CLI — including a real code scan —
with every `site-packages` import blocked, and `scripts/smoke-source-cli.sh`
repeats the clone-and-run install in Debian 12 and Debian 13 containers that have
`python3` and no pip at all. Every scanner, the impact model and the report
writers work there. `--extras` adds only two optional engine libraries (YAML
OpenAPI-spec parsing, and the RS256 proof that a leaked cloud key is live); both
features degrade silently without them. See `requirements-cli.txt`.

**This is the install to use on Parrot and Kali**, and the only one on arm64 —
the release package is built for Debian 13 amd64. For the desktop app and the
local-model stack from source, see [DEPLOY.md](DEPLOY.md); that is the path that
needs Node.js 22.12+, a venv and `requirements.txt`.

### Desktop package and AppImage (Debian 13 amd64)

The `.deb`, the AppImage and the headless CLI tarball are **release assets, not
files in the repository** — download one from
[Releases](https://github.com/GreyNOC/GreyIQ/releases) first. `apt` installs the
desktop libraries and `zstd`, which the on-demand Ollama download needs:

```bash
sudo apt install ./GreyIQ-5.0.5-amd64.deb
greyiq-cli dashboard
```

`greyiq` opens the desktop app. `greyiq-cli` runs the same frozen backend's
command-line interface; `dashboard` is an interactive, read-only terminal view
of local health, system load, programs, findings, reports, and activity. Press
`q` to quit, `r` to refresh, and Tab or the arrow keys to change panels. The
dashboard requires a terminal and only probes the API on `127.0.0.1`. Both the
installed desktop and CLI use `$XDG_DATA_HOME/greyiq/runtime` (or
`~/.local/share/greyiq/runtime`) unless `GREYIQ_RUNTIME_DIR` is set. On first
launch after upgrading an older AppImage, the desktop copies existing data from
its previous Electron runtime directory when the new location is still absent.
Launch the desktop once before running CLI hunts after an upgrade so that copy
can complete.

For the headless CLI archive, extract it and run `./greyiq-cli path` for local
PATH guidance, then `./greyiq-cli dashboard`.
The included `INSTALL.txt` and [deployment guide](DEPLOY.md) show the exact
optional `~/.local/bin` PATH setup; the Debian package needs no PATH change.

For the AppImage, install its FUSE and local-model extraction dependencies, then
make it executable. Debian 13 and Ubuntu 24.04+ name the FUSE package
`libfuse2t64`; Debian 12 derivatives (Parrot 6, Kali) name it `libfuse2`:

```bash
sudo apt install libfuse2t64 zstd || sudo apt install libfuse2 zstd
chmod +x GreyIQ-*-x86_64.AppImage
./GreyIQ-*-x86_64.AppImage
```

### When the .deb will not install

Two commands identify every case below:

```bash
dpkg --print-architecture   # the release .deb requires amd64
cat /etc/debian_version     # 12.x derivatives (Parrot 6, Kali) are not the build target
```

| Message | Cause | Fix |
| --- | --- | --- |
| `Unsupported file … given on commandline` | the filename matched nothing — most often the `GreyIQ-*-amd64.deb` glob pasted inside a fresh clone, where no release asset exists | download the asset from Releases, or use the git-clone CLI install above |
| `Unable to locate package GreyIQ-…deb` | `apt` read the filename as a package name | keep the leading `./`: `sudo apt install ./GreyIQ-5.0.5-amd64.deb` |
| `package architecture (amd64) does not match system (arm64)` | the release package is amd64 only | use the git-clone CLI install above — it is pure Python and architecture-independent |
| `Depends: libasound2t64 but it is not installable` | releases up to 4.12.0 require the Debian 13 package name; Debian 12 derivatives call it `libasound2` | use the git-clone CLI install or the AppImage; packages built after 4.12.0 accept either name |
| `version 'GLIBC_2.xx' not found` from `greyiq-cli` or `greyiq` | the frozen binaries are built on Ubuntu 24.04 and need a newer glibc than Debian 12 derivatives ship | use the git-clone CLI install above, which runs on the distribution's own Python |
| a file manager reports an unsupported or unknown file type | no GUI handler is registered for `.deb` on that desktop | install from a terminal with `sudo apt install ./<file>.deb` |

The `.deb` only ever carries the desktop app and the frozen CLI. Nothing in it is
required to hunt: the clone install above exposes the same commands.

## macOS

The tagged release workflow builds native Apple Silicon (`arm64`) and Intel
(`x64`) DMG and ZIP archives. Choose the archive matching your Mac. The app
contains its own frozen backend and Chromium for proof screenshots. Ollama is
installed on demand by the operator for local coding models; it is not bundled.

Apple Developer signing and notarization require the repository secrets in
[CODE_SIGNING.md](docs/CODE_SIGNING.md). Without them, the draft assets are
unsigned and macOS Gatekeeper may block a normal first launch. A human operator
reviews the draft and decides whether to publish it.

## Check

Install the Python runtime and test dependencies before running the full check:

```powershell
python -m pip install -r requirements.txt -r requirements-test.txt
```

```powershell
npm run check
```

Reusable checks are also available:

```powershell
npm run check:js
npm run check:python
npm run check:devops
```

## Coding brain

In the **Coding brain** panel (training column) pick a provider:

- **Off** — bundled, source-labelled offline playbooks; the character-level TinyGPT experiment runs only in development builds.
- **Local model (Ollama)** — choose from a live dropdown of free, locally downloadable models with tool support from [Ollama's catalog](https://ollama.com/search?c=local&c=tools). GreyIQ also lists weights already installed on the selected Ollama server. Picking a model starts download and chat/tool readiness checks, then selects it automatically when both pass. The Ollama runtime isn't shipped in the installer — GreyIQ fetches it (with its bundled NVIDIA/CUDA runner) on first local setup. On AMD, GreyIQ fetches Ollama's ROCm runtime separately; without a supported GPU, it runs on CPU.
- **Claude API** — paste an Anthropic key (default model `claude-opus-4-8`).
- **OpenAI-compatible** — any `/v1/chat/completions` endpoint.

For a Hugging Face model, expand **Import a Hugging Face GGUF model**, paste a
public GGUF model page such as `https://huggingface.co/owner/model-GGUF` or an
`hf.co/owner/model-GGUF:Q4_K_M` reference, and choose **Import and select**.
GreyIQ starts local Ollama if needed, downloads the weights, checks that they
appear locally, and tests chat and structured tool calls before switching the
active brain. A model that only supports chat leaves the previous brain active.
Private, gated, and non-GGUF repositories need separate access or conversion.
Once selected, the model
then also drives BugHunter's hunt planning when the brain is enabled. If a model
is unavailable during a hunt, the bounded offline planner still runs. The
packaged desktop starts the saved local runtime again after app restart. For
source and headless CLI use, install and start Ollama locally; CLI hunts use
the saved model with `--brain`. Review each model's license and card before use.

If Ollama's repository pull rejects a model because it contains only **split
GGUF shards**, GreyIQ checks the complete quantization set, reports its size,
checks that local Ollama is version 0.35.0 or newer, and checks download space
before fetching the shards. An explicit `:quant` tag
selects that quantization; otherwise GreyIQ chooses the smallest complete one.
It verifies the downloaded files, reuses saved shards or Ollama blobs on retry,
and creates a local Ollama model from the original filenames, then runs the
same readiness checks. Large split models
need room for both the download cache and Ollama's model store, and still need
an Ollama version that supports their architecture. The status panel explains
preflight or model-creation failures without changing the previous brain.
Set `GREYIQ_RUNTIME_DIR` to move the download cache and `OLLAMA_MODELS` to move
the bundled Ollama model store before starting GreyIQ if the default volume is
too small. The latter also works for a separately installed Ollama when set in
that server's environment. For example, in PowerShell before opening the
portable app:

```powershell
$env:GREYIQ_RUNTIME_DIR = 'D:\GreyIQ\runtime'
$env:OLLAMA_MODELS = 'D:\GreyIQ\ollama-models'
```

For split GGUF shards larger than 4 GiB, both locations must use NTFS or
exFAT on Windows. FAT32 cannot store a single file that large even when the
drive has enough free space; GreyIQ checks this before downloading.

Launch GreyIQ from that PowerShell session so it inherits both settings.

On Linux, export both variables before starting the app and its Ollama server:

```bash
export GREYIQ_RUNTIME_DIR=/mnt/models/greyiq-runtime
export OLLAMA_MODELS=/mnt/models/ollama-models
```

For split imports, stop an already-running Ollama server before launching
GreyIQ. GreyIQ must launch Ollama with `OLLAMA_MODELS` set so it can verify the
model store's free space; a server started elsewhere has an unknown store and
the split download stops before transferring weights. Ordinary Ollama pulls
can use an existing server. Existing models in a former store are not moved
automatically.

See the [Hugging Face Ollama guide](https://huggingface.co/docs/hub/main/ollama).
If Ollama reports a blocked Hugging Face download redirect, update Ollama to
0.34.3 or newer; 0.34.2 has a [known redirect bug](https://github.com/ollama/ollama/issues/18526).

The brain answers chat, drives Agent mode, and writes the analysis in BugHunter reports.
For security and root-cause work, Agent mode can call a shared evidence-grounded
investigator that scans code read-only, ranks hypotheses, names the proof still needed,
and detects contradictions before proposing a fix. Raw credential values are never
included in the brief sent to a configured model.

## MCP servers

Open **Brain → MCP servers** to save more than one trusted server. Choose an
absolute native executable path with one argument per line for a local stdio
server, or an HTTP URL on literal loopback such as
`http://127.0.0.1:3000/mcp`. HTTP servers on other hosts, redirects, proxy
settings, custom headers, and stored environment variables are not supported.
For a Python or Node server, select the full path to `python.exe` or `node.exe`
as the command and put the server script's full path in Arguments. The form
does not download or install a server for you. Do not put credentials in
Arguments; they are saved as plaintext and may appear in process listings.

**Save** records the configuration without connecting. A new server is
disabled. **Test** explicitly starts a connection and lists available tools;
enable the server after you review it. Chat uses exact, one-shot commands:

```text
mcp list
mcp tools -y my-server
mcp call -y my-server tool_name {"argument":"value"}
```

`-y` confirms this chat connection or call is intentional. The chat model does
not choose or invoke MCP tools on its own. Server output is shown as untrusted text and
excluded from later model chat history. MCP commands and results stay visible
until reload but are not saved in browser chat storage. GreyIQ cannot enforce target scope,
rate limits, or request markers inside an external MCP server, so use a server
for target testing only when that server can enforce the engagement's rules.
Adding a server alone does not authorize any target activity.

Every authorized hunt automatically calls GreyIQ's built-in, in-memory MCP
evidence-review tool after the scan. It receives bounded categories and indexes
from the captured surface and findings, makes no target requests, and writes an
advisory review to the report and JSON sidecar. Its output cannot confirm a
finding, change severity, or schedule a probe.

For external analysis during a hunt, first enable and test a server, then approve
an exact advertised tool under **Brain → MCP servers** as evidence-only. This
approval is bound to the saved server configuration and becomes invalid after
the configuration changes. At hunt launch, separately check **External MCP
evidence analysis** for that run. GreyIQ passes only bounded, redacted hunt
metadata to at most three approved tools, one call
each. Their responses are labeled as untrusted advisory data. External servers
execute outside GreyIQ's
network guard: approve only tools you have verified do not make target requests.
No external tool runs automatically from server enablement alone.

## Agent mode & the Workbench

Toggle **Agent** and pick a workspace folder. The agent plans, then reads/searches/edits
files (traversal-guarded, confined to the workspace) and verifies its work; `run_command`
is **off by default**. The **Workbench** opens an IDE-style layer — a **Project** tab
(source cards of what GreyIQ knows about the workspace: purpose, tech stack, run
commands, key files, plus your own notes — one-click **Scan project**, and the agent
gets it on every run), a **Workflow** tab that lays each run out as
**Plan → Change → Verify → Explain**, plus a file tree, a read-only preview with line
numbers + light syntax highlighting, a Changes/diff tab, Agent Steps, and a Verify
panel. **Undo last agent run** rolls the workspace back to its exact state before the
run, and each card in the Changes tab can **Revert** just that one file. Neither will
overwrite a file you have edited since the run — it is reported and left alone, because
an undo that destroys work the agent never touched is worse than no undo.
Drag the divider to resize, or slide it to the top to
**dock** the workbench (chat moves to a 1/3 side panel). A light/dark theme toggle is in
the header.

One-click **task templates** above the composer (Review project, Explain repo, Create
README, Fix failing tests, Find security risks, Package for release, Issue / PR plan)
prefill a vetted prompt and switch on Agent mode when the task needs it.

**Security trust labels.** GreyIQ scans files for prompt-injection and labels them in the
preview (*trusted local file* → *prompt-injection risk*, with the matched signals). When
the agent reads a flagged file, its contents are handed to the model as untrusted **data,
not instructions**, so an embedded "ignore your instructions / exfiltrate secrets" can't
hijack the run — the same thinking as the agent red-team, in the daily UI.

For deployment work, GreyIQ injects deterministic project setup detection into the
agent prompt before the repo map, then applies bundled playbooks for PM2, Ubuntu VPS,
Nginx, env/secrets, and deployment docs. PM2 ecosystem generation prefers localhost
binding, avoids secrets, and updates `DEPLOY.md` when deployment behavior changes.
Verification is stronger for scripts and configs: Python, JSON, JavaScript, PM2
ecosystem files, shell scripts, YAML files, and `.env.example` secret-shaped values are
checked where the local command settings allow it. Command execution remains off by
default. The offline coder can also scaffold a bounded authorized HTTP/C2 traffic simulator
for a local lab; it sends finite attributed requests and treats every response as data, never
as commands to execute.

## Your bots

A bot is a record in `runtime/bots.json`: a name, a provider, a model, a persona, a style, a
temperature, and the standing instructions you have taught it. Exactly one is **live** — it answers
you *and* plans your hunts.

```bash
gn bot ls                      # every bot, the live one marked *
gn bot new recon --provider anthropic --model claude-opus-5 --use
gn bot set recon persona "a terse recon analyst; name the endpoint you probed"
gn bot teach recon "prefer read-only probes until the scope is confirmed"
gn bot clone recon --as recon-aggressive
gn bot use qwen                # switch; a prefix is enough
gn bot show                    # the live one in full, lessons included
gn bot train                   # train what that bot actually has
gn bot rm recon-aggressive -y
```

Each verb is one slash command inside `gn studio` (`/bots`, `/use`, `/new`, `/clone`, `/teach`,
`/train`, `/model`, `/persona`, `/hf`), with Tab completion over commands and bot names. One store,
one set of rules, two doors.

Six bots always exist: **tinygpt** (the bundled local model — no key, nothing leaves the machine,
and the default), **local** (Ollama or any OpenAI-compatible endpoint), **anthropic**, **openai**,
**offline** (the deterministic template+AST coder — it edits, it does not chat) and **off**. Edit
one and the edited copy is stored; `gn bot reset <name>` puts it back. They cannot be deleted,
because the fallback has to exist.

The store holds no **keys** (they stay in the perms-restricted `runtime/secrets.json`; `gn bot show`
reports `configured` or `none`) and no **authorization** — a file on disk cannot assert that you are
authorized, so `-y` stays the only source. A persona reaches **chat** prompts only: the hunt planner
sets its own.

**Picking a bot changes the hunt.** `gn hunt --brain` (or `hunt.brain on`) resolves the live bot
over the app's runtime config, so `gn bot use anthropic` decides which brain `hunt_brain` plans
with. A bot with no model behind it (`tinygpt`, `off`, `offline`, an inert clone) means the bounded
**offline planner**, and `--brain` says so rather than silently doing nothing. Without `--brain`
nothing is loaded at all. A `bots.json` that will not parse costs you your *selection*, never your
hunt — and is never overwritten.

**`gn bot train` runs the trainer that bot actually has.** There are two, and neither trains a
hosted model's weights: the offline hunt ranker (`hunt_train`, from the trace corpus) and TinyGPT's
own checkpoint (`gn train-coder`, which needs torch). A hosted bot trains its *ranker* and the verb
says so — claiming "trained" about an API model would be a number nobody could reproduce. A refused
gate is reported as the gate's own reason and leaves no trained stamp.

### The same bots in the app

The desktop/web app's **AI Studio** and `gn bot` are two doors onto that one store, not two stores.
A bot you make in the app is in `gn bot ls` and can be made live there; a bot you make with `gn bot
new` is in the app's roster, with its provider, its model and whether it is ready; and `gn studio`'s
BOTS panel agrees with both. Picking a bot in the app's roster goes through the same single writer
`gn bot use` does, so the app's selected bot and the `*` in `gn bot ls` are the same bot — and the
one your next `gn hunt --brain` plans with.

The app's roster used to live in the browser's localStorage, which is why none of that was true.
Three things stay in the browser, deliberately:

- **A bot's colour.** It is how one browser draws the bot — no CLI surface can use a hex triple, and
  a field every other surface has to ignore does not belong in a shared store.
- **The in-browser preference weights.** They are fitted from that browser's own chat ratings and
  memories, which never leave it, so a copy in the store would be a number nobody could reproduce
  from the store. They are also not a training run: the registry's trained stamp is written only by
  a real trainer (`gn bot train`), which is why the Studio's Model meter stopped reading them.
- **Chat history and memories**, as before.

Everything else is the store's, including what the app called a bot's **corpus** — operator prose
that shapes the bot, which is exactly what a **lesson** is, so it lives in `lessons` and shows up in
`gn bot show`. The app's **Variation** slider now speaks the store's own units (0.0-2.0, the number
`gn bot show` prints) rather than a 0-100 position, and a bot with none set reads *provider default*
instead of a number nobody chose.

The first time the app runs against this store it hands over whatever bots that browser had, **once**
— keeping the persona, the style, the corpus (as lessons), the temperature (the old slider was a
sampling temperature x100 on its only consumer, so 46 becomes 0.46) and which bot was selected. An id
the store already holds is left exactly as it is, so the handover cannot overwrite a bot you made in
the shell or duplicate anything if it runs again, and nothing deletes the browser's copy. A bot the
store refuses is named rather than dropped quietly.

The store is served by the local GreyIQ service. With the service down the app shows the last roster
it saw, says so, and takes no edits it could not save.

## Plugging in Hugging Face bots

`gn bot hf <ref>` (or `/hf <ref>`) plugs one in. The Hub hosts two different things, and they do not
get the same treatment:

```bash
gn bot hf unsloth/Qwen2.5-Coder-7B-Instruct-GGUF --use   # weights -> a runnable local bot
gn bot hf spaces/agents-course/First_agent_template      # an agent -> cloned, inert
```

- **GGUF weights** are imported into your local Ollama (its own `hf.co/` pull first, falling back to
  the verified split-GGUF importer when the repo is sharded), **probed for chat and tool calls**,
  and registered as a runnable `local` bot with the probe's verdict on its row. One that fails the
  chat probe is reported as not ready rather than quietly made live; one that chats but fails the
  tool-call probe says *chat only*, because the agent and the hunt planner need tool calls.
- **An agent repository** is cloned at a pinned, digest-verified commit (the machinery below) and
  registered **inert**: it can never become a brain, and nothing cloned is imported or executed.

Which kind it is comes from what the Hub serves, not what you typed: `spaces/` is an agent,
`--agent`/`--model` are explicit, and anything else is probed for GGUF weights — a models repo with
no GGUF falls through to the clone path and says so. `--as` names it, `--use` makes it live, `--json`
prints the result.

## Cloning Hugging Face agents

The Hub hosts agents as ordinary repositories: `smolagents` writes an
`agent.json` (class, model, tool names, prompt templates), a `prompts.yaml`, and
one Python file per tool under `tools/`. Clone one into the local agent store
from the CLI:

```bash
gn agent clone https://huggingface.co/spaces/agents-course/First_agent_template
```

The reference can be a repository page URL, a `tree/<branch>` URL you pasted
from the browser, `hf.co/spaces/owner/name`, `spaces/owner/name`, or a bare
`owner/name` (Spaces are searched first, then models). Append `@<branch|tag|sha>`
or pass `--revision` to pin an exact commit, `--as NAME` to choose the local id,
`--force` to replace an existing clone, and `--json` for the machine-readable
manifest. The other actions are `gn agent list`, `gn agent show <name>`
(`--files` for every digest, `--prompt` for the cloned `prompts.yaml`), and
`gn agent remove <name> -y`.

```
gn agent clone spaces/mrafidamin/AlfredAgent --as alfred
cloned  alfred  <-  spaces/mrafidamin/AlfredAgent
commit  299ba2dfadf84b2dbb54e712b8c6c687bb797e11
files   11 verified against Hugging Face digests
model   Qwen/Qwen2.5-Coder-32B-Instruct via InferenceClientModel
tools   6: catering_service_tool, final_answer, suggest_menu, …
trust   clean
```

**A clone is reference material, not a running agent.** Three rules hold, and
they are what make it safe to clone a stranger's agent:

- **Nothing fetched is executed or imported.** A cloned tool is someone else's
  arbitrary Python — smolagents' own `from_hub` requires `trust_remote_code=True`
  for that reason. GreyIQ reads the tool interface (name, description, inputs,
  output type, imports) statically with `ast` instead, so `gn agent show` gives
  you the full inventory without running a line of it.
- **Every byte is pinned and verified.** The revision is resolved to a commit SHA
  before the first download, and each file is checked against the git blob digest
  the Hub published for it. A digest or size mismatch refuses the whole clone and
  leaves nothing behind. Weights, binaries and non-code files are not downloaded;
  they are listed as skipped with the reason.
- **The clone's text is untrusted data.** A remote agent's prompts, description
  and tool docs are prose aimed at a model. Each clone gets a `SKILL.md` playbook
  that the coding agent and offline coder pick up like any other playbook, but it
  loads with source `cloned` and is fenced inside an untrusted-data boundary — it
  is never spliced into the system prompt the way an operator-authored playbook
  is, and an operator-authored skill of the same name wins over it. The clone's
  own prompts are also screened for injection directives, and the result is in
  the manifest and on the `trust` line above.

Clones live under `<runtime>/agents/<name>/` — `source/` holds the verified
original files, `greyiq-agent.json` the manifest, `SKILL.md` the playbook. Set
`GREYIQ_RUNTIME_DIR` to move the store. Review each agent's license and card
before reusing anything from it.

## BugHunter

See [docs/USER_GUIDE.md](docs/USER_GUIDE.md) for the full Hunt-cockpit walkthrough —
Program setup (including browsing visible programs through HackerOne, YesWeHack, and Intigriti APIs,
previewing their scope and rules, or importing a CSV/paste table; Bugcrowd uses manual or CSV intake),
local-clone source scanning (remote Git cloning currently refuses to run),
per-program SSRF/OOB setup, running a hunt, and reports & submission. The cockpit also opens
a short guided tour on first launch (reopen anytime via **🧭 Guide me** in the top bar).
When adding a HackerOne program, enter and save the API identifier and token in
the Program wizard's **Identify** step. You can test the saved connection there
before browsing programs or fetching scope; the token field is masked and cleared
after saving.

- **Assess from chat:** `scan code <local-path>` runs a local source scan. Network scans require an explicit authorization assertion and exact scope. `scan web -y --scope app.example.com https://app.example.com/` runs a scoped passive web pass. `scan active -y --scope app.example.com https://app.example.com/` starts a background proof pass with at most 16 GET/HEAD/OPTIONS requests and reports observations alongside controls. Missing or mismatched scope is refused before a request, and scoped web redirects cannot leave the host. These short web commands require whole-host permission for the methods used. For narrower policies, use the saved program workflow in the Hunt cockpit; hunts refuse restrictions the engine cannot enforce. Remote Git scans currently refuse to run because Git can fetch alternate object stores outside the named repository; scan a local clone instead. Scoped live browser scans currently refuse to run until browser DNS egress can be pinned.
- **Expert knowledge in chat:** bundled assessment cards teach hypothesis selection, differential controls, evidence calibration, stop conditions, and fix verification. Offline replies quote source-labelled excerpts. A configured reasoning brain receives at most two brief, source-labelled excerpts as reference data; they never count as target evidence or testing authorization.
- **Unauthenticated ATO and RCE, including the blind half.** The active prover confirms command
  injection the target echoes back or delays; with an OOB collaborator configured, a hunt also
  proves the blind kind — a shell-wrapped callback in parameters *and* in the request headers that
  reach a shell without any parameter existing. A hit is only called RCE when a matched control
  carrying the same URL as a bare value stays silent, so an app that merely fetches URLs is
  reported as that instead. On the takeover side the prover forges `alg:none`, RS→HS confusion, a
  cracked weak HMAC secret and a self-signed `jwk` embedded key against the token the site hands an
  ANONYMOUS visitor (no session needed), and the collaborator additionally proves `jku`/`x5u`
  key-source injection — the verifier fetching a signing key the token itself named.
- **Leads** — after a hunt finishes, the **Leads** button in the Hunt cockpit's export row renders
  the whole investigation queue in the app: every lead with its evidence state, the exact artifact
  that would confirm it, the predicted result, a matched negative control, a stop condition,
  the gaps still open, and anything the engine says contradicts it. These predictions do not
  grant permission or count as proof. The same
  panel downloads it as one Markdown brief — that file is what you hand to an analyst (or paste to
  Claude) to work the leads. (A *Download leads (.md)* button also exists in the AI Studio surface;
  the cockpit is where a hunt actually runs, which is why the queue is rendered there.)
- **Investigate leads with Claude**: `gn leads <bounty-*.json | engagement-folder>` exports a
  finished hunt's ranked investigation queue — the cortex's hypotheses, ordered attack chains,
  contradictions, and the exact proof obligation for each lead — as a stable, **redaction-safe**
  `greyiq-lead-queue-v1`. Each lead carries its own evidence state, the contradictions that cite it,
  and the chains it belongs to, inline. `--json` emits the machine queue; `--brief` renders a
  Markdown investigation brief wrapped as untrusted data, ready to hand to a configured Claude brain
  (or to Claude Code) to work lead by lead; `--status` / `--ref` / `--min-confidence` filter it. It
  is assembled from a strict field allowlist and scrubs every field, so no raw credential, response
  body, page source, or screenshot path ever leaves the machine — only the differential and the
  safe sensitive-data labels.
- **OSINT campaigns from the local CLI**: `gn osint example.com` correlates two public
  certificate-transparency indexes with Google and Cloudflare DNS, keeps claim-level source
  provenance, and writes `OSINT.md` + `osint.json`. Add `--hunt --scope "*.example.com" -y`
  to pass only independently DNS-verified public hosts into the normal BugHunter campaign;
  OSINT discovery never grants authorization.
- **Bug-bounty hunt** (training panel): pick a profile (Web app / API / Source-code /
  Secrets / Full sweep) and an optional vuln-class focus (XSS, SQLi, SSRF, IDOR/access
  control, auth, RCE, secrets). GreyIQ runs the right scanner, the brain writes
  reproduction steps + attack plans, and a Markdown report (+ JSON sidecar, optional
  per-finding files) is written to a folder you choose. **Authorized testing only** —
  a hunt won't run unless you confirm the target is in scope.
- Submission packages include a concise, plain-language `.md` body for the platform's
  description field. The `.details.md` analyst report and `.json` sidecar retain the
  metadata, proof state, limitations, and evidence for review. The operator checks
  captured artifacts and the current program policy before submitting.
- Bounty reports now add triage, class mix, submission-readiness checks, and an
  **Investigation intelligence** brief: calibrated confidence, typed evidence state,
  explicit proof gaps, contradiction detection, a ranked hypothesis queue, and
  correlated attack-chain leads. The same graph is available in the JSON sidecar and
  hunt API.
- **Theorizing, not just scanning.** The hypothesis queue is ranked by *expected information
  gain* — how much a test would collapse the unknown, and how many attack chains rest on it —
  so the top lead is the one worth testing next rather than merely the biggest number. GreyIQ
  also derives theories no single finding shows: three routes sharing one weakness on one
  property is reported as a control missing at the framework layer, clearly marked as derived
  and routed to the "worth testing" queue rather than presented as a result. Each lead names
  the chains that confirming it would complete.
- **Acting on it.** Set `GREYIQ_HUNT_REPLAN=1` to let a finished pass chase its own strongest
  unresolved lead: the engine turns each proof obligation into a concrete (endpoint, class)
  probe and runs one bounded extra wave through the same scope- and SSRF-gated prover, capped
  at three endpoints and eight requests. It confirms nothing on its own — the captured-artifact
  gate still decides — and it is off by default because it spends real requests. Reports also include retest guidance and platform-friendly one-file-per-finding
  exports. Reports reshape for
  HackerOne, YesWeHack, Bugcrowd, Intigriti, and **HackenProof** (web3: exchanges, protocols,
  smart contracts) — pick the format in Submissions. HackerOne is the only live-API submit;
  the rest, HackenProof included, are export-only (HackenProof has no researcher API — you
  submit on its dashboard). Focus classes also cover CSRF, CORS, open
  redirect, unsafe file upload, business logic, and supply-chain/dependency risk.
- **Negative knowledge** — GreyIQ remembers what it already probed and did **not** confirm. A
  planned `(endpoint, class)` that yields nothing becomes a *miss*; after two misses the pair is
  downranked on the next hunt so the capped probe budget goes to surface that has never been looked
  at, instead of re-testing inert ground. It can never blind a hunt: anything ever confirmed is
  immune forever, misses decay after 45 days, a pair is re-enabled the moment **surface drift**
  reports its endpoint changed, and suppression only reorders (dropping an endpoint only when every
  class on it is cooled). Set `GREYIQ_NO_NEGATIVE_KNOWLEDGE=1` to turn it off. **Campaigns share this
  memory too** — they read cooled pairs, hunt what surface drift says moved first, and write both
  memories back, so the unattended mode stops re-testing ground it has already exhausted. A miss is
  only ever learned from a campaign that finished its fan-out with every per-URL pass running clean,
  and anything the prover confirmed is banked before the report's own filters can hide it.
- **Each target teaches the next.** Within a campaign, a class confirmed on one URL moves to the
  front of the probe order for the URLs not yet hunted on the same registrable domain — so a proven
  IDOR on one object endpoint is a reason to try IDOR on its siblings. A matched CVE advisory does
  the same job earlier: the component fingerprint now runs *before* the active pass and maps each
  advisory's CWE to the class the prover can confirm, so an outdated jQuery aims the prober at
  reflected XSS. Both only reorder; the differential prover still owns every confirmation, and a
  version match never becomes a finding by itself.
- **Blind findings confirm themselves in an auto hunt.** With an OOB collaborator configured
  (the `/oob` endpoint on your own greynoc-chat host), a hunt can prove the four classes that
  reflect *nothing* in the target's own response — blind SSRF, XXE-over-HTTP, blind RCE, and
  `jku`/`x5u` JWT key injection, which is unauthenticated takeover. Previously only the cockpit's
  single-target scan passed the collaborator in, so **every campaign and every unattended operator
  cycle ran with it inert**; now the campaign path carries it too, gated on the program's own
  `oob_allowed` flag ("this program's policy permits out-of-band testing"). That flag was stored,
  normalized and served over HTTP while nothing read it — this is what reads it, so arming the
  collaborator stays a per-program operator decision and never a global switch.
- **The money loop closes itself.** An auto hunt already learned from its own observations —
  negative knowledge cools an `(endpoint, class)` pair after two misses, and class priors reweight
  from its own confirmations. What it could not learn was **what pays**: at submit time the engine
  records `status="submitted"`, which the priors deliberately discard, so payout weighting stayed
  empty however long the operator ran. Now the operator **syncs adjudicated outcomes once per pass**
  (read-only GETs for reports GreyIQ itself filed, capped per pass, closed reports never re-polled)
  *before* it hunts, so the same cycle's ranking sees the fresh verdict — and it then **hunts the
  programs that have actually paid first** instead of alphabetically, and **retrains the offline
  ranker** from the corpus it is growing (the trainer's own gate refuses a corpus too small or a
  model that doesn't beat the rules). `gn sync` does the same pass by hand.
- **Set it up once** — `gn setup` writes the operator profile: the live bot (`tinygpt`, GreyIQ's own
  local model, by default — no key, nothing leaves the machine; the wizard offers whatever is in
  your bot store), learning on, the default hunt
  profile, whether active verification is armed by default, and where reports go. ENTER through
  every question is a valid way to answer it, and `gn setup --defaults` writes exactly that without
  asking (for scripts, CI and containers). `gn settings` lists every setting with its value, where
  that value came from, and the commands that change it; `gn settings set hunt.profile api` saves
  immediately. A verb then reads the profile for anything you did **not** type, so a flag you do
  type always wins — including when you type the default — and no setting can turn an armed flag
  off. `learning off` genuinely stops the automatic writing: no hunt trace, no surface baseline, no
  negative knowledge, no auto-retrain (an explicit `gn learn` or `gn train-brain` is still yours to
  run). A stored value that cannot be honoured is named rather than silently replaced by its
  default. `bot` has one writer (`gn bot use`, which `gn settings set bot`, `gn setup` and the
  studio's `/set bot` all route through), so a bot that does not exist is refused at every door
  instead of being parked in the profile. **The profile cannot authorize
  anything** — there is no such setting, unknown keys are refused, and a hand-edited
  `"authorize": true` does nothing: a file on disk may not assert that a human is authorized.
  Secrets stay in the perms-restricted store, never in the profile.
- **One line to hunt** — `gn hunt <target>` with no other flags: the profile supplies the posture,
  `-y` supplies the target's scope, and on a terminal the authorization question is **asked** (it
  names the target, and answering it is the same attestation as `-y`). `gn auto hunt -s acme.example`
  is the scope form — no directory, no target list: each host in the scope seeds an `https://`
  target, it becomes a saved program so the learning memory accumulates, and the hunt asks for a
  session when it reaches a login wall. `--json`, `--no-prompt` and a non-terminal still require
  `-y` outright, because there is nobody there to ask.
- **Where reports go** — `gn output --path D:/reports` sets the default; `gn output -s acme.example
  --path D:/engagements/acme` sends that host (and its subdomains, unless they have their own entry)
  somewhere of its own; `gn output` lists what is set and `--clear` drops one. `-o` on a single run
  still wins. It applies to **every** report writer, including `gn campaign` and `gn auto`, which
  have no `-o` of their own. A configured folder keeps the same rule `-o` has: it may create its
  own leaf, never a brand-new multi-level tree, so a saved report folder cannot become a
  write-anywhere primitive — a path that fails that falls back to `runtime/reports`, and the path
  printed at the end of a run is always the one actually written to.
- **The dash** — `gn dash` opens the **threat board** in standby: the same full-screen map a hunt
  flies arcs across, with nothing running and a command line under it. Type `/hunt <url> -y` and the
  board hands off to the real hunt (so the arcs are the engine's own), the summary and report path
  land in your scrollback, and ENTER brings standby back; `q` leaves. `/panels` (or `gn dash
  --panels`) switches to the **panel cockpit** — TARGETS / FINDINGS / RATE / LOG, an OUTPUT pane,
  `/usage`, and every `gn` verb typed inside it. `gn dash <target> -y` and `gn dash --attach` still
  open the panel cockpit over one specific run. The board needs a 74x24 terminal and draws on
  stderr; anything narrower says so and names `--panels`. `gn fx wopr` replays the board's demo if
  you just want to check a terminal.
- **The agent studio** — `gn studio` (also `/studio` from the board, or `gn dash --studio`) is the
  third view of the same cockpit, in the same amber: **your bots — make them, teach them, train
  them, pick one, talk to it.** BOTS lists every bot, the live one marked `*`, with what each could
  do right now (`ready`, `needs a key`, `needs a model`, `inert`). BRAIN resolves that bot against
  the app's runtime config, so the provider and model shown are the ones the **hunt** will use (the
  key row says *configured* or *none*, never the key). LEARNING reads the hunt-trace corpus, bounty
  outcomes, cooled endpoint/class pairs, the offline ranker and the tiny model's corpus. A store
  that will not answer renders `--` with the reason, never a zero. Every bot verb is one slash
  command (see [Your bots](#your-bots)); `/settings`, `/set` and `/unset` write through the same
  profile `gn settings set` does; `/board`, `/panels` and `/studio` switch views and `/refresh`
  re-reads every store. **Who answers a typed question is whichever bot is live**, and the line
  under every answer says which: `tinygpt`, `offline` and cloned agents quote the bundled playbook
  pack verbatim with its source path (`solin_domain` generates nothing, so a chat window on a
  security tool cannot invent a security claim), while a `local`/`anthropic`/`openai` bot is
  **called** with its persona and lessons as the system prompt and its answer is labelled as a
  model's. Opening the studio still sends nothing — no model call happens on the repaint path, only
  on a question you typed. A bot that sends off this machine is marked `->net` in the header, and
  `/pack <q>` asks the offline pack regardless.
- **The board during a hunt** — it fills the terminal now, and takes keys while the run is going:
  `l` the full engine log (PgUp/PgDn to scroll), `f` the findings as they are confirmed, `r` the
  live request traffic (method, host, path, status), `b`/Esc back to the map, `q` to stop the hunt
  at the next safe point rather than killing it mid-probe. A reticle closes on whichever asset the
  prover is hitting, a sparkline on the status bar shows the request rate per second, and DEFCON
  flashes when it drops. Every one of those is driven by something the engine reported — the
  traffic feed is taken at the one chokepoint every active request goes through.
- **`-y` is sudo for the target you named.** `-y/--authorize` now puts that target in scope itself,
  so `gn hunt https://acme.example -y` is the whole command — no `-s acme.example` repeating what
  you just typed, and no refusal for forgetting it. The grant is exact (the host, or the repository
  root) and additive: your own `-s` text is kept, a `*.` wildcard is never invented, a host the
  engine *discovers* mid-run still has to be in scope on its own, and a saved program's exclusion
  still wins. Without `-y` nothing widens — the flag is the attestation. Use `-s` for anything
  *beyond* the target, e.g. `-s '*.corp.example'`.
- **Hunt a directory** — `gn auto -y` in a repo or a hunt folder. It reads
  the targets from `.greyiq/targets.txt` (one per line, `#` comments) or `.greyiq/hunt.json`; in a
  git repo with no targets listed, the **repository itself** is the target and its remote is the
  scope. Scope comes from `.greyiq/scope.txt`, else the hunt file, else it is **derived** from the
  targets' apexes and labelled as derived. The folder becomes a saved program, so negative
  knowledge, priors, surface drift and the ledger accumulate across runs (`--dry-run` to see the
  plan first, `--passive` to never arm active probing). **Authorization is never read from the
  directory** — a file on disk cannot assert that you are authorized, so `-y/--authorize` stays the
  only source, and a hunt file that tries to set it is refused out loud. With a scope established it
  also arms the **theorize → act** re-plan wave, so an auto hunt chases its own strongest unresolved
  lead instead of being one flat pass. `-y` buys **one reviewed cycle**; to let the scheduler keep
  re-hunting the directory unwatched, add `--grant-file` — the same auditable per-program
  authorization record `gn operator run` requires, since `-y` alone cannot stand in for one.
- **Import a Shannon run** — `gn shannon <run-dir|workspaces-dir|report.sarif>` imports a finished
  [Shannon](https://github.com/KeygraphHQ/shannon) pentest as GreyIQ candidates. Shannon is an
  external autonomous engine you run yourself (it is not bundled, and it needs Docker + WSL2 on
  Windows); GreyIQ reads the `report.sarif` it leaves behind. Everything arrives as a **candidate
  tagged `source: shannon`**: Shannon's own `exploited` verdict is kept as provenance but is never
  a proof state, because GreyIQ's prover never saw that target — so an imported finding cannot
  reach the live-submit path, enforced in `report._has_captured_artifact` and
  `submission.submit_to_hackerone`. Each candidate carries the exact proof obligation that would
  confirm it, and the class is resolved only from Shannon's validated SAST CWE or an unambiguous
  class; `injection` deliberately abstains rather than inflate into RCE. Shannon's exploitation
  steps and proof-of-impact are **not** imported — they carry captured tokens and exfiltrated data
  by design. See [docs/shannon-integration.md](docs/shannon-integration.md).
- **Agent security test** — red-teams GreyIQ's own agent in a throwaway sandbox
  (sandbox/policy probes always; opt-in prompt-injection + jailbreak behavioral probes)
  and reports a posture verdict.

## Local Security Defaults

GreyIQ binds local services to `127.0.0.1` by default. Set `GREYIQ_HOST`
or `HOST` only when you intentionally want another interface.

The Python API rejects browser requests whose `Origin` does not match the
running service. If you intentionally serve a separate trusted frontend, set
`GREYIQ_ALLOWED_ORIGINS` to a comma-separated list such as
`http://127.0.0.1:4173`.

Every `/api/*` call (except the health check) requires a **per-session token** the
backend mints at startup and injects into the page it serves — so another local
process on `127.0.0.1` can't drive the API (allowlisted cross-origin frontends are
exempt). Request bodies are capped (`GREYIQ_MAX_REQUEST_BYTES`, default 16 MB).
**API keys are kept in a permission-restricted `secrets.json`**, separate from the
main config and migrated out of it on first run, and are never sent back to the UI.
The agent's `run_command` stays **off by default**, and even when enabled a denylist
refuses catastrophic commands (`rm -rf`, disk formats, pipe-to-shell, power control,
privilege escalation, …).

Local code scans can be restricted to one folder with
`GREYIQ_CODE_SCAN_BASE_PATH`. Remote repository URLs are recognized but refuse to clone until the Git transport can be constrained to the authorized source; provide a local clone. Web scans refuse private/loopback hosts unless
`GREYIQ_SCAN_ALLOW_PRIVATE_URLS=1`; scoped browser scans currently refuse to run.

Fixed third-party egress is narrow and documented. HackerOne import/submission uses
`api.hackerone.com` only on its corresponding operator action. YesWeHack program search,
scope import and sign-in use `api.yeswehack.com` the same way — read-only apart from the
sign-in exchange, on an explicit click only, host-pinned, and with redirects refused so a
credential can never follow a hop off that host. Intigriti program intake uses
`api.intigriti.com` for explicit read-only program discovery and previews. Bugcrowd
programs use manual or CSV intake. Imported programs are saved paused until you review
the current policy and authorize testing. The optional **Enrich from
forge (read-only)** action uses one unauthenticated GET per selected repository to
`api.github.com` (GitHub) or `gitlab.com` (GitLab); it has a hard timeout, never runs in the
background, and only returns homepage/web domains as **unticked** scope suggestions. Enrichment
never authorizes or probes those hosts. Other supported forges are not queried for metadata.

## How Training Works

Each bot owns browser-side preference weights for instant fallback behavior. When the GreyIQ backend is running, preferences, rated examples, and source-specific training data are also written into the local runtime training data. The trainer can run against one or more selected sources, and the AI core store tracks the active bot as a local core. Data stays on the machine unless you explicitly move it.

## AI Cores

GreyIQ starts with companion, builder, researcher, and BugHunter cores. Each core carries a response contract, confidence policy, trust posture, and starter knowledge profile so first-run answers feel useful before personal training begins. Personal choices and imported documents become higher-priority local sources as the user trains the app.
