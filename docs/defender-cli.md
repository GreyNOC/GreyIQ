# GreyIQ Defender CLI

`gn` now provides one command line for source/web bug discovery (`gn scan`,
`gn hunt`) and local endpoint monitoring (`gn defend`). The defender commands
run on the machine where `gn` is installed. They do not require the desktop
service or a cloud account.

## First run

```bash
gn defend status
gn defend inventory
gn defend inventory --path /etc --json
gn defend inventory --hash-processes
```

Inventory is read-only. It reports the host, processes, sockets, interfaces,
routes, services, startup entries, installed packages, and collection coverage
where the operating system permits. An explicit `--path` adds a bounded file
integrity map of that file or directory. Collection errors are part of the
result. A missing field or permission-limited probe is not a clean bill of
health.
`--hash-processes` hashes observed executable files on disk within fixed file,
count, and total byte limits. It records which binaries could not be hashed.
This is an opt-in disk read, and the hash describes the file at collection time,
not necessarily the bytes loaded in a running process.

After an operator has reviewed a known-good host state, create the reference
snapshot:

```bash
gn defend baseline create --accept-current-state --path /etc
gn defend baseline show
gn defend baseline compare
```

`baseline create` is deliberately explicit: a newly installed CLI cannot know
that the current machine is safe. It refuses to overwrite a baseline unless
`--replace` is given. Replacement saves a private, content-addressed copy of
the prior validated baseline beside the active baseline before publishing the
new one. Scan artifacts and events record the exact baseline inventory digest,
so historical evidence can be matched to its reference. Archive these files
together. `compare` and `scan` reuse the file roots recorded in the
baseline. A comparison refuses a different set of file roots so it cannot
claim that uncollected files disappeared. Differences are review
indicators; they do not by themselves prove malware or compromise.

## Scan and watch

```bash
gn defend scan
gn defend scan --hash-processes
gn defend watch --interval 60
gn defend watch --interval 60 --iterations 10 --json
gn defend events --limit 50
```

`scan` takes a fresh inventory, compares the reference, evaluates local
indicator rules, and appends a structured event to the local defender journal.
`watch` repeats that cycle until interrupted, or until `--iterations` is
reached. It requires a reviewed baseline. `--json` on `watch` emits one JSON
object per cycle, suitable for a local log collector.
Rules also correlate new or changed non-loopback listeners with newly observed
executable paths, and changed startup or service definitions with running binaries in
staging directories. These correlations narrow a review lead; they do not
identify an intruder. Listener rules require an observed TCP `LISTEN` socket.
When an authorized TShark capture includes TCP flag metadata, a rule flags a
short SYN-only burst from one public source across at least eight ports on an
exactly inventoried local IP. This is a port-probe lead, not evidence of access.
Encapsulated traffic can make flattened TShark fields ambiguous, so review the
saved metadata and surrounding network context before acting on that lead.

To inspect the local process associated with an observed socket:

```bash
gn defend trace --pid 1234
gn defend trace --remote 192.0.2.10 --json
```

The trace relates a local PID to process and socket metadata available at the
time of collection. It cannot determine the identity of a remote person or
threat actor. PIDs and sockets are short-lived, so preserve the relevant
timestamp and repeat collection when investigating a lead.

## Optional network tools

Nmap and TShark are optional executables installed and maintained by the
operator. `gn defend status` reports whether each is on `PATH`. Passive host
inventory and baseline monitoring work without them. Both integrations are
bounded and must be requested explicitly:

```bash
gn defend scan --nmap-target 192.168.1.10 --scope 192.168.1.10 -y
gn defend scan --capture-interface eth0 --capture-seconds 10 --packet-limit 500 -y
```

The Nmap adapter accepts only a literal private/local IP or CIDR within the exact
authorized host or CIDR scope, at most 16 addresses. It checks a fixed, limited
set of TCP ports without scripts or version probes. The TShark adapter captures packet **metadata**
only, in non-promiscuous mode, with a duration and packet limit; it does not
save packet payloads or a PCAP by default. A watch that repeats Nmap is
restricted to intervals of at least five minutes. If a tool is unavailable or
cannot run, the result records that limitation.

The `-y` flag is an operator assertion that the named network or interface is
authorized for this assessment. Private addressing alone is not authorization.
Do not use these flags on a third party's network or on a segment with unclear
scope. Stop a capture or scan if an unexpected block or out-of-scope system
appears.

## Indicator references

`gn defend rules` lists the bundled local detection rules and their evidence
requirements. Rules draw on GreyNOC [HomeGuard](https://github.com/GreyNOC/HomeGuard)
concepts such as risky exposed services, new devices/listeners, and changes to
trusted state. GreyIQ reports these as indicators with context and limitations.
They are not malware signatures or proof of actor identity. HomeGuard itself is
an optional, separate engine; its Python dependencies are not required for the
bare-Python `gn` install.
The integration was checked against HomeGuard revision
`47dd57e073170bf38b236562e81790e510c9a503` and its
[MIT license](https://github.com/GreyNOC/HomeGuard/blob/47dd57e073170bf38b236562e81790e510c9a503/LICENSE).
GreyIQ imports that package only when this optional command is called; no
HomeGuard source is bundled in this change.

With HomeGuard installed separately, `gn defend homeguard devices.json` can
evaluate an existing, authorized device export using HomeGuard's own detection
engine. The file is a JSON array of device records, or an object with a
`devices` array. `--homeguard-baseline FILE` points to a HomeGuard device
baseline, which is distinct from GreyIQ's host baseline. This command does not
discover devices or fetch threat feeds. HomeGuard may initialize its local
definition cache on first use.

For a reviewed indicator list, pass `--indicators FILE` to `scan` or `watch`.
The JSON object needs `source`, `url`, `retrieved_at`, `expires_at`, and an
`indicators` array of `{ "type": "ip|domain|sha256", "value": "..." }` records.
The source URL and freshness dates provide provenance; the CLI does not fetch
or silently refresh a feed. Exact matches are leads
for investigation, not automatic attribution. Do not treat an unverified feed
as authorization to scan the systems it names.
When a reviewed indicator file includes SHA-256 values, `scan` and `watch`
automatically enable the bounded process executable hash collection, so those
indicators can match running binaries. File SHA-256 indicators match only
explicitly watched roots and process binaries successfully hashed on disk.
Normal host inventory and TShark capture record IP addresses, not DNS names;
domain indicators only match when an input observation already contains a
hostname. The CLI does not resolve domain indicators into IPs.
Process executable digest drift requires successful hashes in both the baseline
and current observation. Service and startup definition SHA-256 digests detect
changes without retaining raw launch commands; a digest of a guessable command
is not a confidentiality control, so protect snapshots as sensitive metadata.

The journal and baseline live under `GREYIQ_RUNTIME_DIR/defender` when that
environment variable is set. By default, standalone Windows and macOS CLI
commands use the per-user GreyIQ data directory (`%APPDATA%\GreyIQ\runtime` on
Windows or `~/Library/Application Support/GreyIQ/runtime` on macOS), matching
the packaged desktop's data location. Linux release binaries use the XDG data
directory; a Linux source checkout uses its `runtime` directory. `gn defend
status` prints the actual path. A managed Windows roaming profile may sync
`%APPDATA%`; set `GREYIQ_RUNTIME_DIR` to a restricted local directory when
that is inappropriate.
These files contain local system metadata. Limit access to the operator and
protect them in backups and support bundles. POSIX files use owner-only modes;
on Windows, the files inherit the runtime directory's ACL, so choose a
directory restricted to the operator account. `gn defend events --verify`
checks the journal chain and its head checkpoint for corruption or truncation.
`gn defend events --verify-artifacts` also checks every linked run artifact's
SHA-256 against its journal reference. This can take time when the journal is
large.
The chain cannot prove that an attacker with write access to both files did not
rewrite them.

## Live defender dashboard

```bash
gn defend dash
gn defend dash --capture-interface eth0 --capture-seconds 3 --packet-limit 500 -y
gn defend dash --baseline /path/to/reviewed-baseline.json --indicators /path/to/reviewed-iocs.json
```

`dash` opens a full-screen terminal board with observed local ports, socket
owners, packet metadata, and current detector findings. It refreshes after each
completed scan plus `--interval` seconds (default 5). The board is green while
no rule has emitted a finding in this session. A finding turns it red and the
red review state remains visible for the session, even if a later cycle no longer
matches. Red means suspected activity requiring investigation; it never claims
that an intrusion or a person has been identified. The board shows when there
is no reviewed baseline or when inventory coverage is partial.

Packet capture is opt-in. Name one exact local interface and supply `-y` only
for an authorized assessment. The capture is non-promiscuous, lasts at most 30
seconds per cycle, and stores timestamps, addresses, ports, protocol, TCP SYN
and ACK flags, and frame length. It does not save packet payloads or PCAPs.
The in-memory search buffer holds at most 2,000 packet records; the scan
artifact and journal preserve each completed cycle. A missing or failed network
tool pauses automatic scans and leaves its error visible. Press `r` to retry.

Press `/` to filter packet metadata by a case-insensitive substring (IP, port,
protocol, timestamp, length, or TCP flag), `Enter` to apply, and `Esc` to cancel.
`Tab` switches between ports and packets; arrow keys inspect a row in detail.
Press `x` to clear the filter, `r` to scan again, or `q` to quit. The dashboard
requires an interactive terminal; use `gn defend watch --json` for a log
collector. Repeated Nmap scans require an interval of at least five minutes.

## Evidence retention

Full compressed observations are kept under `runtime/defender/runs` and linked
from journal records by runtime-relative path and SHA-256 (the original absolute
path is also retained for immediate access). Verification still works after the
complete `defender` directory is copied to a different runtime. To avoid
silently filling a disk,
collection stops at 10,000 run artifacts, 512 MiB of run artifacts, or when
free disk space falls below 128 MiB. It does not delete referenced evidence.
Archive the entire `defender` directory together, then use a fresh
`GREYIQ_RUNTIME_DIR` to start a new journal and baseline.
If a power loss interrupts an event append between the journal write and its
head checkpoint, verification may fail closed. Preserve the entire directory
for review and start a fresh runtime; do not delete or rewrite the old evidence
in place.

## QA and operational limits

Run the relevant regression suite before distributing a build:

```bash
python -B -m pytest -q backend -k defender
python -B -m pytest -q backend/test_gn_cli_stdlib_boot.py
npm run check
```

The collector is bounded and permission-aware. It cannot inventory every file,
inspect memory, decrypt traffic, confirm ransomware, or guarantee that a host is
clean. File integrity checks include only explicit paths. Packet inspection is
metadata-based, and encrypted payloads are not inspected. Investigations need
corroborating endpoint, network, and operator evidence before escalation.
