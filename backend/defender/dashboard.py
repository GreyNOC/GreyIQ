"""Interactive, local defender signal board over the existing evidence-producing scan.

Only bounded packet metadata reaches this screen. The scan owns inventory,
detection, capture authorization, artifacts, and the append-only event journal.
"""

from __future__ import annotations

import re
import sys
import time
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import dataclass, field
from typing import Any, Callable

import gn_tui


_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")
_PACKET_HISTORY = 2000


def _safe(value: Any, limit: int = 160) -> str:
    """Remove terminal controls and wide/untrusted characters before sizing rows."""
    plain = _CONTROL.sub(" ", str(value if value is not None else ""))
    return plain.encode("ascii", "replace").decode("ascii")[:limit]


def _port(value: Any) -> str:
    return str(value) if type(value) is int and 0 <= value <= 65535 else "-"


def _count(value: Any) -> str:
    return str(value) if type(value) is int and value >= 0 else "-"


def _packet_text(packet: dict[str, Any]) -> str:
    source = f"{_safe(packet.get('source'), 48)}:{_port(packet.get('source_port'))}"
    destination = f"{_safe(packet.get('destination'), 48)}:{_port(packet.get('destination_port'))}"
    return (f"{_safe(packet.get('timestamp'), 25)[11:23]:12} "
            f"{_safe(packet.get('protocol'), 8).upper():5} "
            f"{source:28.28} > {destination:28.28} "
            f"{_count(packet.get('length')):>5}B")


@dataclass
class BoardState:
    capture_enabled: bool = False
    cycle: int = 0
    busy: bool = False
    stopped: bool = False
    baseline: bool = False
    message: str = "Waiting for the first local observation"
    collected_at: str = ""
    ports: list[dict[str, Any]] = field(default_factory=list)
    packets: deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=_PACKET_HISTORY))
    findings: list[dict[str, Any]] = field(default_factory=list)
    alert_latched: bool = False
    query: str = ""
    search_original: str = ""
    search_mode: bool = False
    focus: str = "packets"
    selected_port: int = 0
    selected_packet: int = 0
    artifact: str = ""
    coverage_error: bool = False

    def ingest(self, result: dict[str, Any]) -> None:
        observation = result.get("observation") or {}
        connections = observation.get("connections") or []
        self.ports = sorted(
            [row for row in connections if isinstance(row, dict) and
             type(row.get("local_port")) is int and 0 <= row["local_port"] <= 65535],
            key=lambda row: (str(row.get("state") or "").upper() != "LISTEN",
                             str(row.get("protocol") or ""), int(row["local_port"]),
                             str(row.get("local_address") or "")),
        )
        capture = (result.get("tools") or {}).get("tshark") or {}
        for packet in capture.get("packets") or []:
            if isinstance(packet, dict):
                self.packets.append(packet)
        self.findings = [row for row in result.get("findings") or [] if isinstance(row, dict)]
        self.alert_latched |= bool(self.findings)
        self.baseline = bool(result.get("baseline_sha256"))
        self.coverage_error = bool((result.get("inventory") or {}).get("errors"))
        self.artifact = _safe((result.get("artifact") or {}).get("artifact_path"), 250)
        self.collected_at = _safe(result.get("at"), 32)
        self.cycle += 1
        self.busy = False
        self.selected_port = min(self.selected_port, max(0, len(self.ports) - 1))
        self.selected_packet = 0
        if capture and not capture.get("ok"):
            self.stopped = True
            self.message = f"Capture stopped: {_safe(capture.get('status') or capture.get('error'))}"
        elif any(not row.get("ok") for row in (result.get("tools") or {}).values()):
            self.stopped = True
            self.message = "Network tool failed; automatic scans stopped. Press r to retry."
        else:
            self.message = f"Cycle {self.cycle} logged | {len(self.ports)} socket(s) | {len(self.packets)} packet(s) buffered"

    def matching_packets(self) -> list[dict[str, Any]]:
        packets = reversed(self.packets)
        needle = self.query.casefold().strip()
        if not needle:
            return list(packets)
        return [row for row in packets if needle in " ".join(
            _safe(row.get(key), 100) for key in ("timestamp", "source", "destination",
                                                 "source_port", "destination_port", "protocol",
                                                 "length", "tcp_syn", "tcp_ack")
        ).casefold()]

    def selected_detail(self) -> str:
        if self.focus == "ports" and self.ports:
            row = self.ports[min(self.selected_port, len(self.ports) - 1)]
            return (f"SOCKET {_safe(row.get('protocol')).upper()} "
                    f"{_safe(row.get('local_address'))}:{_port(row.get('local_port'))} "
                    f"{_safe(row.get('state'))} PID {_count(row.get('pid'))} "
                    f"REMOTE {_safe(row.get('remote_address'))}:{_port(row.get('remote_port'))}")
        matches = self.matching_packets()
        if matches:
            row = matches[min(self.selected_packet, len(matches) - 1)]
            return (f"PACKET {_safe(row.get('timestamp'))} | {_safe(row.get('protocol')).upper()} "
                    f"{_safe(row.get('source'))}:{_port(row.get('source_port'))} > "
                    f"{_safe(row.get('destination'))}:{_port(row.get('destination_port'))} | "
                    f"{_count(row.get('length'))} bytes | SYN {row.get('tcp_syn')} ACK {row.get('tcp_ack')}")
        return "No packet selected. Capture metadata with --capture-interface IFACE -y."


def _row(text: str, width: int, vertical: str) -> str:
    inner = max(0, width - 4)
    clean = _safe(text, max(160, width * 2))[:inner]
    return f"{vertical} {clean.ljust(inner)} {vertical}"


def _border(title: str, width: int, left: str, right: str, horizontal: str) -> str:
    label = f" {title} " if title else ""
    return left + label + horizontal * max(0, width - len(label) - 2) + right


def render(state: BoardState, size: gn_tui.Size, tier: dict[str, Any] | None = None,
           *, color: bool = True) -> list[str]:
    """Produce a complete, bounded frame; red is a latched review signal."""
    width, height = size
    if width < 78 or height < 22:
        return ["Resize terminal to at least 78 columns x 22 rows"[:max(0, width)]]
    glyphs = (tier or {"box": ("+", "+", "+", "+", "-", "|", "+", "+")})["box"]
    tl, tr, bl, br, h, v, lt, rt = glyphs
    bright, mid, dim = ((196, 160, 52) if state.alert_latched else (46, 34, 22))
    rows: list[tuple[str, str]] = []

    def add(text: str, shade: str = "mid") -> None:
        rows.append((_row(text, width, v), shade))

    def divider(title: str) -> None:
        rows.append((_border(title, width, lt, rt, h), "bright"))

    rows.append((_border(" GREYIQ // DEFENDER SIGNAL GRID ", width, tl, tr, h), "bright"))
    if state.alert_latched:
        signal = "[!] SUSPECTED ACTIVITY // INVESTIGATE THE EVIDENCE"
    elif state.cycle:
        signal = "[+] MONITORING // NO INDICATORS IN THIS SESSION"
    else:
        signal = "[.] INITIALIZING // WAITING FOR OBSERVATION"
    add(f"{signal}                                      CYCLE {state.cycle:04d}", "bright")
    coverage = "BASELINE ACTIVE" if state.baseline else "NO REVIEWED BASELINE"
    if state.coverage_error:
        coverage += " / PARTIAL COVERAGE"
    capture = "CAPTURE ON" if state.capture_enabled else "CAPTURE OFF"
    add(f"{_safe(state.message, 55)}  |  {coverage}  |  {capture}  |  "
        f"{state.collected_at or 'NO SNAPSHOT YET'}", "bright" if state.stopped else "mid")
    divider(f"LOCAL PORTS [{len(state.ports)}]")
    add("    PROTO  LOCAL ADDRESS:PORT                 STATE          PID   REMOTE", "dim")
    port_height = min(10, max(4, (height - 13) // 2))
    port_start = max(0, state.selected_port - port_height + 1)
    for index in range(port_start, port_start + port_height):
        if index < len(state.ports):
            row = state.ports[index]
            marker = ">" if state.focus == "ports" and index == state.selected_port else " "
            add(f"{marker}   {_safe(row.get('protocol'), 5).upper():5}  "
                f"{(_safe(row.get('local_address'), 34) + ':' + _port(row.get('local_port'))):34.34} "
                f"{_safe(row.get('state'), 13):13} "
                f"{_count(row.get('pid')):>6}  "
                f"{_safe(row.get('remote_address'), 26)}", "bright" if marker == ">" else "mid")
        else:
            add("    ... no additional observed sockets ..." if index == 0 else "", "dim")
    divider(f"PACKET STREAM [{len(state.packets)} buffered | {len(state.matching_packets())} matches]")
    add("    TIME         PROTO  SOURCE                       DESTINATION                    SIZE", "dim")
    packet_height = max(1, height - 13 - port_height)
    matches = state.matching_packets()
    packet_start = max(0, state.selected_packet - packet_height + 1)
    for index in range(packet_start, packet_start + packet_height):
        if index < len(matches):
            marker = ">" if state.focus == "packets" and index == state.selected_packet else " "
            add(f"{marker}   {_packet_text(matches[index])}", "bright" if marker == ">" else "mid")
        else:
            add("    ... no matching packet metadata ..." if index == 0 else "", "dim")
    divider("SELECTED EVIDENCE")
    add(state.selected_detail())
    lead = state.findings[0] if state.findings else None
    if lead:
        add(f"ALERT {len(state.findings)} finding(s): {_safe(lead.get('rule_id'), 55)} "
            f"| {_safe(lead.get('title'), 75)}", "bright")
    elif state.alert_latched:
        add("Earlier indicator remains latched. Review the event journal and saved scan artifacts.", "bright")
    else:
        add("No current rule finding. Indicators are leads, not proof of an intruder.", "dim")
    add(f"EVIDENCE {state.artifact or 'first scan pending'} | metadata only; no packet payloads", "dim")
    if state.search_mode:
        add(f"SEARCH /{_safe(state.query, width - 28)}_    ENTER apply  ESC cancel", "bright")
    else:
        add(f"[TAB] focus  [UP/DOWN] inspect  [/] search  [x] clear  [r] rescan  [q] quit", "bright")
    rows.append((_border(" OBSERVE / PRESERVE / VERIFY ", width, bl, br, h), "bright"))
    palette = {"bright": bright, "mid": mid, "dim": dim}
    if not color:
        return [row for row, _ in rows]
    return [f"\033[48;5;16m\033[38;5;{palette[shade]}m{row}\033[0m" for row, shade in rows]


def _handle_key(state: BoardState, key: str | None, editor: gn_tui.CommandLine) -> str:
    """Return quit/refresh/none. Search never treats typed q as a quit key."""
    if not key:
        return ""
    if key == "CTRL-C":
        return "quit"
    if state.search_mode:
        if key == "ESC":
            state.search_mode = False
            state.query = state.search_original
            editor.clear()
        else:
            submitted = editor.feed(key)
            if submitted is not None:
                state.query = _safe(submitted, 120)
                state.selected_packet = 0
                state.search_mode = False
            else:
                state.query = editor.text
        return ""
    if key in ("q", "Q"):
        return "quit"
    if key == "/":
        state.search_mode = True
        state.search_original = state.query
        editor.set(state.query)
    elif key == "TAB":
        state.focus = "ports" if state.focus == "packets" else "packets"
    elif key in ("UP", "DOWN"):
        direction = -1 if key == "UP" else 1
        if state.focus == "ports":
            state.selected_port = max(0, min(len(state.ports) - 1, state.selected_port + direction))
        else:
            state.selected_packet = max(0, min(len(state.matching_packets()) - 1,
                                                state.selected_packet + direction))
    elif key in ("x", "X"):
        state.query = ""
        state.selected_packet = 0
    elif key in ("r", "R"):
        state.stopped = False
        return "refresh"
    return ""


def run_dashboard(args: Any, *, scan: Callable[[], dict[str, Any]]) -> int:
    """Keep input and painting responsive while one bounded scan runs at a time."""
    refusal = gn_tui.refusal()
    if refusal:
        print(f"gn: {refusal}", file=sys.stderr)
        return 2
    state = BoardState(capture_enabled=bool(args.capture_interface))
    editor = gn_tui.CommandLine()
    future: Future[dict[str, Any]] | None = None
    next_scan = 0.0
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="defender-board") as pool:
        with ExitStack() as stack:
            keys = stack.enter_context(gn_tui.KeyReader())
            screen = stack.enter_context(gn_tui.Screen())
            try:
                while screen.active:
                    now = time.monotonic()
                    if future is not None and future.done():
                        try:
                            state.ingest(future.result())
                        except Exception as exc:  # noqa: BLE001 - restore the screen and show a stopped state
                            state.busy = False
                            state.stopped = True
                            state.message = f"Scan stopped: {_safe(exc, 130)}. Press r to retry."
                        future = None
                        next_scan = now + args.interval
                    if future is None and not state.stopped and now >= next_scan:
                        state.busy = True
                        state.message = "Collecting local inventory and bounded packet metadata..."
                        future = pool.submit(scan)
                    screen.take_resize()
                    screen.frame(render(state, screen.size(), gn_tui.tier()))
                    action = _handle_key(state, keys.read(0.08), editor)
                    if action == "quit":
                        break
                    if action == "refresh":
                        next_scan = 0.0
            except KeyboardInterrupt:
                pass
        # Preserve the in-flight scan artifact and event before returning to the shell.
        if future is not None:
            print("Finishing the bounded defender scan before exit...", file=sys.stderr)
    return 0
