"""Minimal DNS-over-UDP CNAME resolver — stdlib ``socket``/``struct`` only (no dnspython, so
it survives the PyInstaller freeze). Sends one DNS query for a host's CNAME record to a public
resolver and parses the answer, handling DNS name-compression pointers.

Used to correlate a subdomain's CNAME target with known-takeoverable third-party services
(GitHub Pages, S3, Heroku, …) so a dangling CNAME is caught even when the page body gives no
fingerprint. Best-effort: any timeout / malformed packet returns ``[]``. The query goes to a
public resolver (the same external DNS the OS already uses for getaddrinfo); it never touches
the target host.
"""

from __future__ import annotations

import secrets
import socket
import struct

_TYPE_CNAME = 5
_CLASS_IN = 1


def _encode_qname(host: str) -> bytes:
    out = b""
    for label in host.strip(".").split("."):
        try:
            raw = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode("ascii")
        except (UnicodeError, ValueError):
            raw = label.encode("ascii", "ignore")
        out += bytes([len(raw) & 0x3F]) + raw[:63]
    return out + b"\x00"


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    """Read a (possibly compressed) DNS name. Returns (name, offset_after_name_in_stream)."""
    labels: list[str] = []
    jumped = False
    next_off = offset
    pos = offset
    for _ in range(128):  # loop guard against malicious pointer cycles
        if pos >= len(data):
            break
        length = data[pos]
        if length == 0:
            pos += 1
            if not jumped:
                next_off = pos
            break
        if (length & 0xC0) == 0xC0:  # compression pointer
            if pos + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                next_off = pos + 2
            jumped = True
            pos = ptr
            continue
        labels.append(data[pos + 1:pos + 1 + length].decode("ascii", "replace"))
        pos += 1 + length
    return ".".join(labels), next_off


def parse_cname_response(data: bytes) -> list[str]:
    """Parse a DNS response packet, returning the CNAME target(s) in the answer section."""
    if len(data) < 12:
        return []
    ancount = struct.unpack(">H", data[6:8])[0]
    _, off = _read_name(data, 12)   # skip the question name
    off += 4                         # skip qtype + qclass
    targets: list[str] = []
    for _ in range(min(ancount, 64)):
        if off + 10 > len(data):
            break
        _, off = _read_name(data, off)
        if off + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        if rtype == _TYPE_CNAME:
            name, _ = _read_name(data, off)
            name = name.strip(".").lower()
            if name:
                targets.append(name)
        off += rdlen
    return targets


def resolve_cname(host: str, *, server: str = "8.8.8.8", timeout: float = 4.0) -> list[str]:
    """Resolve ``host``'s CNAME chain via a UDP query to ``server``. Returns the CNAME target(s),
    or ``[]`` on no-CNAME / timeout / error."""
    host = str(host or "").strip().strip(".").lower()
    if not host or "." not in host:
        return []
    qid = secrets.randbits(16)
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # RD=1, qdcount=1
    packet = header + _encode_qname(host) + struct.pack(">HH", _TYPE_CNAME, _CLASS_IN)
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (server, 53))
        data, _addr = sock.recvfrom(4096)
    except (OSError, socket.timeout, ValueError):
        return []
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return parse_cname_response(data)
