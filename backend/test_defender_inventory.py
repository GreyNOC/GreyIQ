"""Evidence, privacy, and boundedness tests for local defender inventory."""

from __future__ import annotations

import json
import hashlib
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from defender.baseline import _listeners, compare_baseline, load_baseline, save_baseline
from defender.inventory import (
    _collect_files, _collect_windows, _hash_process_executables, _linux_addr, _linux_services,
    _linux_startup, _windows_tcp_state,
)
from defender.trace import trace_pid


def _snapshot() -> dict:
    return {
        "schema_version": 1, "collected_at": "2026-10-13T00:00:00+00:00",
        "host": {"hostname": "test-host", "platform": "linux", "machine": "x86_64"},
        "processes": [
            {"pid": 1, "ppid": 0, "name": "init", "exe": "/sbin/init", "started": "10"},
            {"pid": 10, "ppid": 1, "name": "server", "exe": "/usr/bin/server", "started": "20"},
        ],
        "connections": [
            {"protocol": "tcp", "family": "ipv4", "local_address": "127.0.0.1",
             "local_port": 8080, "remote_address": "", "remote_port": 0,
             "state": "LISTEN", "pid": 10},
            {"protocol": "tcp", "family": "ipv4", "local_address": "127.0.0.1",
             "local_port": 52344, "remote_address": "192.0.2.4", "remote_port": 443,
             "state": "ESTABLISHED", "pid": 10},
        ],
        "interfaces": [{"name": "lo", "index": 1, "mac": "", "status": "up", "addresses": ["127.0.0.1/8"]}],
        "routes": [{"destination": "127.0.0.0/8", "gateway": "0.0.0.0", "interface": "lo", "metric": 0, "family": "ipv4"}],
        "services": [{"name": "server.service", "status": "running", "start_type": "enabled"}],
        "startup": [], "packages": [{"name": "server", "version": "1.0", "publisher": ""}],
        "files": [], "file_roots": [],
        "coverage": {section: "ok" for section in (
            "processes", "connections", "interfaces", "routes", "services", "startup", "packages")}
        | {"files": "not_requested"},
        "errors": [],
    }


class DefenderBaselineTests(unittest.TestCase):
    def test_replacement_archives_exact_validated_reference(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            original = save_baseline(_snapshot(), path)
            original_bytes = path.read_bytes()
            changed = _snapshot()
            changed["services"][0]["start_type"] = "disabled"
            replacement = save_baseline(changed, path, replace=True)
            archive = replacement["archive"]
            archived_path = Path(archive["path"])
            self.assertEqual(archived_path.read_bytes(), original_bytes)
            self.assertEqual(load_baseline(archived_path), original)
            self.assertEqual(archive["sha256"], hashlib.sha256(original_bytes).hexdigest())
            self.assertEqual(archive["baseline_sha256"], original["sha256"])
            self.assertEqual(load_baseline(path)["sha256"], replacement["sha256"])
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(archived_path.stat().st_mode), 0o600)

            # Restoring identical prior bytes exercises exact-content archive
            # collision handling without creating another archive version.
            path.write_bytes(original_bytes)
            again = save_baseline(changed, path, replace=True)
            self.assertEqual(again["archive"], archive)
            self.assertEqual(archived_path.read_bytes(), original_bytes)

    def test_replacement_refuses_archive_failure_or_collision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            save_baseline(_snapshot(), path)
            original_bytes = path.read_bytes()
            changed = _snapshot()
            changed["services"][0]["start_type"] = "disabled"
            with mock.patch("defender.baseline.os.link", side_effect=OSError("archive publication failed")):
                with self.assertRaisesRegex(OSError, "archive publication failed"):
                    save_baseline(changed, path, replace=True)
            self.assertEqual(path.read_bytes(), original_bytes)

            archive = Path(tmp) / (
                f".{path.name[:48]}.archive.{hashlib.sha256(original_bytes).hexdigest()}.json"
            )
            archive.write_bytes(b"wrong content")
            with self.assertRaisesRegex(ValueError, "archive collision"):
                save_baseline(changed, path, replace=True)
            self.assertEqual(path.read_bytes(), original_bytes)
            archive.unlink()
            sentinel = Path(tmp) / "sentinel"
            sentinel.write_bytes(b"private unrelated data")
            try:
                archive.symlink_to(sentinel)
            except (OSError, NotImplementedError):
                pass
            else:
                with self.assertRaisesRegex(ValueError, "symlink"):
                    save_baseline(changed, path, replace=True)
                self.assertEqual(path.read_bytes(), original_bytes)
                self.assertEqual(sentinel.read_bytes(), b"private unrelated data")

    def test_replacement_refuses_invalid_previous_reference(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            save_baseline(_snapshot(), path)
            document = json.loads(path.read_text(encoding="utf-8"))
            document["inventory"]["services"][0]["start_type"] = "tampered"
            path.write_text(json.dumps(document), encoding="utf-8")
            invalid_bytes = path.read_bytes()
            with self.assertRaisesRegex(ValueError, "integrity"):
                save_baseline(_snapshot(), path, replace=True)
            self.assertEqual(path.read_bytes(), invalid_bytes)

    def test_replacement_refuses_symlink_or_oversized_prior_reference(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sentinel = root / "sentinel.json"
            sentinel.write_bytes(b"untouched")
            link = root / "baseline-link.json"
            try:
                link.symlink_to(sentinel)
            except (OSError, NotImplementedError):
                pass  # Symlink creation may require elevated Windows privileges.
            else:
                with self.assertRaisesRegex(ValueError, "symlink"):
                    save_baseline(_snapshot(), link, replace=True)
                self.assertEqual(sentinel.read_bytes(), b"untouched")

            path = root / "baseline.json"
            large = _snapshot()
            large["packages"][0]["name"] = "x" * 10_000
            save_baseline(large, path)
            previous_bytes = path.read_bytes()
            with mock.patch("defender.baseline._MAX_BASELINE_BYTES", 5_000):
                with self.assertRaisesRegex(ValueError, "exceeds size limit"):
                    save_baseline(_snapshot(), path, replace=True)
            self.assertEqual(path.read_bytes(), previous_bytes)

    def test_windows_process_hash_path_case_is_normalized_only_on_windows(self) -> None:
        prior = _snapshot()
        prior["host"]["platform"] = "win32"
        prior["processes"] = [{"pid": 10, "name": "server.exe", "exe": r"C:\Apps\Server.EXE",
                               "sha256": "a" * 64}]
        current = _snapshot()
        current["host"]["platform"] = "win32"
        current["processes"] = [{"pid": 11, "name": "server.exe", "exe": r"c:\apps\server.exe",
                                 "sha256": "a" * 64}]
        with tempfile.TemporaryDirectory() as tmp:
            baseline = save_baseline(prior, Path(tmp) / "baseline.json")
            self.assertEqual(compare_baseline(current, baseline)["sections"]["processes"]["changed"], [])
            current["processes"][0]["sha256"] = "b" * 64
            changes = compare_baseline(current, baseline)["sections"]["processes"]["changed"]
        self.assertEqual(len(changes), 1)
        self.assertEqual(set(changes[0]["before"]["sha256_by_exe"]), {r"c:\apps\server.exe"})

    def test_explicit_baseline_validates_integrity_and_refuses_overwrite(self) -> None:
        snapshot = _snapshot()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            saved = save_baseline(snapshot, path)
            self.assertEqual(saved, load_baseline(path))
            self.assertEqual(saved["inventory"]["host"]["hostname"], "test-host")
            with self.assertRaises(FileExistsError):
                save_baseline(snapshot, path)
            document = json.loads(path.read_text(encoding="utf-8"))
            document["inventory"]["services"][0]["start_type"] = "disabled"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "integrity"):
                load_baseline(path)

    def test_pid_churn_and_outbound_connection_do_not_create_drift(self) -> None:
        baseline_inventory = _snapshot()
        current = _snapshot()
        current["processes"][1]["pid"] = 25
        current["processes"][1]["started"] = "30"
        current["connections"][0]["pid"] = 25
        current["connections"][1]["pid"] = 25
        current["connections"][1]["remote_address"] = "192.0.2.5"
        with tempfile.TemporaryDirectory() as tmp:
            baseline = save_baseline(baseline_inventory, Path(tmp) / "baseline.json")
            result = compare_baseline(current, baseline)
        self.assertEqual(result["summary"], {"added": 0, "removed": 0, "changed": 0})

    def test_ephemeral_udp_binding_change_is_not_listener_drift(self) -> None:
        baseline_inventory = _snapshot()
        baseline_inventory["connections"].append({
            "protocol": "udp", "family": "ipv4", "local_address": "0.0.0.0",
            "local_port": 53001, "remote_address": "", "remote_port": 0,
            "state": "BOUND", "pid": 10,
        })
        current = _snapshot()
        current["connections"].append({
            "protocol": "udp", "family": "ipv4", "local_address": "0.0.0.0",
            "local_port": 53002, "remote_address": "", "remote_port": 0,
            "state": "BOUND", "pid": 10,
        })
        with tempfile.TemporaryDirectory() as tmp:
            baseline = save_baseline(baseline_inventory, Path(tmp) / "baseline.json")
            result = compare_baseline(current, baseline)
        self.assertEqual(result["sections"]["listeners"]["added"], [])
        self.assertEqual(result["sections"]["listeners"]["removed"], [])
        self.assertEqual(result["summary"], {"added": 0, "removed": 0, "changed": 0})
        self.assertEqual(current["connections"][-1]["protocol"], "udp")

    def test_executable_replacement_and_service_change_are_observations(self) -> None:
        current = _snapshot()
        current["processes"][1]["exe"] = "/tmp/server"
        current["services"][0]["start_type"] = "disabled"
        current["packages"].append({"name": "newpackage", "version": "1", "publisher": ""})
        with tempfile.TemporaryDirectory() as tmp:
            baseline = save_baseline(_snapshot(), Path(tmp) / "baseline.json")
            result = compare_baseline(current, baseline)
        self.assertEqual(result["summary"], {"added": 1, "removed": 0, "changed": 3})
        process_change = result["sections"]["processes"]["changed"][0]
        self.assertEqual(process_change["before"]["exe"], "/usr/bin/server")
        self.assertEqual(process_change["after"]["exe"], "/tmp/server")
        self.assertIn("not confirmed threats", result["note"])

    def test_partial_collection_does_not_claim_removal(self) -> None:
        current = _snapshot()
        current["services"] = []
        current["coverage"]["services"] = "partial"
        with tempfile.TemporaryDirectory() as tmp:
            baseline = save_baseline(_snapshot(), Path(tmp) / "baseline.json")
            result = compare_baseline(current, baseline)
        self.assertEqual(result["sections"]["services"]["removed"], [])
        self.assertEqual(result["sections"]["services"]["status"], "partial")

    def test_host_mismatch_refuses_comparison(self) -> None:
        current = _snapshot()
        current["host"]["hostname"] = "another-host"
        with tempfile.TemporaryDirectory() as tmp:
            baseline = save_baseline(_snapshot(), Path(tmp) / "baseline.json")
            with self.assertRaisesRegex(ValueError, "different host"):
                compare_baseline(current, baseline)

    def test_file_scope_mismatch_refuses_false_removals(self) -> None:
        current = _snapshot()
        current["file_roots"] = ["/another/path"]
        with tempfile.TemporaryDirectory() as tmp:
            baseline = save_baseline(_snapshot(), Path(tmp) / "baseline.json")
            with self.assertRaisesRegex(ValueError, "file roots differ"):
                compare_baseline(current, baseline)


class DefenderFilesAndTraceTests(unittest.TestCase):
    def test_process_hash_drift_requires_two_observed_on_disk_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp) / "server.bin"
            executable.write_bytes(b"first local binary")
            prior = _snapshot()
            prior["processes"] = [{"pid": 10, "ppid": 1, "name": "server", "exe": str(executable)}]
            _hash_process_executables(prior, max_hashes=2, max_file_bytes=1024,
                                      max_total_bytes=1024)
            self.assertEqual(prior["coverage"]["process_binaries"], "ok")
            baseline = save_baseline(prior, Path(tmp) / "baseline.json")

            current = _snapshot()
            current["processes"] = [{"pid": 11, "ppid": 1, "name": "server", "exe": str(executable)}]
            # A scan without opt-in hashing does not claim binary drift.
            self.assertEqual(compare_baseline(current, baseline)["sections"]["processes"]["changed"], [])
            executable.write_bytes(b"second local binary")
            _hash_process_executables(current, max_hashes=2, max_file_bytes=1024,
                                      max_total_bytes=1024)
            changes = compare_baseline(current, baseline)["sections"]["processes"]["changed"]
            self.assertEqual(len(changes), 1)
            self.assertNotEqual(changes[0]["before"]["sha256_by_exe"][str(executable)],
                                changes[0]["after"]["sha256_by_exe"][str(executable)])
            self.assertEqual(current["processes"][0]["hash_source"], "executable_path_file")

    def test_process_hash_limits_mark_partial_without_false_hash_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp) / "server.bin"
            executable.write_bytes(b"large local binary")
            prior = _snapshot()
            prior["processes"] = [{"pid": 10, "ppid": 1, "name": "server", "exe": str(executable)}]
            _hash_process_executables(prior, max_hashes=1, max_file_bytes=1024,
                                      max_total_bytes=1024)
            baseline = save_baseline(prior, Path(tmp) / "baseline.json")
            current = _snapshot()
            current["processes"] = [{"pid": 10, "ppid": 1, "name": "server", "exe": str(executable)}]
            _hash_process_executables(current, max_hashes=1, max_file_bytes=4,
                                      max_total_bytes=4)
            self.assertEqual(current["processes"][0]["hash_status"], "skipped_size")
            self.assertEqual(current["coverage"]["process_binaries"], "partial")
            self.assertEqual(compare_baseline(current, baseline)["sections"]["processes"]["changed"], [])

    def test_linux_socket_address_parser(self) -> None:
        self.assertEqual(_linux_addr("0100007F:1F90", "ipv4"), ("127.0.0.1", 8080))
        self.assertEqual(_linux_addr("00000000000000000000000001000000:0050", "ipv6"), ("::1", 80))

    def test_windows_numeric_tcp_state_recovers_listener_and_flags_unknown(self) -> None:
        self.assertEqual(_windows_tcp_state("2"), ("LISTEN", True))
        self.assertEqual(_windows_tcp_state("Listen"), ("LISTEN", True))
        self.assertEqual(_windows_tcp_state(5), ("ESTABLISHED", True))
        self.assertEqual(_windows_tcp_state("999"), ("UNKNOWN(999)", False))

        def powershell_result(expression: str):
            if "Win32_Process" in expression:
                return ([{"ProcessId": 10, "ParentProcessId": 1, "Name": "server.exe",
                          "ExecutablePath": "C:\\server.exe", "CreationDate": "2026-10-13"}], "")
            if "Get-NetTCPConnection" in expression:
                return ([
                    {"LocalAddress": "127.0.0.1", "LocalPort": 8080,
                     "RemoteAddress": "0.0.0.0", "RemotePort": 0, "State": "2", "OwningProcess": 10},
                    {"LocalAddress": "127.0.0.1", "LocalPort": 8081,
                     "RemoteAddress": "0.0.0.0", "RemotePort": 0, "State": "999", "OwningProcess": 10},
                ], "")
            return ([], "")

        snapshot = _snapshot()
        with mock.patch("defender.inventory._powershell_json", side_effect=powershell_result):
            _collect_windows(snapshot)
        self.assertEqual(snapshot["connections"][0]["state"], "LISTEN")
        self.assertEqual(len(_listeners(snapshot)), 1)
        self.assertEqual(snapshot["connections"][1]["state"], "UNKNOWN(999)")
        self.assertEqual(snapshot["coverage"]["connections"], "partial")
        self.assertTrue(any("unknown TCP state" in error["error"] for error in snapshot["errors"]))

    def test_windows_sources_detect_n_plus_one_and_keep_udp_when_tcp_overflows(self) -> None:
        limits = {"processes": 1, "connections": 4, "interfaces": 1,
                  "routes": 1, "services": 1, "startup": 1, "packages": 1}

        def powershell_result(expression: str):
            if "Win32_Process" in expression:
                self.assertIn("-First 2", expression)
                return ([{"ProcessId": pid, "Name": "p.exe"} for pid in (1, 2)], "")
            if "Get-NetTCPConnection" in expression:
                self.assertIn("-First 5", expression)
                return ([{"LocalAddress": "127.0.0.1", "LocalPort": 8000 + port,
                          "RemoteAddress": "0.0.0.0", "RemotePort": 0,
                          "State": "Listen", "OwningProcess": 1} for port in range(4)], "")
            if "Get-NetUDPEndpoint" in expression:
                self.assertIn("-First 5", expression)
                return ([{"LocalAddress": "127.0.0.1", "LocalPort": 9000 + port,
                          "OwningProcess": 1} for port in range(2)], "")
            if "Get-NetAdapter" in expression:
                self.assertIn("-First 2", expression)
                return ([{"Name": "a", "InterfaceIndex": 1},
                         {"Name": "b", "InterfaceIndex": 2}], "")
            if "Get-NetIPAddress" in expression:
                self.assertIn("-First 2", expression)
                return ([{"InterfaceIndex": 1, "IPAddress": "127.0.0.1", "PrefixLength": 8},
                         {"InterfaceIndex": 2, "IPAddress": "192.0.2.2", "PrefixLength": 24}], "")
            if "Get-NetRoute" in expression:
                self.assertIn("-First 2", expression)
                return ([{"DestinationPrefix": "0.0.0.0/0", "NextHop": "192.0.2.1", "InterfaceIndex": 1},
                         {"DestinationPrefix": "192.0.2.0/24", "NextHop": "0.0.0.0", "InterfaceIndex": 2}], "")
            if "Win32_Service" in expression:
                self.assertIn("-First 2", expression)
                return ([{"Name": "svc1"}, {"Name": "svc2"}], "")
            if "Win32_StartupCommand" in expression:
                self.assertIn("-First 2", expression)
                return ([{"Name": "start1"}, {"Name": "start2"}], "")
            if "Get-ItemProperty" in expression:
                self.assertIn("-First 2", expression)
                return ([{"DisplayName": "app1"}, {"DisplayName": "app2"}], "")
            self.fail(f"unexpected PowerShell expression: {expression}")

        snapshot = _snapshot()
        with mock.patch.dict("defender.inventory.LIMITS", limits), \
             mock.patch("defender.inventory._MAX_WINDOWS_ADDRESSES", 1), \
             mock.patch("defender.inventory._powershell_json", side_effect=powershell_result):
            _collect_windows(snapshot)
        for section in limits:
            self.assertEqual(snapshot["coverage"][section], "partial", section)
            self.assertTrue(any(row["section"] == section and "truncated" in row["error"]
                                for row in snapshot["errors"]), section)
        self.assertEqual(len(snapshot["connections"]), 4)
        self.assertTrue(any(row["protocol"] == "udp" for row in snapshot["connections"]))

    def test_windows_exact_cap_is_not_reported_truncated(self) -> None:
        snapshot = _snapshot()
        with mock.patch.dict("defender.inventory.LIMITS", {"processes": 1}), \
             mock.patch("defender.inventory._powershell_json", side_effect=lambda expression: (
                 ([{"ProcessId": 1, "Name": "p.exe"}] if "Win32_Process" in expression else []), "")):
            _collect_windows(snapshot)
        self.assertEqual(snapshot["coverage"]["processes"], "ok")
        self.assertFalse(any(row["section"] == "processes" for row in snapshot["errors"]))

    def test_windows_same_name_service_and_startup_command_repointing(self) -> None:
        secret = "private-token-example"

        def collect(service_path: str, startup_path: str, service_dll: str = "") -> dict:
            def powershell_result(expression: str):
                if "Win32_Service" in expression:
                    return ([{"Name": "svc", "State": "Running", "StartMode": "Auto",
                              "PathName": f'"{service_path}" --token={secret}',
                              "ServiceDll": service_dll}], "")
                if "Win32_StartupCommand" in expression:
                    return ([{"Name": "autostart", "Location": "HKCU:Run",
                              "Command": f'"{startup_path}" --token={secret}'}], "")
                return ([], "")

            snapshot = _snapshot()
            with mock.patch("defender.inventory._powershell_json", side_effect=powershell_result):
                _collect_windows(snapshot)
            return snapshot

        first = collect(r"C:\Apps\old.exe", r"C:\Startup\old.exe")
        same = collect(r"C:\Apps\old.exe", r"C:\Startup\old.exe")
        second = collect(r"C:\Apps\new.exe", r"C:\Startup\new.exe")
        dll_repoint = collect(r"C:\Apps\old.exe", r"C:\Startup\old.exe",
                              service_dll=r"C:\Apps\new.dll")
        with tempfile.TemporaryDirectory() as tmp:
            baseline = save_baseline(first, Path(tmp) / "baseline.json")
            self.assertEqual(compare_baseline(same, baseline)["summary"]["changed"], 0)
            diff = compare_baseline(second, baseline)
            dll_diff = compare_baseline(dll_repoint, baseline)
        self.assertEqual(len(diff["sections"]["services"]["changed"]), 1)
        self.assertEqual(len(diff["sections"]["startup"]["changed"]), 1)
        self.assertEqual(len(dll_diff["sections"]["services"]["changed"]), 1)
        self.assertNotEqual(first["services"][0]["definition_sha256"],
                            second["services"][0]["definition_sha256"])
        self.assertEqual(second["services"][0]["target_path"], r"C:\Apps\new.exe")
        self.assertNotIn(secret, json.dumps(first))
        self.assertNotIn(secret, json.dumps(diff))

    def test_linux_unit_and_dropin_repointing_changes_digest(self) -> None:
        secret = "local-private-value"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            unit = root / "demo.service"
            dropin = root / "demo.service.d" / "override.conf"
            dropin.parent.mkdir()
            unit.write_text(f"[Service]\nExecStart=/usr/bin/old --token={secret}\n", encoding="utf-8")
            dropin.write_text("[Service]\nEnvironment=MODE=one\n", encoding="utf-8")
            with mock.patch("defender.inventory.shutil.which", return_value="systemctl"), \
                 mock.patch("defender.inventory._command", return_value=("demo.service enabled\n", "")):
                first, error, partial = _linux_services(unit_roots=(root,))
                same, _, _ = _linux_services(unit_roots=(root,))
                dropin.write_text("[Service]\nEnvironment=MODE=two\n", encoding="utf-8")
                second, _, _ = _linux_services(unit_roots=(root,))
            self.assertEqual(error, "")
            self.assertFalse(partial)
            self.assertEqual(first[0]["definition_status"], "hashed")
            self.assertEqual(first[0]["definition_sha256"], same[0]["definition_sha256"])
            self.assertNotEqual(first[0]["definition_sha256"], second[0]["definition_sha256"])
            self.assertEqual(first[0]["target_path"], "")  # drop-in may override ExecStart
            self.assertNotIn(secret, json.dumps(first))

            reference = _snapshot()
            reference["services"] = first
            current = _snapshot()
            current["services"] = second
            baseline = save_baseline(reference, root / "baseline.json")
            self.assertEqual(len(compare_baseline(current, baseline)["sections"]["services"]["changed"]), 1)

    def test_missing_linux_unit_definition_marks_service_coverage_partial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            unit = root / "demo.service"
            unit.write_text("[Service]\nExecStart=/usr/bin/demo\n", encoding="utf-8")
            with mock.patch("defender.inventory.shutil.which", return_value="systemctl"), \
                 mock.patch("defender.inventory._command", return_value=("demo.service enabled\n", "")):
                observed, _, _ = _linux_services(unit_roots=(root,))
                unit.unlink()
                services, error, partial = _linux_services(unit_roots=(Path(tmp),))
        self.assertEqual(services[0]["definition_status"], "unavailable")
        self.assertTrue(partial)
        self.assertIn("definition(s) unavailable", error)
        prior = _snapshot()
        prior["services"] = observed
        current = _snapshot()
        current["services"] = services
        current["coverage"]["services"] = "partial"
        with tempfile.TemporaryDirectory() as tmp:
            baseline = save_baseline(prior, Path(tmp) / "baseline.json")
            self.assertEqual(compare_baseline(current, baseline)["sections"]["services"]["changed"], [])

    def test_unreadable_linux_startup_root_marks_partial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(Path, "iterdir", side_effect=PermissionError("denied")):
                startup, error, partial = _linux_startup(roots=(Path(tmp),))
        self.assertEqual(startup, [])
        self.assertTrue(partial)
        self.assertIn("root(s) unavailable", error)

    def test_linux_desktop_startup_repoint_and_oversize_are_visible(self) -> None:
        secret = "desktop-private-token"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = root / "client.desktop"
            entry.write_text(f"[Desktop Entry]\nExec=/usr/bin/old --token={secret}\n", encoding="utf-8")
            first, error, partial = _linux_startup(roots=(root,))
            self.assertEqual((error, partial), ("", False))
            entry.write_text(f"[Desktop Entry]\nExec=/usr/bin/new --token={secret}\n", encoding="utf-8")
            second, _, _ = _linux_startup(roots=(root,))
            self.assertEqual(second[0]["target_path"], "/usr/bin/new")
            self.assertNotEqual(first[0]["definition_sha256"], second[0]["definition_sha256"])
            self.assertNotIn(secret, json.dumps(second))

            reference = _snapshot()
            reference["startup"] = first
            current = _snapshot()
            current["startup"] = second
            baseline = save_baseline(reference, root / "baseline.json")
            self.assertEqual(len(compare_baseline(current, baseline)["sections"]["startup"]["changed"]), 1)

            with mock.patch("defender.inventory._MAX_DEFINITION_BYTES", 8):
                oversized, oversized_error, oversized_partial = _linux_startup(roots=(root,))
            self.assertEqual(oversized[0]["definition_status"], "too_large")
            self.assertEqual(oversized[0]["definition_sha256"], "")
            self.assertTrue(oversized_partial)
            self.assertIn("over limits", oversized_error)

    def test_file_hashes_are_opt_in_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.txt").write_text("alpha", encoding="utf-8")
            (root / "b.txt").write_text("oversized content", encoding="utf-8")
            snapshot = {"files": [], "coverage": {}, "errors": []}
            _collect_files(snapshot, [str(root)], max_files=1000, max_file_bytes=10)
            self.assertEqual(len(snapshot["files"]), 2)
            self.assertEqual(snapshot["files"][0]["status"], "hashed")
            self.assertEqual(len(snapshot["files"][0]["sha256"]), 64)
            self.assertEqual(snapshot["files"][1]["status"], "skipped_size")
            self.assertEqual(snapshot["coverage"]["files"], "partial")

            snapshot = {"files": [], "coverage": {}, "errors": []}
            _collect_files(snapshot, [str(root)], max_files=1, max_file_bytes=10)
            self.assertEqual(len(snapshot["files"]), 1)
            self.assertEqual(snapshot["coverage"]["files"], "partial")
            self.assertTrue(any("limit reached" in row["error"] for row in snapshot["errors"]))

    def test_file_diff_reports_digest_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "observed.txt"
            path.write_text("before", encoding="utf-8")
            prior = _snapshot()
            prior["file_roots"] = [str(path)]
            _collect_files(prior, [str(path)], max_files=10, max_file_bytes=100)
            baseline = save_baseline(prior, Path(tmp) / "baseline.json")
            path.write_text("after", encoding="utf-8")
            current = _snapshot()
            current["file_roots"] = [str(path)]
            _collect_files(current, [str(path)], max_files=10, max_file_bytes=100)
            diff = compare_baseline(current, baseline)
        self.assertEqual(len(diff["sections"]["files"]["changed"]), 1)
        self.assertNotEqual(diff["sections"]["files"]["changed"][0]["before"]["sha256"],
                            diff["sections"]["files"]["changed"][0]["after"]["sha256"])

    def test_pid_trace_correlates_only_local_observations(self) -> None:
        trace = trace_pid(10, _snapshot())
        self.assertEqual(trace["status"], "observed")
        self.assertEqual(trace["ancestors"][0]["pid"], 1)
        self.assertEqual(trace["remote_peers"], [{"address": "192.0.2.4", "port": 443}])
        self.assertIn("not identities", trace["limitations"][1])
        self.assertEqual(trace_pid(9999, _snapshot())["status"], "not_observed")


if __name__ == "__main__":
    unittest.main()
