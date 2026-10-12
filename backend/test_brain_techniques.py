from __future__ import annotations

import json
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import brain_techniques
from bughunter import hunt_trace


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_catalog_reads_seed_and_workspace_hunting_markdown(tmp_path: Path) -> None:
    seed = tmp_path / "seed"
    runtime = tmp_path / "runtime"
    workspace = tmp_path / "workspace"
    _write(
        seed / "skills" / "verify.md",
        "---\nname: verify-work\ndescription: Verify a code change\nwhen: test, verify\n---\nRun focused tests.",
    )
    _write(
        seed / "bounty" / "chain.md",
        "---\nname: chain-map\ndescription: Map an attack chain\nwhen: chain, recon\n---\nStart from scope.",
    )
    _write(
        workspace / "Hunting" / "web" / "idor.md",
        "# Object authorization\nCompare two authorized object contexts and require proof.",
    )

    catalog = brain_techniques.load_techniques(runtime, seed, workspace)

    assert {(item.domain, item.name) for item in catalog} == {
        ("code", "verify-work"),
        ("hunt", "chain-map"),
        ("hunt", "Object authorization"),
    }
    workspace_item = next(item for item in catalog if item.source == "workspace")
    wrapped = brain_techniques.prompt_block([workspace_item])
    assert "<workspace_data" in wrapped and "<content>" in wrapped


def test_attack_chains_are_bounded_to_surface_and_redact_query_values() -> None:
    endpoint = "https://example.test/download?token=secret&file=report.pdf"
    surface = {"endpoints": [endpoint]}
    plan = {
        "probe_priority": [
            {"endpoint": endpoint, "classes": ["path-traversal", "xss"], "score": 90},
            {"endpoint": "https://outside.test/admin", "classes": ["rce"], "score": 200},
        ]
    }

    chains = brain_techniques.build_attack_chains(plan, surface, priors={"path-traversal": 1.2})

    assert len(chains) == 1
    assert chains[0]["classes"] == ["path-traversal", "xss"]
    assert "secret" not in chains[0]["endpoint"]
    assert "report.pdf" not in chains[0]["endpoint"]
    assert chains[0]["steps"][-1]["gate"] == "report"
    assert all("outside.test" not in chain["endpoint"] for chain in chains)


def test_code_outcomes_record_success_and_failure_without_tool_output(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    assert brain_techniques.record_code_outcome(
        runtime,
        message="Fix token=super-secret in parser",
        provider="local",
        model="test",
        completed=True,
        verified=True,
        skills=["verify-work"],
        plan=["Change parser", "Run tests"],
        transcript=[{"tool": "verify", "is_error": False, "output": "private output"}],
    )
    assert brain_techniques.record_code_outcome(
        runtime,
        message="Fix parser again",
        provider="local",
        model="test",
        completed=False,
        verified=False,
        skills=["verify-work"],
        plan=["Try again"],
        transcript=[{"tool": "verify", "is_error": True, "output": "do not persist"}],
    )

    rows = brain_techniques.load_code_outcomes(runtime)
    assert [row["success"] for row in rows] == [True, False]
    assert rows[0]["tools"] == [{"name": "verify", "error": False}]
    assert "private output" not in (runtime / "brain_code_outcomes.jsonl").read_text(encoding="utf-8")
    assert "super-secret" not in rows[0]["intent"]
    assert "1/2" in brain_techniques.learned_code_guidance(runtime, ["verify-work"])


def test_hunt_priors_learn_from_confirmed_and_unconfirmed_chains(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    endpoint = "https://example.test/search"
    plan = {"used": True, "probe_priority": [{"endpoint": endpoint, "classes": ["sqli", "xss"]}]}
    surface = {"endpoints": [endpoint], "params": ["q"], "tech": [], "forms": []}
    for index in range(3):
        outcomes = [
            {
                "endpoint": endpoint,
                "class": "sqli",
                "proof_status": "confirmed" if index == 0 else "missing",
            }
        ]
        assert hunt_trace.record_trace(
            runtime,
            program="demo",
            target=endpoint,
            surface=surface,
            plan=plan,
            outcomes=outcomes,
            execution=[{"endpoint": endpoint, "classes": ["sqli", "xss"]}],
        )

    priors = brain_techniques.learned_hunt_priors(runtime, "demo", endpoint)

    assert priors["sqli"] > priors["xss"]
    assert 0.7 <= priors["xss"] <= 1.0
    assert brain_techniques.combine_priors({"sqli": 1.8}, {"sqli": 1.4})["sqli"] == 2.0


def test_hunt_priors_ignore_planned_but_unchecked_pairs(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    endpoint = "https://example.test/search"
    plan = {"probe_priority": [{"endpoint": endpoint, "classes": ["xss", "sqli"]}]}
    for _ in range(4):
        assert hunt_trace.record_trace(runtime, program="demo", target=endpoint,
                                       surface={}, plan=plan, outcomes=[],
                                       execution=[{"endpoint": endpoint, "classes": ["xss"]}])
    priors = brain_techniques.learned_hunt_priors(runtime, "demo", endpoint)
    assert "xss" in priors
    assert "sqli" not in priors


def test_hunt_priors_credit_exact_check_tags_for_shared_impacts(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    cases = (
        ("debug-rce", "rce", "active.debug-endpoint", "debug"),
        ("debug-disclosure", "disclosure", "active.debug-endpoint", "debug"),
        ("framing", "headers", "active.clickjacking", "clickjacking"),
        ("crlf", "redirect", "active.crlf", "crlf"),
        ("host", "redirect", "active.host-header-injection", "host-header"),
        ("open", "redirect", "active.open-redirect", "redirect"),
    )
    for path, impact, rule_id, tag in cases:
        endpoint = f"https://example.test/{path}"
        assert hunt_trace.record_trace(runtime, program="demo", target=endpoint,
                                       surface={}, plan={},
                                       outcomes=[{"endpoint": endpoint, "class": impact,
                                                  "rule_id": rule_id, "proof_status": "confirmed"}],
                                       execution=[{"endpoint": endpoint, "classes": [tag]}])
    priors = brain_techniques.learned_hunt_priors(runtime, "demo")
    for tag in ("debug", "clickjacking", "crlf", "host-header", "redirect"):
        assert tag in priors
    assert "rce" not in priors
    assert "disclosure" not in priors
    assert "headers" not in priors


def test_hunt_priors_skip_unknown_ambiguous_confirm_and_legacy_trace(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    endpoint = "https://example.test/admin"
    assert hunt_trace.record_trace(runtime, program="demo", target=endpoint,
                                   surface={}, plan={},
                                   outcomes=[{"endpoint": endpoint, "class": "rce",
                                              "rule_id": "active.unrecognized", "proof_status": "confirmed"}],
                                   execution=[{"endpoint": endpoint, "classes": ["debug", "rce", "xss"]}])
    # A legacy trace has no execution coverage and only an ambiguous impact.
    with (runtime / "hunt_traces.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"v": 1, "program": "demo", "outcomes": [{"endpoint": endpoint,
                      "class": "headers", "proof_status": "confirmed"}]}) + "\n")
    priors = brain_techniques.learned_hunt_priors(runtime, "demo")
    assert "debug" not in priors
    assert "rce" not in priors
    assert "clickjacking" not in priors
    assert "xss" in priors  # it was checked and had no related confirmation


def test_status_snapshot_exposes_metadata_not_playbook_bodies(tmp_path: Path) -> None:
    seed = tmp_path / "seed"
    runtime = tmp_path / "runtime"
    _write(
        seed / "bounty" / "safe.md",
        "---\nname: safe-chain\ndescription: Safe chain\nwhen: hunt\n---\nBODY-MUST-STAY-SERVER-SIDE",
    )

    snapshot = brain_techniques.status_snapshot(runtime, seed, tmp_path / "workspace")

    assert snapshot["ok"] is True
    assert snapshot["techniques"]["hunt"] == 1
    assert snapshot["techniques"]["items"][0]["name"] == "safe-chain"
    assert "BODY-MUST-STAY-SERVER-SIDE" not in str(snapshot)
    assert any("POE" in row for row in snapshot["guardrails"])


def test_studio_operations_contract_is_wired_end_to_end() -> None:
    public = BACKEND_DIR.parent / "public"
    html = (public / "index.html").read_text(encoding="utf-8")
    script = (public / "app.js").read_text(encoding="utf-8")
    styles = (public / "styles.css").read_text(encoding="utf-8")

    assert 'id="pmode-ops"' in html
    assert 'id="panelOps"' in html
    assert 'id="brainLiveFeed"' in html
    assert "nothing is auto-submitted" in html.lower()
    assert 'const PANEL_MODES = ["brain", "ops", "train", "security"]' in script
    assert 'apiFetch("/api/brain/status"' in script
    assert 'liveOn("brain_dialog", appendBrainLive)' in script
    assert 'liveOn("poe_dialog", appendBrainLive)' in script
    assert ".brain-live-feed" in styles
    assert 'body[data-app-mode="studio"] .app-shell' in styles
