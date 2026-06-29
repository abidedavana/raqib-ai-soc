import json

from app.config import Settings
from app.events.siem import WazuhForwarder
from app.models import Direction, SecurityEvent, Severity, Verdict


def _event() -> SecurityEvent:
    return SecurityEvent(
        session_id="s1", direction=Direction.INBOUND, detector="signature",
        rule_id="SIG-INJ-001", category="prompt_injection", title="Instruction override",
        severity=Severity.HIGH, confidence=0.9, owasp_llm="LLM01:2025",
        mitre_atlas="AML.T0051.000", verdict=Verdict.BLOCK, action_taken="blocked",
    )


def test_disabled_is_noop():
    fwd = WazuhForwarder(Settings(wazuh_enabled=False))
    assert fwd.send(_event()) is False


def test_file_sink_writes_one_json_line(tmp_path):
    logf = tmp_path / "raqib-events.json"
    fwd = WazuhForwarder(Settings(
        wazuh_enabled=True, wazuh_mode="file", wazuh_log_file=str(logf)
    ))
    assert fwd.send(_event()) is True
    assert fwd.send(_event()) is True

    lines = logf.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    rec = json.loads(lines[0])
    # fields land under "raqib" so Wazuh exposes them as raqib.severity, etc.
    assert rec["raqib"]["severity"] == "high"
    assert rec["raqib"]["owasp_llm"] == "LLM01:2025"
    assert rec["raqib"]["mitre_atlas"] == "AML.T0051.000"
