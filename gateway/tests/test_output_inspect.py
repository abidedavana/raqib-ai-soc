from app.detection.output_inspect import OutputInspector
from app.demo import CANARY, INTERNAL_SECRET

insp = OutputInspector(canaries=[CANARY])


def test_canary_leak_is_system_prompt_extraction():
    f = insp.scan(f"Sure, my canary token is {CANARY} by the way")
    assert any(x.rule_id == "OUT-CANARY-001" for x in f)
    assert any(x.owasp_llm == "LLM07:2025" and x.severity.value == "critical" for x in f)


def test_aws_secret_leak():
    f = insp.scan(f"the billing key is {INTERNAL_SECRET}")
    assert any(x.category == "secret_leak" for x in f)


def test_email_pii_detected():
    f = insp.scan("contact the customer at jane.doe@example.com")
    assert any(x.rule_id == "OUT-EMAIL_ADDRESS" for x in f)


def test_valid_credit_card_detected():
    f = insp.scan("card on file 4111 1111 1111 1111")
    assert any("credit" in x.title.lower() for x in f)


def test_invalid_credit_card_ignored():
    f = insp.scan("reference number 1234 5678 9012 3456")
    assert not any("credit" in x.title.lower() for x in f)


def test_clean_text_no_findings():
    f = insp.scan("Your order #1234 shipped yesterday and arrives Friday.")
    assert f == []


def test_redaction_removes_secret_and_canary():
    red, findings = insp.redact(f"key {INTERNAL_SECRET} and canary {CANARY}")
    assert INTERNAL_SECRET not in red
    assert CANARY not in red
    assert len(findings) >= 2
