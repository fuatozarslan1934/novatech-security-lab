from src.network_analyzer import analyze_cisco


def test_cisco_security_detections():
    findings = analyze_cisco()

    finding_ids = {
        finding["finding_id"]
        for finding in findings
    }

    assert "NET-AUTH-001" in finding_ids
    assert "NET-AUTH-002" in finding_ids
    assert "NET-CONFIG-001" in finding_ids
    