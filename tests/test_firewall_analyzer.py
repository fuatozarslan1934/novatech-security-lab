from src.firewall_analyzer import analyze_firewall


def test_firewall_security_detections():
    findings = analyze_firewall()

    finding_ids = {
        finding["finding_id"]
        for finding in findings
    }

    assert "FW-DENY-001" in finding_ids
    assert "FW-SCAN-001" in finding_ids
    assert "FW-SCAN-002" in finding_ids