from src.linux_analyzer import analyze_linux


def test_linux_security_detections():
    findings = analyze_linux()

    finding_ids = {
        finding["finding_id"]
        for finding in findings
    }

    assert "LINUX-AUTH-001" in finding_ids
    assert "LINUX-AUTH-002" in finding_ids
    assert "LINUX-AUTH-003" in finding_ids
    assert "LINUX-PRIV-002" in finding_ids