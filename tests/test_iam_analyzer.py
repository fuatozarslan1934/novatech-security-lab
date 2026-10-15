from src.iam_analyzer import scan_identity


def test_identity_security_detections():
    findings = scan_identity()

    finding_ids = {
        finding["finding_id"]
        for finding in findings
    }

    assert "IAM-RBAC-001" in finding_ids
    assert "IAM-AUTH-001" in finding_ids
    assert "IAM-AUTH-002" in finding_ids