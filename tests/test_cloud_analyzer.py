from src.cloud_analyzer import scan_cloud


def test_cloud_security_detections():
    findings = scan_cloud()

    finding_ids = {
        finding["finding_id"]
        for finding in findings
    }

    assert "CLOUD-VM-001" in finding_ids
    assert "CLOUD-SQL-003" in finding_ids
    assert "CLOUD-NSG-001" in finding_ids