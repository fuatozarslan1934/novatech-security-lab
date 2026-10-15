from src.correlator import investigate_incident


def test_incident_004_multi_source_correlation():
    result = investigate_incident("INC-004")

    assert result is not None

    correlation = result["correlation"]

    assert correlation["event_count"] == 23
    assert "Cisco" in correlation["sources"]
    assert "Linux" in correlation["sources"]
    assert "Entra ID" in correlation["sources"]
    assert "Firewall" in correlation["sources"]
    assert "Azure Activity" in correlation["sources"]


def test_incident_001_linux_focus():
    result = investigate_incident("INC-001")

    correlation = result["correlation"]

    assert correlation["sources"] == ["Linux"]
    assert correlation["event_count"] == 6