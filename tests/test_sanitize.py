from src.sanitize import sanitize_text

def test_password_redaction():
    text = "password=SuperSecret123"
    assert "SuperSecret123" not in sanitize_text(text)
    assert "[REDACTED]" in sanitize_text(text)
