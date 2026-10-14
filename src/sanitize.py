"""Redact sensitive values before external AI use."""

import re
from typing import Any


PATTERNS = [
    # Passwords
    (
        re.compile(
            r"(?i)\b(password|passwd|pwd)\s*[=:]\s*[^\s,;]+"
        ),
        r"\1=[REDACTED]",
    ),

    # API keys
    (
        re.compile(
            r"(?i)\b(api[_-]?key|apikey)\s*[=:]\s*[^\s,;]+"
        ),
        r"\1=[REDACTED]",
    ),

    # Tokens
    (
        re.compile(
            r"(?i)\b(access[_-]?token|refresh[_-]?token|token)\s*[=:]\s*[^\s,;]+"
        ),
        r"\1=[REDACTED]",
    ),

    # Secrets / client secrets
    (
        re.compile(
            r"(?i)\b(client[_-]?secret|secret)\s*[=:]\s*[^\s,;]+"
        ),
        r"\1=[REDACTED]",
    ),

    # Connection strings
    (
        re.compile(
            r"(?i)\b(connection[_-]?string)\s*[=:]\s*[^\n]+"
        ),
        r"\1=[REDACTED]",
    ),

    # Authorization Bearer tokens
    (
        re.compile(
            r"(?i)\bBearer\s+[A-Za-z0-9._\-]+"
        ),
        "Bearer [REDACTED]",
    ),
]


PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?"
    r"-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)


def sanitize_text(text: str) -> str:
    """Redact secrets from a text string."""

    if not isinstance(text, str):
        text = str(text)

    text = PRIVATE_KEY_PATTERN.sub(
        "[REDACTED PRIVATE KEY]",
        text,
    )

    for pattern, replacement in PATTERNS:
        text = pattern.sub(
            replacement,
            text,
        )

    return text


def sanitize_data(data: Any) -> Any:
    """
    Recursively sanitize dictionaries,
    lists, tuples, and strings.
    """

    sensitive_keys = {
        "password",
        "passwd",
        "pwd",
        "api_key",
        "apikey",
        "api-key",
        "token",
        "access_token",
        "refresh_token",
        "secret",
        "client_secret",
        "connection_string",
        "private_key",
    }

    if isinstance(data, dict):
        sanitized = {}

        for key, value in data.items():
            normalized_key = str(key).lower()

            if normalized_key in sensitive_keys:
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = sanitize_data(value)

        return sanitized

    if isinstance(data, list):
        return [
            sanitize_data(item)
            for item in data
        ]

    if isinstance(data, tuple):
        return tuple(
            sanitize_data(item)
            for item in data
        )

    if isinstance(data, str):
        return sanitize_text(data)

    return data
    
