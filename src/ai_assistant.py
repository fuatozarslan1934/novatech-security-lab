"""Optional evidence-grounded AI investigation assistant."""

import json
import os

from dotenv import load_dotenv

from sanitize import sanitize_data


load_dotenv()


def build_ai_prompt(investigation):
    """
    Build a sanitized, evidence-grounded prompt.
    """

    sanitized = sanitize_data(investigation)

    evidence_json = json.dumps(
        sanitized,
        indent=2,
        default=str,
    )

    return f"""
You are assisting with a cybersecurity incident investigation.

Use ONLY the evidence provided below.
Do not invent events, identities, systems, or conclusions.

Provide:

1. Executive Summary
2. Key Evidence
3. Likely Attack Sequence
4. Risk Assessment
5. Recommended Investigation Actions
6. Confidence and Limitations

Clearly distinguish facts from reasonable hypotheses.

SANITIZED INVESTIGATION EVIDENCE:

{evidence_json}
"""


def get_ai_analysis(investigation):
    """
    Send sanitized evidence to OpenAI if configured.

    Returns a dictionary so the CLI can handle
    success and failure cleanly.
    """

    api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        return {
            "success": False,
            "message": (
                "OPENAI_API_KEY is not configured. "
                "AI analysis was skipped."
            ),
        }

    try:
        from openai import OpenAI

        client = OpenAI(
            api_key=api_key
        )

        prompt = build_ai_prompt(
            investigation
        )

        model = os.getenv(
            "OPENAI_MODEL",
            "gpt-4o-mini",
        )

        response = client.responses.create(
            model=model,
            input=prompt,
        )

        return {
            "success": True,
            "model": model,
            "analysis": response.output_text,
        }

    except Exception as error:
        return {
            "success": False,
            "message": (
                "AI analysis failed: "
                f"{error}"
            ),
        }


def print_ai_analysis(investigation):
    print(
        "\nNOVATECH AI INVESTIGATION ASSISTANT\n"
    )

    result = get_ai_analysis(
        investigation
    )

    if not result["success"]:
        print(result["message"])
        print(
            "Deterministic investigation "
            "results remain available."
        )
        return

    print(
        f"Model: {result['model']}\n"
    )

    print(result["analysis"])
