"""
Headless incident responder for the Order Tracker application.

The responder analyzes a bounded evidence packet collected from the
observability stack. It can diagnose the incident and propose a response,
but it is not allowed to modify the application or infrastructure.
"""

import json
from pathlib import Path
from typing import Any

from responder.evidence import build_evidence_packet


# I keep the responder instructions in code so the investigation
# boundaries are explicit and reviewable.
SYSTEM_PROMPT = """
You are the incident responder for the Order Tracker application.

Analyze only the evidence provided to you.

Rules:
1. Do not invent evidence that is not present in the evidence packet.
2. Distinguish observed facts from conclusions.
3. Identify the user impact.
4. Identify the most likely root cause only when supported by evidence.
5. Propose a bounded response, but do not execute commands or modify files.
6. If the evidence is insufficient, say that escalation is required.
7. Return valid JSON only.

Return this structure:

{
  "status": "diagnosed | insufficient_evidence",
  "user_impact": "...",
  "observations": ["..."],
  "root_cause": "...",
  "proposed_action": "...",
  "requires_authorization": true,
  "final_line": "..."
}
"""


def create_responder_input(trace_id: str) -> dict[str, Any]:
    """
    Build the complete input that will be provided to the responder.

    I keep the instructions and evidence separate so it is clear which
    information is policy and which information came from telemetry.
    """

    evidence = build_evidence_packet(trace_id)

    return {
        "instructions": SYSTEM_PROMPT.strip(),
        "evidence": evidence,
    }


def save_responder_input(
    responder_input: dict[str, Any],
    output_path: str = "responder/responder-input.json",
) -> None:
    """
    Save the bounded responder input to disk.

    This gives me an auditable record of the exact evidence and
    instructions that were provided to the incident responder.
    """

    path = Path(output_path)

    path.write_text(
        json.dumps(responder_input, indent=2),
        encoding="utf-8",
    )


if __name__ == "__main__":
    # I use the trace ID correlated from the Loki evidence for the
    # express order incident.
    trace_id = "b3441eeb164698f390e6c6c4dcbc510f"

    responder_input = create_responder_input(trace_id)

    save_responder_input(responder_input)

    print(
        json.dumps(
            responder_input,
            indent=2,
        )
    )