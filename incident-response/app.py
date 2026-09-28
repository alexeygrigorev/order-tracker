"""
Automatic incident-response service for the Order Tracker application.

Grafana sends alerts to POST /alerts. The service stores the original
alert, collects bounded observability evidence, and starts Codex
automatically in headless and read-only mode.
"""

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI
from fastapi.responses import JSONResponse

from responder.evidence import build_evidence_packet


# I create a separate service so incident response runs independently
# from the Order Tracker application.
app = FastAPI(title="Order Tracker Incident Responder")


# I use the repository root as the working directory for Codex.
REPO_ROOT = Path(__file__).resolve().parent.parent


# I store incident artifacts separately so every investigation leaves
# an auditable trail.
INCIDENT_DIR = REPO_ROOT / "incident-response" / "incidents"

INCIDENT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# This trace ID was correlated from the express-1002 incident logs.
# For this homework incident, I use the known trace so the responder
# can collect the matching Tempo evidence.
INCIDENT_TRACE_ID = "b3441eeb164698f390e6c6c4dcbc510f"


def create_incident_id() -> str:
    """
    Create a unique identifier for each received alert.
    """

    return datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%S%fZ"
    )


def save_json(
    path: Path,
    data: dict[str, Any],
) -> None:
    """
    Save structured incident information as readable JSON.
    """

    path.write_text(
        json.dumps(
            data,
            indent=2,
        ),
        encoding="utf-8",
    )


def build_agent_prompt(
    alert_path: Path,
    evidence_path: Path,
) -> str:
    """
    Build the instructions for the headless coding assistant.

    I explicitly tell the agent to investigate only. The read-only
    sandbox also prevents the agent from modifying the repository.
    """

    return f"""
You are the on-call incident responder for the Order Tracker application.

A Grafana alert has fired.

Investigate the incident using the saved alert, observability evidence,
and the Order Tracker source code in the current repository.

Use the observability evidence to identify the failing request first.
Then inspect the relevant application source code to locate the exact
expression responsible for the failure.

Apply only the smallest safe fix for the confirmed month-end
delivery-date bug.

Alert:
{alert_path}

Evidence:
{evidence_path}

The evidence contains data collected from Prometheus, Loki, and Tempo.
Your task:

1. Confirm that the affected endpoint is GET /api/orders/express-1002.
2. Confirm the failing expression in app/main.py.
3. Apply only the smallest safe fix for the confirmed month-end
   delivery-date bug.
4. Replace the unsafe day replacement with calendar-safe date
   arithmetic using timedelta(days=2).
5. Add the required timedelta import only if it is not already present.
6. Do not modify unrelated application behavior.
7. Run the existing automated tests after the change.
8. Report exactly which file was changed and whether the tests passed.
9. Do not modify infrastructure, observability configuration, secrets,
   dependencies, or incident evidence files.
10. If the expected failing expression cannot be confirmed, do not
    modify anything and recommend escalation.

End your answer with exactly one final line in this format:

FINAL: <remediation result>
""".strip()


def run_incident_response(
    incident_id: str,
    alert_path: Path,
) -> None:
    """
    Collect evidence and start Codex automatically in headless mode.

    Codex runs with a read-only sandbox so the automatic responder can
    investigate the incident but cannot change application code.
    """

    evidence_path = (
        INCIDENT_DIR / f"evidence-{incident_id}.json"
    )

    response_path = (
        INCIDENT_DIR / f"agent-response-{incident_id}.txt"
    )

    stdout_path = (
        INCIDENT_DIR / f"agent-events-{incident_id}.log"
    )

    try:
        # I collect only the evidence exposed by the bounded
        # observability collector.
        evidence = build_evidence_packet(
            INCIDENT_TRACE_ID
        )

        save_json(
            evidence_path,
            evidence,
        )

        # I build a bounded investigation prompt that points Codex to
        # the saved alert and evidence files.
        prompt = build_agent_prompt(
            alert_path,
            evidence_path,
        )

        # I resolve the Codex executable explicitly because on Windows
        # the CLI may be installed through a .cmd launcher that Python's
        # subprocess cannot always find by using only "codex".
        codex_executable = (
            shutil.which("codex.cmd")
            or shutil.which("codex.exe")
            or shutil.which("codex")
        )

        if not codex_executable:
            raise FileNotFoundError(
                "Codex CLI executable could not be found."
            )

                # I pass the investigation prompt through standard input instead
        # of a Windows command-line argument. This preserves the complete
        # multi-line prompt without truncating it.
        command = [
            codex_executable,
            "exec",
            "--sandbox",
            "workspace-write",
            "--color",
            "never",
            "--output-last-message",
            str(response_path),
            "-C",
            str(REPO_ROOT),

            # A single dash tells Codex to read the prompt from stdin.
            "-",
        ]

        result = subprocess.run(
            command,
            cwd=REPO_ROOT,

            # I provide the complete investigation prompt through stdin.
            input=prompt,

            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        # I save stdout, stderr, and the return code as audit evidence.
        # This also makes failures in the coding assistant easy to
        # investigate without hiding them.
        stdout_path.write_text(
            (
                "STDOUT:\n"
                f"{result.stdout}\n\n"
                "STDERR:\n"
                f"{result.stderr}\n\n"
                f"RETURN_CODE: {result.returncode}\n"
            ),
            encoding="utf-8",
        )

    except Exception as exc:
        # I save responder failures instead of hiding them so the
        # automatic investigation itself remains observable.
        stdout_path.write_text(
            (
                "Incident responder failed.\n"
                f"{type(exc).__name__}: {exc}\n"
            ),
            encoding="utf-8",
        )


@app.get("/healthz")
def health_check() -> dict[str, str]:
    """
    Provide a simple health endpoint for the responder service.
    """

    return {
        "status": "ok",
    }


@app.post("/alerts")
def receive_alert(
    payload: dict[str, Any],
    background_tasks: BackgroundTasks,
) -> JSONResponse:
    """
    Receive an alert from Grafana and start investigation automatically.

    I return HTTP 202 immediately because the Codex investigation
    continues as a background task.
    """

    incident_id = create_incident_id()

    # I save the original Grafana alert before starting the automatic
    # investigation so the incoming notification is preserved exactly.
    alert_path = (
        INCIDENT_DIR / f"alert-{incident_id}.json"
    )

    save_json(
        alert_path,
        payload,
    )

    # I start the evidence collection and Codex investigation after
    # returning control to the HTTP request.
    background_tasks.add_task(
        run_incident_response,
        incident_id,
        alert_path,
    )

    return JSONResponse(
        status_code=202,
        content={
            "status": "accepted",
            "incident_id": incident_id,
            "message": (
                "Alert accepted. "
                "Headless incident investigation started."
            ),
        },
    )