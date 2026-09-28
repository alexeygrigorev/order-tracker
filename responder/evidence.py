"""
Read-only evidence collector for the Order Tracker incident responder.

The responder is intentionally restricted to a predefined set of
observability queries. It can collect evidence from Prometheus, Loki,
and Tempo, but it cannot modify the application or infrastructure.
"""

import json
import urllib.parse
import urllib.request
from enum import Enum


# I keep the observability endpoints in one place so they can be
# changed later without modifying the query functions.
PROMETHEUS_URL = "http://localhost:9090"
LOKI_URL = "http://localhost:3100"
TEMPO_URL = "http://localhost:3200"


class EvidenceQuery(str, Enum):
    """
    These are the only evidence categories that the responder
    is allowed to request.
    """

    FIVE_XX_METRICS = "five_xx_metrics"
    ORDER_LOGS = "order_logs"
    ORDER_TRACES = "order_traces"


# I define an explicit allowlist instead of allowing the responder
# to construct arbitrary observability queries.
ALLOWED_QUERIES = {
    EvidenceQuery.FIVE_XX_METRICS: {
        "source": "prometheus",
        "description": (
            "Read the number of 5xx responses produced by the "
            "order lookup endpoint."
        ),
    },
    EvidenceQuery.ORDER_LOGS: {
        "source": "loki",
        "description": (
            "Read application logs related to order lookup requests."
        ),
    },
    EvidenceQuery.ORDER_TRACES: {
        "source": "tempo",
        "description": (
            "Read a specific trace related to the order lookup endpoint."
        ),
    },
}


def get_allowed_queries() -> dict:
    """
    Return a copy of the evidence allowlist.

    Returning the predefined allowlist prevents the responder from
    adding unrestricted queries at runtime.
    """

    return ALLOWED_QUERIES.copy()


def read_json(url: str) -> dict:
    """
    Send a read-only HTTP GET request and decode the JSON response.

    I use GET requests here because this evidence collector only
    reads observability data and does not modify any service.
    """

    with urllib.request.urlopen(url, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def get_five_xx_metrics() -> dict:
    """
    Read recent 5xx responses for the order lookup endpoint
    from Prometheus.

    The query counts how many matching 5xx responses were observed
    during the last five minutes.
    """

    query = (
        "sum(increase("
        "http_server_response_size_bytes_count{"
        'http_status_code=~"5..",'
        'http_target="/api/orders/{order_id}"'
        "}[5m]))"
    )

    params = urllib.parse.urlencode(
        {
            "query": query,
        }
    )

    url = f"{PROMETHEUS_URL}/api/v1/query?{params}"

    return read_json(url)


def get_order_logs() -> dict:
    """
    Read recent Order Tracker application logs from Loki.

    I use a predefined LogQL query so the responder cannot construct
    arbitrary Loki queries. The query only reads logs produced by the
    Order Tracker service.
    """

    query = '{service_name="order-tracker"}'

    params = urllib.parse.urlencode(
        {
            "query": query,
            "limit": 20,
            "direction": "backward",
        }
    )

    url = f"{LOKI_URL}/loki/api/v1/query_range?{params}"

    return read_json(url)


def get_trace(trace_id: str) -> dict:
    """
    Read a specific distributed trace from Tempo.

    The trace ID must come from previously collected observability
    evidence. This keeps the responder read-only and prevents it from
    executing arbitrary Tempo searches.
    """

    if not trace_id:
        raise ValueError("A trace_id is required.")

    url = f"{TEMPO_URL}/api/traces/{trace_id}"

    return read_json(url)


def collect_evidence(
    query: EvidenceQuery,
    trace_id: str | None = None,
) -> dict:
    """
    Execute only an allowlisted evidence query.

    The dispatcher makes the authorization boundary explicit:
    unsupported queries are rejected instead of being executed.

    Tempo requires a trace ID because traces are retrieved by their
    known identifier rather than through an arbitrary search query.
    """

    if query not in ALLOWED_QUERIES:
        raise ValueError(f"Query is not allowlisted: {query}")

    if query == EvidenceQuery.FIVE_XX_METRICS:
        return get_five_xx_metrics()

    if query == EvidenceQuery.ORDER_LOGS:
        return get_order_logs()

    if query == EvidenceQuery.ORDER_TRACES:
        if not trace_id:
            raise ValueError(
                "trace_id is required for the ORDER_TRACES evidence query."
            )

        return get_trace(trace_id)

    raise ValueError(f"Unsupported evidence query: {query}")


def build_evidence_packet(trace_id: str) -> dict:
    """
    Build a bounded evidence packet for the incident responder.

    The responder receives only evidence collected through our
    allowlisted read-only observability queries. It does not receive
    unrestricted access to Prometheus, Loki, or Tempo.
    """

    return {
        "incident": {
            "service": "order-tracker",
            "endpoint": "/api/orders/{order_id}",
            "order_id": "express-1002",
        },

        # Prometheus tells us whether users are currently seeing
        # server-side failures on the order lookup endpoint.
        "metrics": collect_evidence(
            EvidenceQuery.FIVE_XX_METRICS
        ),

        # Loki provides recent application logs produced by the
        # affected Order Tracker service.
        "logs": collect_evidence(
            EvidenceQuery.ORDER_LOGS
        ),

        # Tempo gives us the distributed trace associated with
        # the incident.
        "trace": collect_evidence(
            EvidenceQuery.ORDER_TRACES,
            trace_id=trace_id,
        ),
    }


if __name__ == "__main__":
    # I use the trace ID obtained from the incident logs so that the
    # responder can correlate metrics, logs, and traces for the same
    # user-impacting request.
    trace_id = "b3441eeb164698f390e6c6c4dcbc510f"

    evidence = build_evidence_packet(trace_id)

    # I print one structured JSON evidence packet that can later be
    # supplied to the incident responder agent.
    print(json.dumps(evidence, indent=2))