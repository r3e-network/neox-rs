#!/usr/bin/env python3
"""Watch a running neox-rs node and raise exception notifications when it is unhealthy.

This is an operational sidecar: it never touches the node process. It polls the node's JSON-RPC and
Prometheus ``/metrics`` endpoints, evaluates the health criteria documented in
``docs/neox/OPERATIONS.md`` (canonical height advancing, beacon/dBFT peers present, dBFT rejections
and DKG failures not spiking), and reports the outcome to one or more notification channels:

* **Better Stack heartbeat** (recommended). A healthy check pings
  ``https://uptime.betterstack.com/api/v1/heartbeat/<token>``; an unhealthy check pings the same URL
  with a ``/fail`` suffix and the reason as the body. If the watcher itself dies, the missed ping
  trips Better Stack's grace period, so both stalls and full outages are covered.
* **Better Stack incidents API** (optional). Creates a single incident (Bearer auth,
  ``/api/v3/incidents``) on the transition to unhealthy and resolves it on recovery, for teams that
  want a distinct incident object with on-call escalation.
* **Generic webhook** (optional). POSTs a small JSON body to any URL (Slack incoming webhook, a
  Better Stack incoming webhook, PagerDuty Events, etc.).

Run it continuously (systemd/container) with ``--interval``, or once per invocation with ``--once``
for a cron job or a Kubernetes liveness/readiness probe (exit code 0 = healthy, 1 = unhealthy).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

# Prometheus metric names exposed by the node (scope "neox.sync"/"neox.dkg" -> "reth_neox_sync_*").
METRIC_BEACON_PEERS = "reth_neox_sync_beacon_peers"
METRIC_DBFT_PEERS = "reth_neox_sync_dbft_peers"
METRIC_CANONICAL_HEIGHT = "reth_neox_sync_canonical_height"
METRIC_DBFT_REJECTED = "reth_neox_sync_dbft_transitions_rejected_total"
METRIC_DKG_SUBMISSION_FAILURES = "reth_neox_dkg_submission_failures_total"
METRIC_DKG_PREP_FAILURES = "reth_neox_dkg_task_preparation_failures_total"
METRIC_DKG_EXPIRED = "reth_neox_dkg_expired_total"


class HealthState:
    """Carries the per-cycle state the stateless checks cannot hold themselves."""

    def __init__(self) -> None:
        self.last_height: int | None = None
        self.last_height_advance: float | None = None
        self.previous_counters: dict[str, float] = {}
        self.unhealthy_since: float | None = None
        self.incident_id: str | None = None
        self.last_channel_state: bool | None = None


class HttpClient:
    """Minimal stdlib HTTP client used for both node polling and notification delivery."""

    def __init__(self, timeout: float) -> None:
        self.timeout = timeout

    def get_text(self, url: str) -> str:
        request = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return response.read().decode("utf-8")

    def post_json(self, url: str, payload: dict, headers: dict | None = None) -> tuple[int, str]:
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(url, data=body, method="POST")
        request.add_header("Content-Type", "application/json")
        for key, value in (headers or {}).items():
            request.add_header(key, value)
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return response.status, response.read().decode("utf-8", "replace")

    def post_raw(self, url: str, body: bytes) -> int:
        request = urllib.request.Request(url, data=body, method="POST")
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return response.status


def now() -> float:
    return time.time()


def log(message: str) -> None:
    print(f"[{time.strftime('%Y-%m-%dT%H:%M:%S%z')}] {message}", flush=True)


def rpc_call(client: HttpClient, url: str, method: str, params: list) -> object:
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    status, text = client.post_json(url, payload)
    if status != 200:
        raise RuntimeError(f"RPC HTTP {status}")
    response = json.loads(text)
    if "error" in response:
        raise RuntimeError(f"RPC error: {response['error']}")
    return response["result"]


def parse_metrics(text: str) -> dict[str, float]:
    """Parses the Prometheus text exposition format into a flat name->value map.

    Labels are ignored: the Neo X sync/DKG metrics of interest are single-series gauges and counters,
    so the last sample for a bare metric name is authoritative.
    """
    values: dict[str, float] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        name = parts[0]
        if "{" in name:
            name = name[: name.index("{")]
        try:
            values[name] = float(parts[-1])
        except ValueError:
            continue
    return values


def evaluate_health(config: argparse.Namespace, client: HttpClient, state: HealthState) -> tuple[bool, list[str], dict]:
    """Returns (healthy, reasons, status) for the current cycle."""
    reasons: list[str] = []
    status: dict = {}
    current = now()

    try:
        height_hex = rpc_call(client, config.rpc_url, "eth_blockNumber", [])
        height = int(height_hex, 16)
        status["height"] = height
    except (urllib.error.URLError, OSError, RuntimeError, ValueError, KeyError) as error:
        reasons.append(f"RPC unreachable at {config.rpc_url}: {error}")
        return False, reasons, status

    if state.last_height is None or height > state.last_height:
        state.last_height = height
        state.last_height_advance = current
    stalled_for = current - (state.last_height_advance or current)
    if stalled_for > config.stall_seconds:
        reasons.append(
            f"canonical height stalled at {height} for {int(stalled_for)}s "
            f"(limit {config.stall_seconds}s)"
        )

    if config.metrics_url:
        try:
            metrics = parse_metrics(client.get_text(config.metrics_url))
        except (urllib.error.URLError, OSError) as error:
            reasons.append(f"metrics endpoint unreachable at {config.metrics_url}: {error}")
            return False, reasons, status
        evaluate_metrics(config, metrics, state, reasons, status)

    return len(reasons) == 0, reasons, status


def evaluate_metrics(
    config: argparse.Namespace,
    metrics: dict[str, float],
    state: HealthState,
    reasons: list[str],
    status: dict,
) -> None:
    beacon_peers = metrics.get(METRIC_BEACON_PEERS)
    if beacon_peers is not None:
        status["beacon_peers"] = int(beacon_peers)
        if beacon_peers < config.min_beacon_peers:
            reasons.append(
                f"beacon peers {int(beacon_peers)} below minimum {config.min_beacon_peers}"
            )

    if config.validator:
        dbft_peers = metrics.get(METRIC_DBFT_PEERS)
        if dbft_peers is not None:
            status["dbft_peers"] = int(dbft_peers)
            if dbft_peers < config.min_dbft_peers:
                reasons.append(
                    f"dBFT peers {int(dbft_peers)} below validator minimum {config.min_dbft_peers}"
                )

    _counter_spike(
        metrics, state, reasons, METRIC_DBFT_REJECTED, config.max_rejected_delta, "dBFT rejections"
    )
    if config.dkg:
        _counter_spike(
            metrics, state, reasons, METRIC_DKG_SUBMISSION_FAILURES, config.max_dkg_failures_delta,
            "DKG submission failures",
        )
        _counter_spike(
            metrics, state, reasons, METRIC_DKG_PREP_FAILURES, config.max_dkg_failures_delta,
            "DKG preparation failures",
        )
        _counter_spike(
            metrics, state, reasons, METRIC_DKG_EXPIRED, config.max_dkg_expired_delta,
            "expired DKG tasks",
        )


def _counter_spike(
    metrics: dict[str, float],
    state: HealthState,
    reasons: list[str],
    name: str,
    limit: int,
    label: str,
) -> None:
    """Flags a monotonic counter that grew by more than ``limit`` since the previous cycle."""
    value = metrics.get(name)
    if value is None:
        return
    previous = state.previous_counters.get(name)
    state.previous_counters[name] = value
    if previous is None:
        return
    delta = value - previous
    # A counter reset (node restart) makes the delta negative; treat that as no spike.
    if delta > limit:
        reasons.append(f"{label} increased by {int(delta)} in one interval (limit {limit})")


def notify(config: argparse.Namespace, client: HttpClient, state: HealthState, healthy: bool, reasons: list[str], status: dict) -> None:
    transition = state.last_channel_state is None or state.last_channel_state != healthy
    state.last_channel_state = healthy
    summary = "neox-rs healthy" if healthy else "neox-rs UNHEALTHY: " + "; ".join(reasons)
    detail = json.dumps({"healthy": healthy, "reasons": reasons, "status": status})

    if config.betterstack_heartbeat_url:
        _send_heartbeat(client, config.betterstack_heartbeat_url, healthy, detail)

    if config.betterstack_incident_token and transition:
        _send_incident(config, client, state, healthy, summary, detail)

    if config.webhook_url and (transition or not healthy):
        _send_webhook(client, config.webhook_url, summary, healthy, reasons, status)


def _send_heartbeat(client: HttpClient, base_url: str, healthy: bool, detail: str) -> None:
    url = base_url if healthy else base_url.rstrip("/") + "/fail"
    try:
        client.post_raw(url, detail.encode("utf-8"))
    except (urllib.error.URLError, OSError) as error:
        log(f"heartbeat delivery failed: {error}")


def _send_incident(config: argparse.Namespace, client: HttpClient, state: HealthState, healthy: bool, summary: str, detail: str) -> None:
    try:
        headers = {"Authorization": f"Bearer {config.betterstack_incident_token}"}
        if not healthy:
            payload = {
                "summary": summary[:255],
                "description": detail,
                "requester_email": config.betterstack_requester_email,
                "call": config.betterstack_call,
                "sms": config.betterstack_sms,
            }
            _status, text = client.post_json(config.betterstack_incidents_url, payload, headers)
            try:
                state.incident_id = json.loads(text)["data"]["id"]
            except (json.JSONDecodeError, KeyError, TypeError):
                state.incident_id = None
        elif state.incident_id:
            resolve_url = (
                config.betterstack_incidents_url.rstrip("/") + f"/{state.incident_id}/resolve"
            )
            client.post_json(resolve_url, {"resolved_by": config.betterstack_requester_email}, headers)
            state.incident_id = None
    except (urllib.error.URLError, OSError) as error:
        log(f"incident delivery failed: {error}")


def _send_webhook(client: HttpClient, url: str, summary: str, healthy: bool, reasons: list[str], status: dict) -> None:
    payload = {"text": summary, "healthy": healthy, "reasons": reasons, "status": status}
    try:
        client.post_json(url, payload)
    except (urllib.error.URLError, OSError) as error:
        log(f"webhook delivery failed: {error}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Neo X node health watcher and exception notifier.")
    parser.add_argument("--rpc-url", default=os.environ.get("NEOX_RPC_URL", "http://127.0.0.1:8545"))
    parser.add_argument(
        "--metrics-url",
        default=os.environ.get("NEOX_METRICS_URL", "http://127.0.0.1:9001"),
        help="Prometheus /metrics URL; set empty to run RPC-only checks.",
    )
    parser.add_argument("--interval", type=float, default=30.0)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--once", action="store_true", help="Run one check and exit (0 healthy, 1 unhealthy).")
    parser.add_argument("--stall-seconds", type=float, default=120.0)
    parser.add_argument("--min-beacon-peers", type=int, default=1)
    parser.add_argument("--min-dbft-peers", type=int, default=1)
    parser.add_argument("--validator", action="store_true", help="Also require dBFT peers and check DKG.")
    parser.add_argument("--dkg", action="store_true", help="Evaluate DKG runtime failure/expiry counters.")
    parser.add_argument("--max-rejected-delta", type=int, default=50)
    parser.add_argument("--max-dkg-failures-delta", type=int, default=1)
    parser.add_argument("--max-dkg-expired-delta", type=int, default=0)
    parser.add_argument("--betterstack-heartbeat-url", default=os.environ.get("BETTERSTACK_HEARTBEAT_URL"))
    parser.add_argument("--betterstack-incident-token", default=os.environ.get("BETTERSTACK_API_TOKEN"))
    parser.add_argument(
        "--betterstack-incidents-url",
        default=os.environ.get("BETTERSTACK_INCIDENTS_URL", "https://uptime.betterstack.com/api/v3/incidents"),
    )
    parser.add_argument("--betterstack-requester-email", default=os.environ.get("BETTERSTACK_REQUESTER_EMAIL", ""))
    parser.add_argument("--betterstack-call", action="store_true", help="Escalate incidents by phone call.")
    parser.add_argument("--betterstack-sms", action="store_true", help="Escalate incidents by SMS.")
    parser.add_argument("--webhook-url", default=os.environ.get("NEOX_ALERT_WEBHOOK"))
    return parser


def validate_config(config: argparse.Namespace) -> None:
    if config.validator:
        config.dkg = True
    if config.betterstack_incident_token and not config.betterstack_requester_email:
        raise SystemExit("--betterstack-requester-email is required when using the incidents API")
    if not any([config.betterstack_heartbeat_url, config.betterstack_incident_token, config.webhook_url]):
        log("warning: no notification channel configured; running in log-only mode")


def run(config: argparse.Namespace) -> int:
    validate_config(config)
    client = HttpClient(config.timeout)
    state = HealthState()
    while True:
        healthy, reasons, status = evaluate_health(config, client, state)
        if healthy:
            log(f"healthy {json.dumps(status)}")
        else:
            log("UNHEALTHY: " + "; ".join(reasons))
        notify(config, client, state, healthy, reasons, status)
        if config.once:
            return 0 if healthy else 1
        time.sleep(config.interval)


def main(argv: list[str] | None = None) -> int:
    config = build_parser().parse_args(argv)
    try:
        return run(config)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
