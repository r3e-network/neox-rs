"""Hermetic tests for the Neo X health watcher and exception notifier."""

from __future__ import annotations

import argparse
import importlib.util
import pathlib
import sys
import unittest
import urllib.error

SCRIPT = pathlib.Path(__file__).parents[1] / "neox-health-notify.py"
SPEC = importlib.util.spec_from_file_location("neox_health_notify", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
HN = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HN
SPEC.loader.exec_module(HN)


METRICS_HEALTHY = """\
# HELP reth_neox_sync_canonical_height Current canonical Neo X block height.
# TYPE reth_neox_sync_canonical_height gauge
reth_neox_sync_canonical_height 100
reth_neox_sync_beacon_peers 5
reth_neox_sync_dbft_peers 6
reth_neox_sync_dbft_transitions_rejected_total 3
reth_neox_dkg_submission_failures_total 0
reth_neox_dkg_task_preparation_failures_total 0
reth_neox_dkg_expired_total 0
"""


def config(**overrides) -> argparse.Namespace:
    parser = HN.build_parser()
    cfg = parser.parse_args([])
    cfg.rpc_url = "http://node/rpc"
    cfg.metrics_url = "http://node/metrics"
    cfg.stall_seconds = 120.0
    cfg.min_beacon_peers = 1
    cfg.min_dbft_peers = 1
    cfg.max_rejected_delta = 50
    for key, value in overrides.items():
        setattr(cfg, key, value)
    return cfg


class FakeClient(HN.HttpClient):
    """Serves canned node responses and records every notification call."""

    def __init__(self, *, height=0x64, metrics=METRICS_HEALTHY, fail_urls=()):
        super().__init__(timeout=1.0)
        self.height = height
        self.metrics = metrics
        self.fail_urls = set(fail_urls)
        self.heartbeats: list[tuple[str, bytes]] = []
        self.json_posts: list[tuple[str, dict, dict]] = []

    def get_text(self, url: str) -> str:
        if url in self.fail_urls:
            raise urllib.error.URLError("boom")
        if "metrics" in url:
            return self.metrics
        raise AssertionError(f"unexpected GET {url}")

    def post_json(self, url, payload, headers=None):
        if url in self.fail_urls:
            raise urllib.error.URLError("boom")
        if "rpc" in url:
            return 200, '{"jsonrpc":"2.0","id":1,"result":"' + hex(self.height) + '"}'
        self.json_posts.append((url, payload, headers or {}))
        if "incidents" in url and not url.endswith("resolve"):
            return 201, '{"data": {"id": "inc-1"}}'
        return 200, "{}"

    def post_raw(self, url, body):
        if url in self.fail_urls:
            raise urllib.error.URLError("boom")
        self.heartbeats.append((url, body))
        return 202


class ManualClock:
    def __init__(self) -> None:
        self.value = 1_000.0

    def __call__(self) -> float:
        return self.value


class ParseMetricsTest(unittest.TestCase):
    def test_ignores_comments_and_labels(self) -> None:
        text = 'a_total{k="v"} 7\n# comment\nb 3.5\ngarbage line\n'
        parsed = HN.parse_metrics(text)
        self.assertEqual(parsed["a_total"], 7.0)
        self.assertEqual(parsed["b"], 3.5)
        self.assertNotIn("garbage", parsed)


class EvaluateHealthTest(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = ManualClock()
        self._real_now = HN.now
        HN.now = self.clock
        self.addCleanup(lambda: setattr(HN, "now", self._real_now))

    def test_healthy(self) -> None:
        cfg = config(validator=True, dkg=True)
        state = HN.HealthState()
        healthy, reasons, status = HN.evaluate_health(cfg, FakeClient(), state)
        self.assertTrue(healthy, reasons)
        self.assertEqual(status["height"], 100)
        self.assertEqual(status["beacon_peers"], 5)

    def test_rpc_unreachable(self) -> None:
        cfg = config()
        client = FakeClient(fail_urls=["http://node/rpc"])
        healthy, reasons, _ = HN.evaluate_health(cfg, client, HN.HealthState())
        self.assertFalse(healthy)
        self.assertIn("RPC unreachable", reasons[0])

    def test_metrics_unreachable(self) -> None:
        cfg = config()
        client = FakeClient(fail_urls=["http://node/metrics"])
        healthy, reasons, _ = HN.evaluate_health(cfg, client, HN.HealthState())
        self.assertFalse(healthy)
        self.assertIn("metrics endpoint unreachable", reasons[0])

    def test_height_stall(self) -> None:
        cfg = config(stall_seconds=60.0)
        state = HN.HealthState()
        client = FakeClient()
        self.assertTrue(HN.evaluate_health(cfg, client, state)[0])
        self.clock.value += 61  # height unchanged past the stall limit
        healthy, reasons, _ = HN.evaluate_health(cfg, client, state)
        self.assertFalse(healthy)
        self.assertIn("stalled", reasons[0])

    def test_height_advance_clears_stall(self) -> None:
        cfg = config(stall_seconds=60.0)
        state = HN.HealthState()
        client = FakeClient()
        HN.evaluate_health(cfg, client, state)
        self.clock.value += 61
        client.height += 1  # a new block arrives
        self.assertTrue(HN.evaluate_health(cfg, client, state)[0])

    def test_low_beacon_peers(self) -> None:
        metrics = METRICS_HEALTHY.replace("beacon_peers 5", "beacon_peers 0")
        healthy, reasons, _ = HN.evaluate_health(config(), FakeClient(metrics=metrics), HN.HealthState())
        self.assertFalse(healthy)
        self.assertIn("beacon peers", reasons[0])

    def test_validator_requires_dbft_peers(self) -> None:
        metrics = METRICS_HEALTHY.replace("dbft_peers 6", "dbft_peers 0")
        cfg = config(validator=True, min_dbft_peers=1)
        healthy, reasons, _ = HN.evaluate_health(cfg, FakeClient(metrics=metrics), HN.HealthState())
        self.assertFalse(healthy)
        self.assertTrue(any("dBFT peers" in reason for reason in reasons))

    def test_rejection_spike(self) -> None:
        cfg = config(max_rejected_delta=10)
        state = HN.HealthState()
        self.assertTrue(HN.evaluate_health(cfg, FakeClient(), state)[0])
        spiked = METRICS_HEALTHY.replace("rejected_total 3", "rejected_total 100")
        healthy, reasons, _ = HN.evaluate_health(cfg, FakeClient(metrics=spiked), state)
        self.assertFalse(healthy)
        self.assertTrue(any("dBFT rejections" in reason for reason in reasons))

    def test_counter_reset_is_not_a_spike(self) -> None:
        cfg = config()
        state = HN.HealthState()
        HN.evaluate_health(cfg, FakeClient(), state)  # rejected_total = 3
        reset = METRICS_HEALTHY.replace("rejected_total 3", "rejected_total 0")  # node restart
        self.assertTrue(HN.evaluate_health(cfg, FakeClient(metrics=reset), state)[0])

    def test_dkg_expiry(self) -> None:
        cfg = config(validator=True, dkg=True, max_dkg_expired_delta=0)
        state = HN.HealthState()
        HN.evaluate_health(cfg, FakeClient(), state)
        expired = METRICS_HEALTHY.replace("expired_total 0", "expired_total 2")
        healthy, reasons, _ = HN.evaluate_health(cfg, FakeClient(metrics=expired), state)
        self.assertFalse(healthy)
        self.assertTrue(any("expired DKG tasks" in reason for reason in reasons))


class NotifyTest(unittest.TestCase):
    def test_heartbeat_healthy_then_fail(self) -> None:
        cfg = config(betterstack_heartbeat_url="https://hb.test/api/v1/heartbeat/tok")
        state = HN.HealthState()
        client = FakeClient()
        HN.notify(cfg, client, state, True, [], {"height": 100})
        HN.notify(cfg, client, state, False, ["stalled"], {"height": 100})
        self.assertEqual(client.heartbeats[0][0], "https://hb.test/api/v1/heartbeat/tok")
        self.assertEqual(client.heartbeats[1][0], "https://hb.test/api/v1/heartbeat/tok/fail")
        self.assertIn(b"stalled", client.heartbeats[1][1])

    def test_incident_created_on_transition_and_resolved(self) -> None:
        cfg = config(
            betterstack_incident_token="team-tok",
            betterstack_requester_email="ops@neox.test",
            betterstack_incidents_url="https://inc.test/api/v3/incidents",
        )
        state = HN.HealthState()
        client = FakeClient()
        HN.notify(cfg, client, state, True, [], {})  # first cycle healthy: no incident
        HN.notify(cfg, client, state, False, ["stalled"], {})  # transition -> create
        self.assertEqual(state.incident_id, "inc-1")
        create = [p for p in client.json_posts if p[0].endswith("/incidents")]
        self.assertEqual(len(create), 1)
        self.assertEqual(create[0][2]["Authorization"], "Bearer team-tok")
        self.assertEqual(create[0][1]["requester_email"], "ops@neox.test")
        HN.notify(cfg, client, state, False, ["stalled"], {})  # still unhealthy: no duplicate
        self.assertEqual(len([p for p in client.json_posts if p[0].endswith("/incidents")]), 1)
        HN.notify(cfg, client, state, True, [], {})  # recovery -> resolve
        self.assertIsNone(state.incident_id)
        self.assertTrue(any(p[0].endswith("/resolve") for p in client.json_posts))

    def test_delivery_failure_does_not_raise(self) -> None:
        cfg = config(
            betterstack_heartbeat_url="https://hb.test/fail-me",
            webhook_url="https://hook.test/fail-me",
        )
        client = FakeClient(fail_urls=["https://hb.test/fail-me/fail", "https://hook.test/fail-me"])
        # Must not raise even though both channels error.
        HN.notify(cfg, client, HN.HealthState(), False, ["stalled"], {})


class RunOnceTest(unittest.TestCase):
    def test_once_exit_codes(self) -> None:
        self._real_now = HN.now
        HN.now = ManualClock()
        self.addCleanup(lambda: setattr(HN, "now", self._real_now))
        healthy_client = FakeClient()
        cfg = config(once=True, validator=True)
        # Patch HttpClient construction inside run() by injecting via a subclass swap.
        original = HN.HttpClient
        HN.HttpClient = lambda timeout: healthy_client
        self.addCleanup(lambda: setattr(HN, "HttpClient", original))
        self.assertEqual(HN.run(cfg), 0)

        bad = FakeClient(fail_urls=["http://node/rpc"])
        HN.HttpClient = lambda timeout: bad
        self.assertEqual(HN.run(config(once=True)), 1)


if __name__ == "__main__":
    unittest.main()
