from __future__ import absolute_import

import copy
import json
import socket
import unittest

from neutron_aria.agent.uds_client import LocalApiContractError
from neutron_aria.agent.uds_client import LocalApiResponseError
from neutron_aria.agent.uds_client import LocalApiTimeoutError
from neutron_aria.agent.uds_client import LocalClient
from neutron_aria.tests.unit.status_contract_scenarios import load_status_contract_fixture
from neutron_aria.tests.unit.status_contract_scenarios import status_scenario
from neutron_aria.tests.unit.status_contract_scenarios import status_scenario_cases
from neutron_aria.tests.unit.status_contract_scenarios import status_scenario_contract_error_cases


class FakeResponse(object):
    def __init__(self, status, reason, body):
        self.status = status
        self.reason = reason
        self.body = body

    def read(self, _size):
        if isinstance(self.body, str):
            return self.body
        return json.dumps(self.body)


class FakeConnection(object):
    requests = []
    responses = []
    timeouts = []

    def __init__(self, _socket_path, timeout):
        self.closed = False
        self.timeouts.append(timeout)

    def request(self, method, path, body=None, headers=None):
        self.requests.append({
            "method": method,
            "path": path,
            "body": body,
            "headers": headers or {},
        })

    def getresponse(self):
        return self.responses.pop(0)

    def close(self):
        self.closed = True


class TimeoutConnection(FakeConnection):
    def getresponse(self):
        raise socket.timeout("timed out")


class UdsClientTestCase(unittest.TestCase):
    def setUp(self):
        FakeConnection.requests = []
        FakeConnection.responses = []
        FakeConnection.timeouts = []
        self.client = LocalClient(
            "/tmp/aria-agent.sock",
            timeout=1.0,
            connection_factory=FakeConnection,
        )

    def _capabilities(self, **overrides):
        body = {
            "api_version": "v1",
            "contract_version": "2026-06-v0.9",
            "schema_version_min": 1,
            "schema_version_max": 1,
            "attach_authority": "neutron_snapshot",
            "supports_full_snapshot": True,
            "supports_port_delete": True,
            "supported_domains": ["attach", "acl", "qos"],
            "mandatory_domains": [],
            "body_max_bytes": 1048576,
            "timeout_ms": 3000,
            "error_codes_hash": "v0.9-neutron-errors-2",
            "peer_auth_policy": "filesystem_permissions_then_peercred",
            "capability_hash": "v0.9-neutron-capabilities-3",
        }
        body.update(overrides)
        return body

    def test_capabilities_validates_required_domains(self):
        FakeConnection.responses.append(FakeResponse(200, "OK", self._capabilities()))

        body = self.client.capabilities(required_domains=["acl"])

        self.assertEqual("v1", body["api_version"])
        self.assertEqual("2026-06-v0.9", body["contract_version"])
        self.assertEqual("GET", FakeConnection.requests[0]["method"])
        self.assertEqual("/api/v1/neutron/capabilities", FakeConnection.requests[0]["path"])

    def test_capabilities_rejects_missing_domain(self):
        FakeConnection.responses.append(
            FakeResponse(200, "OK", self._capabilities(supported_domains=["attach"]))
        )

        self.assertRaises(
            LocalApiContractError,
            self.client.capabilities,
            required_domains=["acl"],
        )

    def test_capabilities_accepts_legacy_response_without_target_fields(self):
        FakeConnection.responses.append(FakeResponse(200, "OK", {
            "api_version": "v1",
            "attach_authority": "neutron_snapshot",
            "supports_full_snapshot": True,
            "supports_port_delete": True,
            "supported_domains": ["attach", "acl"],
        }))

        body = self.client.capabilities(required_domains=["acl"])

        self.assertEqual("v1", body["api_version"])

    def test_capabilities_rejects_contract_version_mismatch(self):
        FakeConnection.responses.append(
            FakeResponse(200, "OK", self._capabilities(contract_version="other"))
        )

        self.assertRaises(LocalApiContractError, self.client.capabilities)

    def test_capabilities_rejects_schema_range_mismatch(self):
        FakeConnection.responses.append(
            FakeResponse(200, "OK", self._capabilities(schema_version_min=2, schema_version_max=3))
        )

        self.assertRaises(LocalApiContractError, self.client.capabilities)

    def test_capabilities_rejects_invalid_body_limit(self):
        FakeConnection.responses.append(
            FakeResponse(200, "OK", self._capabilities(body_max_bytes="not-an-int"))
        )

        self.assertRaises(LocalApiContractError, self.client.capabilities)

    def test_capabilities_tightens_request_body_limit(self):
        FakeConnection.responses.append(
            FakeResponse(200, "OK", self._capabilities(body_max_bytes=128))
        )

        self.client.capabilities(required_domains=["acl"])

        self.assertEqual(128, self.client.max_request_bytes)

    def test_capabilities_rejects_invalid_timeout(self):
        FakeConnection.responses.append(
            FakeResponse(200, "OK", self._capabilities(timeout_ms="not-an-int"))
        )

        self.assertRaises(LocalApiContractError, self.client.capabilities)

    def test_port_capability_timeout_is_request_local(self):
        client = LocalClient(
            "/tmp/aria-agent.sock",
            timeout=5.0,
            connection_factory=FakeConnection,
        )
        FakeConnection.responses.extend([
            FakeResponse(200, "OK", self._capabilities(
                timeout_ms=2500,
                supports_port_scoped_snapshot=True,
            )),
            FakeResponse(200, "OK", {
                "generation": 13,
                "results": [],
                "active_instances": [],
            }),
            FakeResponse(200, "OK", {
                "generation": 14,
                "results": [],
                "active_instances": [],
            }),
        ])

        client.put_port_snapshot(
            "target-port",
            {
                "generation": 13,
                "host": "ostack2",
                "ports": [{"port_id": "target-port", "ifname": "tap1"}],
            },
            required_domains=["acl"],
        )
        client.put_snapshot({
            "generation": 14,
            "host": "ostack2",
            "ports": [],
        })

        self.assertEqual([5.0, 2.5, 5.0], FakeConnection.timeouts)
        self.assertEqual(5.0, client.timeout)

    def test_capabilities_rejects_error_hash_mismatch(self):
        FakeConnection.responses.append(
            FakeResponse(200, "OK", self._capabilities(error_codes_hash="other"))
        )

        self.assertRaises(LocalApiContractError, self.client.capabilities)

    def test_capabilities_rejects_capability_hash_mismatch(self):
        FakeConnection.responses.append(
            FakeResponse(200, "OK", self._capabilities(capability_hash="other"))
        )

        self.assertRaises(LocalApiContractError, self.client.capabilities)

    def test_put_snapshot_serializes_json_body(self):
        FakeConnection.responses.append(
            FakeResponse(200, "OK", self._capabilities())
        )
        self.client.capabilities(required_domains=["acl"])
        FakeConnection.requests = []
        FakeConnection.responses.append(FakeResponse(200, "OK", {
            "generation": 12,
            "results": [],
            "active_instances": [],
        }))

        self.client.put_snapshot({"generation": 12, "host": "ostack2", "ports": []})

        request = FakeConnection.requests[0]
        self.assertEqual("PUT", request["method"])
        self.assertEqual("/api/v1/neutron/snapshot", request["path"])
        self.assertEqual("application/json", request["headers"]["Content-Type"])
        self.assertEqual(12, json.loads(request["body"])["generation"])

    def test_recover_pending_snapshot_serializes_json_body(self):
        FakeConnection.responses.append(
            FakeResponse(200, "OK", self._capabilities())
        )
        self.client.capabilities(required_domains=["acl"])
        FakeConnection.requests = []
        FakeConnection.responses.append(FakeResponse(200, "OK", {
            "status": "recovered",
            "recovered_generation": 380,
            "applied_generation": 379,
        }))

        self.client.recover_pending_snapshot(380, "hash-380")

        request = FakeConnection.requests[0]
        self.assertEqual("POST", request["method"])
        self.assertEqual(
            "/api/v1/neutron/snapshot/recover-pending",
            request["path"],
        )
        body = json.loads(request["body"])
        self.assertEqual(380, body["expected_pending_generation"])
        self.assertEqual("hash-380", body["expected_desired_hash"])
        self.assertEqual("rollback_to_last_applied", body["mode"])

    def test_put_snapshot_rejects_oversized_json_body_before_send(self):
        client = LocalClient(
            "/tmp/aria-agent.sock",
            timeout=1.0,
            max_request_bytes=16,
            connection_factory=FakeConnection,
        )
        FakeConnection.responses.append(
            FakeResponse(200, "OK", self._capabilities())
        )
        client.capabilities(required_domains=["acl"])
        FakeConnection.requests = []

        self.assertRaises(
            LocalApiContractError,
            client.put_snapshot,
            {"generation": 12, "host": "ostack2", "ports": []},
        )
        self.assertEqual([], FakeConnection.requests)

    def test_put_snapshot_maps_plain_text_413_to_body_too_large_error(self):
        FakeConnection.responses.append(
            FakeResponse(200, "OK", self._capabilities())
        )
        self.client.capabilities(required_domains=["acl"])
        FakeConnection.requests = []
        FakeConnection.responses.append(
            FakeResponse(413, "Payload Too Large", "request entity too large")
        )

        with self.assertRaises(LocalApiResponseError) as ctx:
            self.client.put_snapshot({"generation": 12, "host": "ostack2", "ports": []})

        self.assertEqual(413, ctx.exception.status)
        self.assertEqual("UDS_BODY_TOO_LARGE", ctx.exception.body["error"])
        self.assertEqual("request entity too large", ctx.exception.body["details"])

    def test_put_port_snapshot_requires_scoped_capability_before_put(self):
        FakeConnection.responses.append(FakeResponse(200, "OK", self._capabilities()))

        with self.assertRaises(LocalApiContractError) as ctx:
            self.client.put_port_snapshot(
                "target-port",
                {
                    "generation": 12,
                    "host": "ostack2",
                    "ports": [{"port_id": "target-port", "ifname": "tap1"}],
                },
                required_domains=["acl"],
            )

        self.assertIn("supports_port_scoped_snapshot", str(ctx.exception))
        self.assertEqual(1, len(FakeConnection.requests))
        self.assertEqual("GET", FakeConnection.requests[0]["method"])
        self.assertEqual(
            "/api/v1/neutron/capabilities",
            FakeConnection.requests[0]["path"],
        )

    def test_put_port_snapshot_serializes_when_scoped_capability_is_advertised(self):
        FakeConnection.responses.append(
            FakeResponse(
                200,
                "OK",
                self._capabilities(supports_port_scoped_snapshot=True),
            )
        )
        FakeConnection.responses.append(FakeResponse(200, "OK", {
            "generation": 13,
            "results": [],
            "active_instances": [],
        }))

        response = self.client.put_port_snapshot(
            "port/with/slash",
            {
                "generation": 13,
                "host": "ostack2",
                "ports": [{"port_id": "port/with/slash", "ifname": "tap1"}],
            },
            required_domains=["acl"],
        )

        self.assertEqual(13, response["generation"])
        self.assertEqual(2, len(FakeConnection.requests))
        request = FakeConnection.requests[1]
        self.assertEqual("PUT", request["method"])
        self.assertEqual(
            "/api/v1/neutron/ports/port%2Fwith%2Fslash/snapshot",
            request["path"],
        )
        self.assertEqual("application/json", request["headers"]["Content-Type"])
        self.assertEqual(
            "port/with/slash",
            json.loads(request["body"])["ports"][0]["port_id"],
        )

    def test_put_port_snapshot_rejects_path_body_mismatch_before_send(self):
        with self.assertRaises(LocalApiContractError):
            self.client.put_port_snapshot(
                "target-port",
                {
                    "generation": 14,
                    "host": "ostack2",
                    "ports": [{"port_id": "other-port", "ifname": "tap1"}],
                },
            )

        self.assertEqual([], FakeConnection.requests)

    def test_plain_text_http_error_is_response_error(self):
        FakeConnection.responses.append(
            FakeResponse(500, "Internal Server Error", "internal failure")
        )

        with self.assertRaises(LocalApiResponseError) as ctx:
            self.client.status()

        self.assertEqual(500, ctx.exception.status)
        self.assertEqual("internal failure", ctx.exception.body["error"])

    def test_delete_port_url_quotes_port_id(self):
        FakeConnection.responses.append(
            FakeResponse(200, "OK", self._capabilities())
        )
        self.client.capabilities(required_domains=["acl"])
        FakeConnection.requests = []
        FakeConnection.responses.append(FakeResponse(200, "OK", {
            "port_id": "port/with/slash",
            "ifname": None,
            "detached": False,
            "status": "not_found",
            "error": None,
        }))

        self.client.delete_port("port/with/slash")

        self.assertEqual(
            "/api/v1/neutron/ports/port%2Fwith%2Fslash",
            FakeConnection.requests[0]["path"],
        )

    def test_socket_timeout_is_typed_transport_error(self):
        client = LocalClient(
            "/tmp/aria-agent.sock",
            timeout=1.0,
            connection_factory=TimeoutConnection,
        )
        client.connection_factory = FakeConnection
        FakeConnection.responses.append(
            FakeResponse(200, "OK", self._capabilities())
        )
        client.capabilities(required_domains=["acl"])
        FakeConnection.requests = []
        client.connection_factory = TimeoutConnection

        self.assertRaises(
            LocalApiTimeoutError,
            client.put_snapshot,
            {"generation": 12, "host": "ostack2", "ports": []},
        )


class StatusContractUdsClientRedTestCase(unittest.TestCase):
    def setUp(self):
        FakeConnection.requests = []
        FakeConnection.responses = []

    def _client(self):
        return LocalClient(
            "/tmp/aria-agent.sock",
            timeout=1.0,
            connection_factory=FakeConnection,
        )

    def _response(self, body):
        FakeConnection.responses.append(FakeResponse(200, "OK", body))

    def _capture_contract_error(self, callback):
        try:
            callback()
        except LocalApiContractError as exc:
            return exc
        return None

    def test_shared_fixture_has_stable_complete_minimum_scenario_set(self):
        fixture = load_status_contract_fixture()
        scenarios = fixture["scenarios"]

        self.assertEqual(1, fixture["fixture_schema_version"])
        self.assertEqual(1, fixture["status_contract"]["version"])
        self.assertEqual(
            "v0.9-neutron-status-1",
            fixture["status_contract"]["hash"],
        )
        self.assertEqual(list(range(1, 15)), [
            scenario["minimum_scenario"] for scenario in scenarios
        ])
        self.assertEqual(14, len(set(
            scenario["id"] for scenario in scenarios
        )))
        for scenario in scenarios:
            self.assertIn("capabilities", scenario)
            self.assertIn("status", scenario)
            self.assertIn("expected_projection", scenario)
            self.assertIn("expected_python", scenario)

    def test_every_valid_v1_status_preserves_projection_and_decision_tuple(self):
        scenario_ids = [
            "full-classified-ready",
            "scoped-classified-ready",
            "classified-degraded-terminal",
            "classified-degraded-full-resync",
            "pending-poll",
            "blocked-recoverable-inventory",
            "blocked-operator",
            "recovery-full-resync",
            "generation-zero-inventory-recovery",
            "restart-classified-routing",
        ]
        decision_by_tuple = {
            ("classified", "ready", "none"): "feature_ready",
            ("classified", "degraded", "none"): "classified_degraded",
            ("classified", "degraded", "full_resync"): "full_resync",
            ("pending", "unknown", "poll"): "poll",
            ("blocked", "blocked", "recover_pending"): "recover_pending",
            ("blocked", "blocked", "operator"): "blocked_operator",
            ("recovery", "degraded", "full_resync"): "recovered_full_resync",
        }
        for scenario_id in scenario_ids:
            FakeConnection.requests = []
            FakeConnection.responses = []
            scenario = status_scenario(scenario_id)
            client = self._client()
            self._response(scenario["capabilities"])
            self._response(scenario["status"])

            client.capabilities(required_domains=["acl"])
            status = client.status()

            with self.subTest(scenario=scenario_id):
                for key, value in scenario["expected_projection"].items():
                    self.assertEqual(value, status[key])
                decision = decision_by_tuple[
                    (
                        status["transaction_state"],
                        status["overall_readiness"],
                        status["required_action"],
                    )
                ]
                self.assertEqual(
                    scenario["expected_python"]["decision"],
                    decision,
                )

    def test_capabilities_reject_unknown_status_version_or_hash(self):
        cases = status_scenario_cases("unknown-v1-contract")[:2]
        for case in cases:
            FakeConnection.requests = []
            FakeConnection.responses = []
            client = self._client()
            self._response(case["capabilities"])

            with self.subTest(case=case["id"]):
                self.assertRaises(LocalApiContractError, client.capabilities)
                self.assertEqual(1, len(FakeConnection.requests))

    def test_v1_status_rejects_negotiated_version_or_hash_mismatch(self):
        scenario = status_scenario("unknown-v1-contract")
        cases = status_scenario_cases("unknown-v1-contract")[2:5]
        for case in cases:
            FakeConnection.requests = []
            FakeConnection.responses = []
            client = self._client()
            self._response(scenario["capabilities"])
            self._response(case["status"])
            client.capabilities()

            with self.subTest(case=case["id"]):
                self.assertRaises(LocalApiContractError, client.status)
                self.assertEqual(2, len(FakeConnection.requests))

    def test_v1_status_rejects_unknown_closed_vocabulary(self):
        scenario = status_scenario("unknown-v1-contract")
        cases = status_scenario_cases("unknown-v1-contract")[5:]
        for case in cases:
            FakeConnection.requests = []
            FakeConnection.responses = []
            client = self._client()
            self._response(scenario["capabilities"])
            self._response(case["status"])
            client.capabilities()

            with self.subTest(case=case["id"]):
                self.assertRaises(LocalApiContractError, client.status)
                self.assertEqual(2, len(FakeConnection.requests))

    def test_unknown_v1_token_blocks_snapshot_delete_and_recover_writes(self):
        scenario = status_scenario("unknown-v1-contract")
        unknown = status_scenario_cases("unknown-v1-contract")[5]
        client = self._client()
        self._response(scenario["capabilities"])
        self._response(unknown["status"])
        client.capabilities()

        status_error = self._capture_contract_error(client.status)
        requests_after_status = len(FakeConnection.requests)
        self._response({"generation": 43, "results": []})
        self._response({"port_id": "port-a", "status": "ok"})
        self._response({"status": "recovered"})
        write_errors = [
            self._capture_contract_error(lambda: client.put_snapshot({
                "generation": 43,
                "host": "ostack2",
                "ports": [],
            })),
            self._capture_contract_error(lambda: client.delete_port("port-a")),
            self._capture_contract_error(lambda: client.recover_pending_snapshot(
                43,
                "hash-ready-43",
            )),
        ]

        self.assertIsInstance(status_error, LocalApiContractError)
        self.assertTrue(all(
            isinstance(error, LocalApiContractError) for error in write_errors
        ))
        self.assertEqual(requests_after_status, len(FakeConnection.requests))

    def test_generation_zero_unknown_cause_is_typed_and_latches_every_write(self):
        scenario = status_scenario("generation-zero-inventory-recovery")
        case = status_scenario_contract_error_cases(scenario["id"])[0]
        closed_vocabulary_case = [
            item for item in status_scenario_cases("unknown-v1-contract")
            if item["id"] == "unknown-recovery-cause"
        ][0]
        context = scenario["request_context"]
        client = self._client()
        self._response(scenario["capabilities"])
        self._response(case["status"])
        client.capabilities(required_domains=["acl"])

        status_error = self._capture_contract_error(client.status)
        requests_after_status = len(FakeConnection.requests)
        self._response({"generation": 2, "results": []})
        self._response(scenario["capabilities"])
        self._response({"generation": 2, "results": []})
        self._response({"port_id": "port-a", "status": "ok"})
        self._response({"status": "recovered"})
        snapshot = {
            "generation": 2,
            "host": "ostack2",
            "ports": [{"port_id": "port-a", "ifname": "tap-port-a"}],
        }
        write_errors = [
            self._capture_contract_error(lambda: client.put_snapshot(snapshot)),
            self._capture_contract_error(lambda: client.put_port_snapshot(
                "port-a",
                snapshot,
                required_domains=["acl"],
            )),
            self._capture_contract_error(lambda: client.delete_port("port-a")),
            self._capture_contract_error(lambda: client.recover_pending_snapshot(
                context["expected_pending_generation"],
                context["expected_desired_hash"],
            )),
        ]

        self.assertEqual("contract_error", case["expected_python"]["decision"])
        self.assertEqual(
            closed_vocabulary_case["status"]["recovery_cause"],
            case["status"]["recovery_cause"],
        )
        self.assertEqual(
            closed_vocabulary_case["expected_python"]["error_type"],
            case["expected_python"]["error_type"],
        )
        self.assertIsInstance(status_error, LocalApiContractError)
        self.assertTrue(all(
            isinstance(error, LocalApiContractError) for error in write_errors
        ))
        self.assertEqual(requests_after_status, len(FakeConnection.requests))

    def test_capability_contract_error_closes_snapshot_delete_and_recover_writes(self):
        for case in status_scenario_cases("unknown-v1-contract")[:2]:
            FakeConnection.requests = []
            FakeConnection.responses = []
            client = self._client()
            self._response(case["capabilities"])
            self._response({"generation": 43, "results": []})
            self._response({"port_id": "port-a", "status": "ok"})
            self._response({"status": "recovered"})

            capability_error = self._capture_contract_error(
                lambda: client.capabilities(required_domains=["acl"])
            )
            requests_after_capabilities = len(FakeConnection.requests)
            write_errors = [
                self._capture_contract_error(lambda: client.put_snapshot({
                    "generation": 43,
                    "host": "ostack2",
                    "ports": [],
                })),
                self._capture_contract_error(lambda: client.delete_port("port-a")),
                self._capture_contract_error(lambda: client.recover_pending_snapshot(
                    43,
                    "hash-ready-43",
                )),
            ]

            with self.subTest(case=case["id"]):
                self.assertIsInstance(
                    capability_error,
                    LocalApiContractError,
                )
                self.assertTrue(all(
                    isinstance(error, LocalApiContractError)
                    for error in write_errors
                ))
                self.assertEqual(
                    requests_after_capabilities,
                    len(FakeConnection.requests),
                )

    def test_v1_ready_rejects_invalid_identity_domain_support_or_duplicates(self):
        scenario = status_scenario("ready-invalid-evidence")
        baseline_client = self._client()
        self._response(scenario["capabilities"])
        self._response(scenario["base_status"])
        baseline_client.capabilities()
        baseline = baseline_client.status()

        self.assertEqual("classified", baseline.get("transaction_state"))
        self.assertEqual("ready", baseline.get("overall_readiness"))
        self.assertEqual("none", baseline.get("required_action"))
        for case in status_scenario_cases("ready-invalid-evidence"):
            FakeConnection.requests = []
            FakeConnection.responses = []
            client = self._client()
            self._response(scenario["capabilities"])
            self._response(case["status"])
            client.capabilities()

            with self.subTest(case=case["id"]):
                self.assertIn("mutation", case)
                self.assertNotIn("status_overrides", case)
                self.assertRaises(LocalApiContractError, client.status)
                self.assertEqual(2, len(FakeConnection.requests))

    def test_legacy_v0_adapter_normalizes_only_bounded_ready_authority(self):
        scenario = status_scenario("legacy-v0-ready")
        client = self._client()
        self._response(scenario["capabilities"])
        self._response(scenario["status"])

        client.capabilities(required_domains=["acl"])
        status = client.status()

        for key, value in scenario["expected_projection"].items():
            self.assertEqual(value, status.get(key))

    def test_legacy_v0_adapter_maps_every_recognized_authority_case(self):
        scenario = status_scenario("legacy-v0-ready")
        for case in scenario["legacy_decoding_cases"]:
            FakeConnection.requests = []
            FakeConnection.responses = []
            client = self._client()
            status_payload = dict(scenario["status"])
            status_payload.update(case["status_overrides"])
            self._response(scenario["capabilities"])
            self._response(status_payload)
            client.capabilities(required_domains=["acl"])

            status = client.status()

            with self.subTest(case=case["id"]):
                for key, value in case["expected_projection"].items():
                    self.assertEqual(value, status.get(key))

    def test_legacy_unknown_authority_is_typed_error_and_blocks_all_writes(self):
        scenario = status_scenario("legacy-v0-unknown-authority")
        client = self._client()
        self._response(scenario["capabilities"])
        self._response(scenario["status"])
        client.capabilities(required_domains=["acl"])

        status_error = self._capture_contract_error(client.status)
        requests_after_status = len(FakeConnection.requests)
        self._response({"generation": 41, "results": []})
        self._response({"status": "recovered"})
        self._response({"port_id": "legacy-port", "status": "ok"})
        write_errors = [
            self._capture_contract_error(lambda: client.put_snapshot({
                "generation": 41,
                "host": "ostack2",
                "ports": [],
            })),
            self._capture_contract_error(lambda: client.recover_pending_snapshot(
                41,
                "legacy-hash-41",
            )),
            self._capture_contract_error(lambda: client.delete_port("legacy-port")),
        ]

        self.assertIsInstance(status_error, LocalApiContractError)
        self.assertTrue(all(
            isinstance(error, LocalApiContractError) for error in write_errors
        ))
        self.assertEqual(requests_after_status, len(FakeConnection.requests))
        self.assertEqual(["GET", "GET"], [
            request["method"] for request in FakeConnection.requests
        ])

    def test_contract_latch_reopens_only_after_valid_supported_status(self):
        scenario = status_scenario("unknown-v1-contract")
        mismatch = status_scenario_cases("unknown-v1-contract")[2]
        valid = status_scenario("full-classified-ready")
        client = self._client()
        self._response(scenario["capabilities"])
        self._response(mismatch["status"])
        self._response(scenario["capabilities"])
        self._response(valid["status"])
        self._response({"generation": 43, "results": []})
        self._response({"generation": 999, "results": []})

        client.capabilities()
        mismatch_error = self._capture_contract_error(client.status)
        client.capabilities()
        requests_before_write = len(FakeConnection.requests)
        blocked_write_error = self._capture_contract_error(lambda: client.put_snapshot({
            "generation": 43,
            "host": "ostack2",
            "ports": [],
        }))
        requests_after_blocked_write = len(FakeConnection.requests)
        valid_status = client.status()
        reopened_response = client.put_snapshot({
            "generation": 43,
            "host": "ostack2",
            "ports": [],
        })

        self.assertIsInstance(mismatch_error, LocalApiContractError)
        self.assertIsInstance(blocked_write_error, LocalApiContractError)
        self.assertEqual(requests_before_write, requests_after_blocked_write)
        self.assertEqual(
            valid["expected_projection"]["transaction_state"],
            valid_status.get("transaction_state"),
        )
        self.assertEqual(43, reopened_response.get("generation"))
        self.assertEqual(
            requests_after_blocked_write + 2,
            len(FakeConnection.requests),
        )

    def test_self_declared_valid_v1_still_requires_handshake_before_write(self):
        scenario = status_scenario("full-classified-ready")
        client = self._client()
        self._response(scenario["status"])
        self._response({"generation": 43, "results": []})

        status = client.status()
        requests_before_write = len(FakeConnection.requests)
        write_error = self._capture_contract_error(lambda: client.put_snapshot({
            "generation": 43,
            "host": "ostack2",
            "ports": [],
        }))

        self.assertEqual(
            scenario["expected_projection"]["transaction_state"],
            status["transaction_state"],
        )
        self.assertIsInstance(write_error, LocalApiContractError)
        self.assertEqual(requests_before_write, len(FakeConnection.requests))


class StatusContractPythonGreenFocusedUdsTestCase(unittest.TestCase):
    def setUp(self):
        FakeConnection.requests = []
        FakeConnection.responses = []

    def _client(self):
        return LocalClient(
            "/tmp/aria-agent.sock",
            timeout=1.0,
            connection_factory=FakeConnection,
        )

    def _response(self, body):
        FakeConnection.responses.append(FakeResponse(200, "OK", body))

    def _capture(self, callback):
        try:
            return callback(), None
        except LocalApiContractError as exc:
            return None, exc

    def _capture_exception(self, callback):
        try:
            callback()
        except Exception as exc:
            return exc
        return None

    def _snapshot(self, generation=43):
        return {
            "generation": generation,
            "host": "ostack2",
            "ports": [],
        }

    def _decode(self, capabilities, status):
        FakeConnection.requests = []
        FakeConnection.responses = []
        client = self._client()
        self._response(copy.deepcopy(capabilities))
        self._response(copy.deepcopy(status))
        client.capabilities(required_domains=["acl"])
        decoded, error = self._capture(client.status)
        return client, decoded, error

    def _normalized_tombstone(self, status, current_generation=False):
        tombstone = copy.deepcopy(status["port_statuses"][0])
        tombstone["port_id"] = "port-detached"
        tombstone["ifname"] = "tap-port-detached"
        if current_generation:
            tombstone["generation"] = status["applied_generation"]
            tombstone["desired_hash"] = status["applied_desired_hash"]
        else:
            tombstone["generation"] = status["applied_generation"] - 1
            tombstone["desired_hash"] = "hash-detached-history"
        tombstone["status"] = "detached"
        tombstone["reason"] = "port_removed"
        for domain in tombstone["domains"]:
            domain["status"] = "not_requested"
            domain["reason"] = "port_removed"
            domain["effective_action"] = "cleanup"
            domain["support_disposition"] = "not_applicable"
        return tombstone

    def _raw_legacy_tombstone(self, status):
        tombstone = copy.deepcopy(status["port_statuses"][0])
        tombstone["port_id"] = "legacy-detached"
        tombstone["ifname"] = "tap-legacy-detached"
        tombstone["generation"] = status["applied_generation"] - 1
        tombstone["desired_hash"] = "legacy-hash-detached"
        tombstone["status"] = "detached"
        tombstone["reason"] = "port_removed"
        for domain in tombstone["domains"]:
            domain["status"] = "detached"
            domain["reason"] = "port_removed"
            domain["effective_action"] = None
            domain.pop("support_disposition", None)
        return tombstone

    def _assert_latched_write(self, client):
        requests_before = len(FakeConnection.requests)
        self._response({"generation": 999, "results": []})
        _response, error = self._capture(
            lambda: client.put_snapshot(self._snapshot())
        )
        requests_after = len(FakeConnection.requests)
        FakeConnection.responses = []
        return error, requests_before, requests_after

    def test_initial_v1_and_legacy_handshakes_authorize_normal_writes(self):
        scenarios = [
            status_scenario("full-classified-ready"),
            status_scenario("legacy-v0-ready"),
        ]
        for scenario in scenarios:
            FakeConnection.requests = []
            FakeConnection.responses = []
            client = self._client()
            self._response(copy.deepcopy(scenario["capabilities"]))
            self._response({"generation": 43, "results": []})

            client.capabilities(required_domains=["acl"])
            response = client.put_snapshot(self._snapshot())

            with self.subTest(scenario=scenario["id"]):
                self.assertEqual(43, response["generation"])
                self.assertEqual(["GET", "PUT"], [
                    request["method"] for request in FakeConnection.requests
                ])

    def test_latch_reopens_only_after_fresh_handshake_then_valid_status(self):
        valid = status_scenario("full-classified-ready")
        mismatch = status_scenario_cases("unknown-v1-contract")[2]
        client = self._client()
        issues = []

        self._response(copy.deepcopy(valid["capabilities"]))
        client.capabilities(required_domains=["acl"])
        self._response(copy.deepcopy(mismatch["status"]))
        _value, mismatch_error = self._capture(client.status)

        self._response(copy.deepcopy(valid["status"]))
        _status_before_handshake, status_before_handshake_error = self._capture(
            client.status
        )
        pre_error, pre_before, pre_after = self._assert_latched_write(client)

        self._response(copy.deepcopy(valid["capabilities"]))
        _capabilities, handshake_error = self._capture(
            lambda: client.capabilities(required_domains=["acl"])
        )
        handshake_only_error, handshake_before, handshake_after = (
            self._assert_latched_write(client)
        )

        self._response(copy.deepcopy(valid["status"]))
        decoded, valid_status_error = self._capture(client.status)
        reopened_before = len(FakeConnection.requests)
        self._response({"generation": 43, "results": []})
        reopened, reopened_error = self._capture(
            lambda: client.put_snapshot(self._snapshot())
        )

        if not isinstance(mismatch_error, LocalApiContractError):
            issues.append("mismatched status did not latch")
        if status_before_handshake_error is not None:
            issues.append("valid status before handshake was not readable")
        if not isinstance(pre_error, LocalApiContractError):
            issues.append("valid status before handshake reopened writes")
        if pre_before != pre_after:
            issues.append("pre-handshake blocked write reached transport")
        if handshake_error is not None:
            issues.append("fresh exact handshake failed")
        if not isinstance(handshake_only_error, LocalApiContractError):
            issues.append("fresh handshake alone reopened writes")
        if handshake_before != handshake_after:
            issues.append("handshake-only blocked write reached transport")
        if valid_status_error is not None:
            issues.append("post-handshake valid status failed")
        if decoded is None or decoded.get("transaction_state") != "classified":
            issues.append("post-handshake status was not decoded")
        if reopened_error is not None or reopened is None:
            issues.append("valid handshake/status sequence did not reopen")
        if len(FakeConnection.requests) != reopened_before + 1:
            issues.append("reopened write did not issue exactly one request")

        self.assertEqual([], issues)

    def test_self_declared_v1_without_handshake_remains_read_only(self):
        scenario = status_scenario("full-classified-ready")
        client = self._client()
        self._response(copy.deepcopy(scenario["status"]))

        decoded, status_error = self._capture(client.status)
        write_error, requests_before, requests_after = self._assert_latched_write(
            client
        )

        self.assertEqual("classified", decoded.get("transaction_state"))
        self.assertEqual(None, status_error)
        self.assertIsInstance(write_error, LocalApiContractError)
        self.assertEqual(requests_before, requests_after)

    def test_v1_tombstone_is_narrow_and_invalid_orphans_latch_writes(self):
        scenario = status_scenario("full-classified-ready")
        valid_statuses = []
        for current_generation in (False, True):
            payload = copy.deepcopy(scenario["status"])
            payload["port_statuses"].append(self._normalized_tombstone(
                payload,
                current_generation=current_generation,
            ))
            valid_statuses.append((
                "current" if current_generation else "historical",
                payload,
            ))

        for label, payload in valid_statuses:
            _client, decoded, error = self._decode(
                scenario["capabilities"],
                payload,
            )
            with self.subTest(valid_tombstone=label):
                self.assertEqual(None, error)
                self.assertEqual("ready", decoded["overall_readiness"])
                self.assertEqual(1, len(decoded["managed_ports"]))
                self.assertTrue(any(
                    row.get("port_id") == "port-a" and
                    row.get("status") == "ready"
                    for row in decoded["port_statuses"]
                ))
                self.assertTrue(any(
                    row.get("port_id") == "port-detached" and
                    row.get("status") == "detached"
                    for row in decoded["port_statuses"]
                ))

        invalid_statuses = []

        cleanup_projected = copy.deepcopy(scenario["status"])
        cleanup_projected["port_statuses"][0]["domains"][0].update({
            "status": "not_requested",
            "effective_action": "cleanup",
            "support_disposition": "not_applicable",
        })
        invalid_statuses.append(("cleanup-projected", cleanup_projected))

        missing_projected = copy.deepcopy(scenario["status"])
        tombstone = self._normalized_tombstone(missing_projected)
        missing_projected["port_statuses"] = [tombstone]
        invalid_statuses.append(("missing-projected", missing_projected))

        empty_ifname = copy.deepcopy(scenario["status"])
        tombstone = self._normalized_tombstone(empty_ifname)
        tombstone["ifname"] = ""
        empty_ifname["port_statuses"].append(tombstone)
        invalid_statuses.append(("empty-tombstone-ifname", empty_ifname))

        whitespace_ifname = copy.deepcopy(scenario["status"])
        tombstone = self._normalized_tombstone(whitespace_ifname)
        tombstone["ifname"] = "   "
        whitespace_ifname["port_statuses"].append(tombstone)
        invalid_statuses.append((
            "whitespace-tombstone-ifname",
            whitespace_ifname,
        ))

        current_hash_mismatch = copy.deepcopy(scenario["status"])
        tombstone = self._normalized_tombstone(
            current_hash_mismatch,
            current_generation=True,
        )
        tombstone["desired_hash"] = "hash-current-mismatch"
        current_hash_mismatch["port_statuses"].append(tombstone)
        invalid_statuses.append((
            "current-tombstone-hash-mismatch",
            current_hash_mismatch,
        ))

        duplicate_managed_domain = copy.deepcopy(scenario["status"])
        tombstone = self._normalized_tombstone(duplicate_managed_domain)
        tombstone["managed_domains"] = ["acl", "acl"]
        duplicate_managed_domain["port_statuses"].append(tombstone)
        invalid_statuses.append((
            "duplicate-tombstone-managed-domain",
            duplicate_managed_domain,
        ))

        duplicate_status_domain = copy.deepcopy(scenario["status"])
        tombstone = self._normalized_tombstone(duplicate_status_domain)
        tombstone["domains"].append(copy.deepcopy(tombstone["domains"][0]))
        duplicate_status_domain["port_statuses"].append(tombstone)
        invalid_statuses.append((
            "duplicate-tombstone-status-domain",
            duplicate_status_domain,
        ))

        tombstone_domain_set_mismatch = copy.deepcopy(scenario["status"])
        tombstone = self._normalized_tombstone(tombstone_domain_set_mismatch)
        tombstone["domains"][0]["domain"] = "attach"
        tombstone_domain_set_mismatch["port_statuses"].append(tombstone)
        invalid_statuses.append((
            "tombstone-domain-set-mismatch",
            tombstone_domain_set_mismatch,
        ))

        non_detached_orphan = copy.deepcopy(scenario["status"])
        orphan = copy.deepcopy(non_detached_orphan["port_statuses"][0])
        orphan["port_id"] = "port-orphan-degraded"
        orphan["ifname"] = "tap-port-orphan-degraded"
        orphan["status"] = "degraded"
        orphan["domains"][0].update({
            "status": "degraded",
            "effective_action": "bypass",
            "support_disposition": "unsupported",
        })
        non_detached_orphan["port_statuses"].append(orphan)
        invalid_statuses.append(("non-detached-orphan", non_detached_orphan))

        extra_ready = copy.deepcopy(scenario["status"])
        orphan = copy.deepcopy(extra_ready["port_statuses"][0])
        orphan["port_id"] = "port-orphan-ready"
        orphan["ifname"] = "tap-port-orphan-ready"
        extra_ready["port_statuses"].append(orphan)
        invalid_statuses.append(("extra-ready-orphan", extra_ready))

        managed_detached = copy.deepcopy(scenario["status"])
        managed_detached["port_statuses"][0].update({
            "status": "detached",
            "reason": "port_removed",
        })
        managed_detached["port_statuses"][0]["domains"][0].update({
            "status": "not_requested",
            "reason": "port_removed",
            "effective_action": "cleanup",
            "support_disposition": "not_applicable",
        })
        invalid_statuses.append(("managed-raw-detached", managed_detached))

        for label, payload in invalid_statuses:
            client, _decoded, status_error = self._decode(
                scenario["capabilities"],
                payload,
            )
            write_error, requests_before, requests_after = (
                self._assert_latched_write(client)
            )
            with self.subTest(invalid_tombstone=label):
                self.assertIsInstance(status_error, LocalApiContractError)
                self.assertIsInstance(write_error, LocalApiContractError)
                self.assertEqual(requests_before, requests_after)

    def test_legacy_raw_detached_extra_row_preserves_ready_subset(self):
        scenario = status_scenario("legacy-v0-ready")
        payload = copy.deepcopy(scenario["status"])
        payload["port_statuses"].append(self._raw_legacy_tombstone(payload))

        _client, decoded, error = self._decode(
            scenario["capabilities"],
            payload,
        )

        self.assertEqual(None, error)
        for key, value in scenario["expected_projection"].items():
            self.assertEqual(value, decoded.get(key))
        self.assertTrue(any(
            row.get("port_id") == "legacy-detached" and
            row.get("status") == "detached"
            for row in decoded["port_statuses"]
        ))

    def test_classified_row_hash_and_top_level_matrix(self):
        scenario = status_scenario("full-classified-ready")
        positive_cases = [
            ("current-row", copy.deepcopy(scenario["status"])),
            (
                "older-scoped-row",
                copy.deepcopy(status_scenario("scoped-classified-ready")["status"]),
            ),
        ]
        valid_tombstone = copy.deepcopy(scenario["status"])
        valid_tombstone["port_statuses"].append(
            self._normalized_tombstone(valid_tombstone)
        )
        positive_cases.append(("valid-tombstone", valid_tombstone))

        for label, payload in positive_cases:
            _client, decoded, error = self._decode(
                scenario["capabilities"],
                payload,
            )
            with self.subTest(positive=label):
                self.assertEqual(None, error)
                self.assertEqual("classified", decoded["transaction_state"])

        negative_cases = []

        zero_generation = copy.deepcopy(scenario["status"])
        zero_generation["port_statuses"][0]["generation"] = 0
        negative_cases.append(("zero-generation", zero_generation))

        empty_port_id = copy.deepcopy(scenario["status"])
        empty_port_id["managed_ports"][0]["port_id"] = ""
        empty_port_id["port_statuses"][0]["port_id"] = ""
        negative_cases.append(("empty-port-id", empty_port_id))

        future_generation = copy.deepcopy(scenario["status"])
        future_generation["port_statuses"][0]["generation"] = 43
        negative_cases.append(("future-generation", future_generation))

        empty_hash = copy.deepcopy(scenario["status"])
        empty_hash["port_statuses"][0]["desired_hash"] = " "
        negative_cases.append(("empty-row-hash", empty_hash))

        current_hash_mismatch = copy.deepcopy(scenario["status"])
        current_hash_mismatch["port_statuses"][0]["desired_hash"] = (
            "hash-current-mismatch"
        )
        negative_cases.append(("current-row-hash-mismatch", current_hash_mismatch))

        ifname_mismatch = copy.deepcopy(scenario["status"])
        ifname_mismatch["port_statuses"][0]["ifname"] = "tap-other"
        negative_cases.append(("ifname-mismatch", ifname_mismatch))

        managed_domain_mismatch = copy.deepcopy(scenario["status"])
        managed_domain_mismatch["port_statuses"][0]["managed_domains"] = [
            "attach"
        ]
        negative_cases.append(("managed-domain-mismatch", managed_domain_mismatch))

        missing_domain = copy.deepcopy(scenario["status"])
        missing_domain["port_statuses"][0]["domains"] = []
        negative_cases.append(("missing-domain", missing_domain))

        extra_domain = copy.deepcopy(scenario["status"])
        domain = copy.deepcopy(extra_domain["port_statuses"][0]["domains"][0])
        domain.update({
            "domain": "attach",
            "effective_action": "no_op",
            "support_disposition": "supported",
        })
        extra_domain["port_statuses"][0]["domains"].append(domain)
        negative_cases.append(("extra-domain", extra_domain))

        duplicate_domain = copy.deepcopy(scenario["status"])
        duplicate_domain["port_statuses"][0]["domains"].append(copy.deepcopy(
            duplicate_domain["port_statuses"][0]["domains"][0]
        ))
        negative_cases.append(("duplicate-domain", duplicate_domain))

        severity_mismatch = copy.deepcopy(scenario["status"])
        severity_mismatch["port_statuses"][0]["domains"][0].update({
            "status": "degraded",
            "effective_action": "bypass",
            "support_disposition": "unsupported",
        })
        negative_cases.append(("top-level-domain-severity", severity_mismatch))

        managed_detached = copy.deepcopy(scenario["status"])
        managed_detached["port_statuses"][0]["status"] = "detached"
        negative_cases.append(("managed-detached", managed_detached))

        invalid_orphan = copy.deepcopy(scenario["status"])
        orphan = copy.deepcopy(invalid_orphan["port_statuses"][0])
        orphan["port_id"] = "port-orphan"
        orphan["ifname"] = "tap-port-orphan"
        invalid_orphan["port_statuses"].append(orphan)
        negative_cases.append(("invalid-orphan", invalid_orphan))

        for port_state in ("blocked", "error", "recovered"):
            unsafe = copy.deepcopy(scenario["status"])
            unsafe["port_statuses"][0].update({
                "status": port_state,
                "reason": "runtime_rebuild_required",
            })
            unsafe["port_statuses"][0]["domains"][0].update({
                "status": "blocked",
                "reason": "runtime_rebuild_required",
                "effective_action": "unchanged",
                "support_disposition": "supported",
            })
            negative_cases.append((port_state + "-rebuild-reason", unsafe))

        for label, payload in negative_cases:
            _client, _decoded, error = self._decode(
                scenario["capabilities"],
                payload,
            )
            with self.subTest(negative=label):
                self.assertIsInstance(error, LocalApiContractError)

    def test_pending_identity_accepts_two_lineages_and_rejects_ambiguity(self):
        pending = status_scenario("pending-poll")
        inventory = status_scenario("blocked-recoverable-inventory")

        same_generation = copy.deepcopy(pending["status"])
        same_generation["pending_generation"] = same_generation[
            "applied_generation"
        ]
        same_generation["desired_hash"] = same_generation[
            "applied_desired_hash"
        ]

        valid_cases = [
            ("intent-lineage", copy.deepcopy(pending["status"])),
            ("committed-lineage", copy.deepcopy(inventory["status"])),
            ("same-generation-matching-hash", same_generation),
        ]
        for label, payload in valid_cases:
            _client, decoded, error = self._decode(
                pending["capabilities"],
                payload,
            )
            with self.subTest(valid=label):
                self.assertEqual(None, error)
                self.assertIsNotNone(decoded.get("pending_generation"))

        middle_generation = copy.deepcopy(pending["status"])
        middle_generation["accepted_generation"] = 43

        same_generation_mismatch = copy.deepcopy(same_generation)
        same_generation_mismatch["desired_hash"] = "hash-same-generation-drift"

        inventory_intent_lineage = copy.deepcopy(inventory["status"])
        inventory_intent_lineage["accepted_generation"] = (
            inventory_intent_lineage["applied_generation"]
        )

        invalid_cases = [
            ("middle-generation", middle_generation),
            ("same-generation-hash-mismatch", same_generation_mismatch),
            ("inventory-requires-accepted-pending", inventory_intent_lineage),
        ]
        for label, payload in invalid_cases:
            client, _decoded, status_error = self._decode(
                pending["capabilities"],
                payload,
            )
            write_error, requests_before, requests_after = (
                self._assert_latched_write(client)
            )
            with self.subTest(invalid=label):
                self.assertIsInstance(status_error, LocalApiContractError)
                self.assertIsInstance(write_error, LocalApiContractError)
                self.assertEqual(requests_before, requests_after)

    def test_classified_generation_zero_and_broad_empty_ifname_are_rejected(self):
        ready = status_scenario("full-classified-ready")
        generation_zero = copy.deepcopy(ready["status"])
        generation_zero.update({
            "last_classified_generation": 0,
            "generation": 0,
            "accepted_generation": 0,
            "applied_generation": 0,
            "pending_generation": None,
            "desired_hash": None,
            "applied_desired_hash": None,
            "managed_ports": [],
            "port_statuses": [],
            "active_instances": [],
        })

        rebuild = status_scenario("classified-degraded-full-resync")
        broad_empty_ifname = copy.deepcopy(rebuild["status"])
        broad_empty_ifname["managed_ports"][0]["ifname"] = ""
        broad_empty_ifname["port_statuses"][0]["ifname"] = ""

        for label, capabilities, payload in (
            (
                "classified-generation-zero",
                ready["capabilities"],
                generation_zero,
            ),
            (
                "full-resync-supported-empty-ifname",
                rebuild["capabilities"],
                broad_empty_ifname,
            ),
        ):
            client, _decoded, status_error = self._decode(
                capabilities,
                payload,
            )
            write_error, requests_before, requests_after = (
                self._assert_latched_write(client)
            )
            with self.subTest(invalid=label):
                self.assertIsInstance(status_error, LocalApiContractError)
                self.assertIsInstance(write_error, LocalApiContractError)
                self.assertEqual(requests_before, requests_after)

    def test_unreadable_contract_responses_and_validator_errors_latch_writes(self):
        scenario = status_scenario("full-classified-ready")

        class RawResponse(object):
            def __init__(self, payload):
                self.status = 200
                self.reason = "OK"
                self.payload = payload

            def read(self, _size):
                return self.payload

        def assert_contract_failure(label, endpoint, response, max_bytes=None):
            FakeConnection.requests = []
            FakeConnection.responses = []
            client = self._client()
            if endpoint == "status":
                self._response(copy.deepcopy(scenario["capabilities"]))
                client.capabilities(required_domains=["acl"])
            if max_bytes is not None:
                client.max_response_bytes = max_bytes
            FakeConnection.responses.append(response)
            if endpoint == "status":
                callback = client.status
            else:
                callback = lambda: client.capabilities(
                    required_domains=["acl"]
                )
            error = self._capture_exception(callback)
            client.max_response_bytes = 1048576
            write_error, requests_before, requests_after = (
                self._assert_latched_write(client)
            )
            with self.subTest(case=label):
                self.assertIsInstance(error, LocalApiContractError)
                self.assertIsInstance(write_error, LocalApiContractError)
                self.assertEqual(requests_before, requests_after)

        for endpoint in ("capabilities", "status"):
            assert_contract_failure(
                "malformed-%s-json" % endpoint,
                endpoint,
                FakeResponse(200, "OK", "{bad-json"),
            )
            assert_contract_failure(
                "oversized-%s" % endpoint,
                endpoint,
                FakeResponse(
                    200,
                    "OK",
                    copy.deepcopy(
                        scenario[
                            "status" if endpoint == "status" else "capabilities"
                        ]
                    ),
                ),
                max_bytes=8,
            )
            assert_contract_failure(
                "invalid-utf8-%s" % endpoint,
                endpoint,
                RawResponse(b"\xff"),
            )

        nested_payload = copy.deepcopy(scenario["capabilities"])
        nested_payload["supported_domains"] = [{}]
        assert_contract_failure(
            "nested-capabilities-type",
            "capabilities",
            FakeResponse(200, "OK", nested_payload),
        )

        timeout_client = LocalClient(
            "/tmp/aria-agent.sock",
            timeout=1.0,
            connection_factory=TimeoutConnection,
        )
        timeout_error = self._capture_exception(
            lambda: timeout_client.capabilities(required_domains=["acl"])
        )
        self.assertIsInstance(timeout_error, LocalApiTimeoutError)
        self.assertNotIsInstance(timeout_error, LocalApiContractError)

        FakeConnection.requests = []
        FakeConnection.responses = [FakeResponse(503, "Unavailable", "not-json")]
        response_client = self._client()
        response_error = self._capture_exception(
            lambda: response_client.capabilities(required_domains=["acl"])
        )
        self.assertIsInstance(response_error, LocalApiResponseError)
        self.assertNotIsInstance(response_error, LocalApiContractError)

    def test_fresh_client_requires_handshake_before_every_mutation(self):
        direct_mutations = [
            (
                "full-snapshot",
                lambda client: client.put_snapshot(self._snapshot()),
                {"generation": 43, "results": []},
                "PUT",
            ),
            (
                "delete-port",
                lambda client: client.delete_port("port-a"),
                {"port_id": "port-a", "status": "not_found"},
                "DELETE",
            ),
            (
                "recover-pending",
                lambda client: client.recover_pending_snapshot(
                    43,
                    "hash-pending-43",
                ),
                {"status": "recovered", "recovered_generation": 43},
                "POST",
            ),
        ]

        for label, mutate, response, _method in direct_mutations:
            FakeConnection.requests = []
            FakeConnection.responses = []
            client = self._client()
            self._response(response)

            _value, error = self._capture(lambda: mutate(client))

            with self.subTest(fresh=label):
                self.assertIsInstance(error, LocalApiContractError)
                self.assertEqual([], FakeConnection.requests)

        for scenario_id in ("full-classified-ready", "legacy-v0-ready"):
            scenario = status_scenario(scenario_id)
            for label, mutate, response, method in direct_mutations:
                FakeConnection.requests = []
                FakeConnection.responses = []
                client = self._client()
                self._response(copy.deepcopy(scenario["capabilities"]))
                self._response(response)

                client.capabilities(required_domains=["acl"])
                value, error = self._capture(lambda: mutate(client))

                with self.subTest(handshake=scenario_id, mutation=label):
                    self.assertEqual(None, error)
                    self.assertIsNotNone(value)
                    self.assertEqual(
                        ["GET", method],
                        [request["method"] for request in FakeConnection.requests],
                    )

        scoped = status_scenario("full-classified-ready")
        FakeConnection.requests = []
        FakeConnection.responses = []
        client = self._client()
        self._response(copy.deepcopy(scoped["capabilities"]))
        self._response({"generation": 43, "results": []})

        response, error = self._capture(lambda: client.put_port_snapshot(
            "port-a",
            {
                "generation": 43,
                "host": "ostack2",
                "ports": [{"port_id": "port-a", "ifname": "tap-port-a"}],
            },
            required_domains=["acl"],
        ))

        self.assertEqual(None, error)
        self.assertEqual(43, response["generation"])
        self.assertEqual(
            ["GET", "PUT"],
            [request["method"] for request in FakeConnection.requests],
        )

    def test_recover_pending_validates_present_v1_diagnostics_before_post(self):
        scenario = status_scenario("blocked-recoverable-inventory")
        generation_zero = copy.deepcopy(scenario["status"])
        generation_zero.update({
            "last_classified_generation": 0,
            "generation": 0,
            "applied_generation": 0,
            "applied_desired_hash": None,
            "managed_ports": [],
            "port_statuses": [],
            "active_instances": [],
        })
        managed_only = copy.deepcopy(scenario["status"])
        managed_only["port_statuses"] = []
        status_only = copy.deepcopy(scenario["status"])
        status_only["managed_ports"] = []

        for label, payload in (
            ("generation-zero-empty", generation_zero),
            ("managed-only", managed_only),
            ("status-only", status_only),
        ):
            _client, decoded, error = self._decode(
                scenario["capabilities"],
                payload,
            )
            with self.subTest(valid=label):
                self.assertEqual(None, error)
                self.assertEqual("recover_pending", decoded["required_action"])

        invalid_cases = []
        unknown_port_status = copy.deepcopy(scenario["status"])
        unknown_port_status["port_statuses"][0]["status"] = "mystery"
        invalid_cases.append(("port-status", unknown_port_status))

        unknown_domain_status = copy.deepcopy(scenario["status"])
        unknown_domain_status["port_statuses"][0]["domains"][0][
            "status"
        ] = "mystery"
        invalid_cases.append(("domain-status", unknown_domain_status))

        unknown_action = copy.deepcopy(scenario["status"])
        unknown_action["port_statuses"][0]["domains"][0][
            "effective_action"
        ] = "mystery"
        invalid_cases.append(("effective-action", unknown_action))

        unknown_support = copy.deepcopy(scenario["status"])
        unknown_support["port_statuses"][0]["domains"][0][
            "support_disposition"
        ] = "mystery"
        invalid_cases.append(("support-disposition", unknown_support))

        malformed_managed = copy.deepcopy(scenario["status"])
        malformed_managed["managed_ports"] = [{}]
        invalid_cases.append(("managed-row", malformed_managed))

        for label, payload in invalid_cases:
            client, _decoded, status_error = self._decode(
                scenario["capabilities"],
                payload,
            )
            requests_before = len(FakeConnection.requests)
            self._response({"status": "recovered"})
            _value, recovery_error = self._capture(
                lambda: client.recover_pending_snapshot(
                    payload["pending_generation"],
                    payload["desired_hash"],
                )
            )
            requests_after = len(FakeConnection.requests)
            FakeConnection.responses = []

            with self.subTest(invalid=label):
                self.assertIsInstance(status_error, LocalApiContractError)
                self.assertIsInstance(recovery_error, LocalApiContractError)
                self.assertEqual(requests_before, requests_after)

    def test_historical_row_hash_must_be_trimmed_and_latches_writes(self):
        scenario = status_scenario("scoped-classified-ready")

        _client, decoded, positive_error = self._decode(
            scenario["capabilities"],
            copy.deepcopy(scenario["status"]),
        )
        self.assertEqual(None, positive_error)
        self.assertEqual("classified", decoded["transaction_state"])

        padded = copy.deepcopy(scenario["status"])
        older_row = next(
            row for row in padded["port_statuses"]
            if row["generation"] < padded["applied_generation"]
        )
        older_row["desired_hash"] = " %s " % older_row["desired_hash"]

        client, _decoded, status_error = self._decode(
            scenario["capabilities"],
            padded,
        )
        write_error, requests_before, requests_after = (
            self._assert_latched_write(client)
        )

        self.assertIsInstance(status_error, LocalApiContractError)
        self.assertIsInstance(write_error, LocalApiContractError)
        self.assertEqual(requests_before, requests_after)


if __name__ == "__main__":
    unittest.main()
