from __future__ import absolute_import

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

    def __init__(self, _socket_path, _timeout):
        self.closed = False

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

    def test_capabilities_tightens_timeout(self):
        client = LocalClient(
            "/tmp/aria-agent.sock",
            timeout=5.0,
            connection_factory=FakeConnection,
        )
        FakeConnection.responses.append(
            FakeResponse(200, "OK", self._capabilities(timeout_ms=2500))
        )

        client.capabilities(required_domains=["acl"])

        self.assertEqual(2.5, client.timeout)

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

        self.assertRaises(
            LocalApiContractError,
            client.put_snapshot,
            {"generation": 12, "host": "ostack2", "ports": []},
        )
        self.assertEqual([], FakeConnection.requests)

    def test_put_snapshot_maps_plain_text_413_to_body_too_large_error(self):
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


if __name__ == "__main__":
    unittest.main()
