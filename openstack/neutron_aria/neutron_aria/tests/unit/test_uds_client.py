from __future__ import absolute_import

import json
import socket
import unittest

from neutron_aria.agent.uds_client import LocalApiContractError
from neutron_aria.agent.uds_client import LocalApiResponseError
from neutron_aria.agent.uds_client import LocalApiTimeoutError
from neutron_aria.agent.uds_client import LocalClient


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


if __name__ == "__main__":
    unittest.main()
