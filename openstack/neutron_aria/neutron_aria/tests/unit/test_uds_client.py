from __future__ import absolute_import

import json
import unittest

from neutron_aria.agent.uds_client import LocalApiContractError
from neutron_aria.agent.uds_client import LocalClient


class FakeResponse(object):
    def __init__(self, status, reason, body):
        self.status = status
        self.reason = reason
        self.body = body

    def read(self, _size):
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


class UdsClientTestCase(unittest.TestCase):
    def setUp(self):
        FakeConnection.requests = []
        FakeConnection.responses = []
        self.client = LocalClient(
            "/tmp/aria-agent.sock",
            timeout=1.0,
            connection_factory=FakeConnection,
        )

    def test_capabilities_validates_required_domains(self):
        FakeConnection.responses.append(FakeResponse(200, "OK", {
            "api_version": "v1",
            "attach_authority": "neutron_snapshot",
            "supports_full_snapshot": True,
            "supports_port_delete": True,
            "supported_domains": ["attach", "acl", "qos"],
        }))

        body = self.client.capabilities(required_domains=["acl"])

        self.assertEqual("v1", body["api_version"])
        self.assertEqual("GET", FakeConnection.requests[0]["method"])
        self.assertEqual("/api/v1/neutron/capabilities", FakeConnection.requests[0]["path"])

    def test_capabilities_rejects_missing_domain(self):
        FakeConnection.responses.append(FakeResponse(200, "OK", {
            "api_version": "v1",
            "attach_authority": "neutron_snapshot",
            "supports_full_snapshot": True,
            "supports_port_delete": True,
            "supported_domains": ["attach"],
        }))

        self.assertRaises(
            LocalApiContractError,
            self.client.capabilities,
            required_domains=["acl"],
        )

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


if __name__ == "__main__":
    unittest.main()
