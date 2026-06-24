from __future__ import absolute_import

import json
import socket

try:
    import httplib as http_client
except ImportError:
    import http.client as http_client

try:
    from urllib import quote as urlquote
except ImportError:
    from urllib.parse import quote as urlquote


NEUTRON_API_VERSION = "v1"
NEUTRON_ATTACH_AUTHORITY = "neutron_snapshot"
DEFAULT_SOCKET_PATH = "/run/aria/aria-agent.sock"


class LocalApiError(Exception):
    pass


class LocalApiTransportError(LocalApiError):
    pass


class LocalApiResponseError(LocalApiError):
    def __init__(self, status, reason, body):
        LocalApiError.__init__(self, "local API returned %s %s" % (status, reason))
        self.status = status
        self.reason = reason
        self.body = body


class LocalApiContractError(LocalApiError):
    pass


class UnixHTTPConnection(http_client.HTTPConnection):
    def __init__(self, socket_path, timeout=None):
        http_client.HTTPConnection.__init__(self, "localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if self.timeout is not None:
            sock.settimeout(self.timeout)
        sock.connect(self.socket_path)
        self.sock = sock


class LocalClient(object):
    def __init__(
        self,
        socket_path=DEFAULT_SOCKET_PATH,
        timeout=3.0,
        max_response_bytes=1048576,
        connection_factory=None,
    ):
        self.socket_path = socket_path
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.connection_factory = connection_factory

    def capabilities(self, required_domains=None):
        body = self._request("GET", "/api/v1/neutron/capabilities")
        self._validate_capabilities(body, required_domains or [])
        return body

    def status(self):
        return self._request("GET", "/api/v1/neutron/status")

    def put_snapshot(self, snapshot):
        return self._request("PUT", "/api/v1/neutron/snapshot", snapshot)

    def delete_port(self, port_id):
        encoded = urlquote(port_id, safe="")
        return self._request("DELETE", "/api/v1/neutron/ports/%s" % encoded)

    def _connection(self):
        if self.connection_factory is not None:
            return self.connection_factory(self.socket_path, self.timeout)
        return UnixHTTPConnection(self.socket_path, self.timeout)

    def _request(self, method, path, body=None):
        headers = {"Accept": "application/json"}
        payload = None
        if body is not None:
            payload = json.dumps(body, sort_keys=True)
            headers["Content-Type"] = "application/json"

        conn = self._connection()
        try:
            conn.request(method, path, body=payload, headers=headers)
            response = conn.getresponse()
            raw = response.read(self.max_response_bytes + 1)
            if len(raw) > self.max_response_bytes:
                raise LocalApiResponseError(response.status, response.reason, "response too large")
            if not raw:
                decoded = {}
            else:
                if not isinstance(raw, str):
                    raw = raw.decode("utf-8")
                decoded = json.loads(raw)
            if response.status >= 400:
                raise LocalApiResponseError(response.status, response.reason, decoded)
            return decoded
        except LocalApiError:
            raise
        except Exception as exc:
            raise LocalApiTransportError(str(exc))
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _validate_capabilities(self, body, required_domains):
        if body.get("api_version") != NEUTRON_API_VERSION:
            raise LocalApiContractError("unsupported api_version %r" % body.get("api_version"))
        if body.get("attach_authority") != NEUTRON_ATTACH_AUTHORITY:
            raise LocalApiContractError(
                "unsupported attach_authority %r" % body.get("attach_authority")
            )
        if not body.get("supports_full_snapshot"):
            raise LocalApiContractError("local API does not support full snapshot")
        if not body.get("supports_port_delete"):
            raise LocalApiContractError("local API does not support port delete")

        supported = set(body.get("supported_domains") or [])
        missing = [domain for domain in required_domains if domain not in supported]
        if missing:
            raise LocalApiContractError("unsupported managed domains: %s" % ",".join(missing))
