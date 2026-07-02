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
NEUTRON_CONTRACT_VERSION = "2026-06-v0.9"
NEUTRON_SCHEMA_VERSION = 1
NEUTRON_BODY_MAX_BYTES = 1048576
NEUTRON_TIMEOUT_MS = 3000
NEUTRON_ERROR_CODES_HASH = "v0.9-neutron-errors-2"
NEUTRON_CAPABILITY_HASH = "v0.9-neutron-capabilities-2"
NEUTRON_ATTACH_AUTHORITY = "neutron_snapshot"
DEFAULT_SOCKET_PATH = "/run/aria/aria-agent.sock"


class LocalApiError(Exception):
    pass


class LocalApiTransportError(LocalApiError):
    pass


class LocalApiTimeoutError(LocalApiTransportError):
    pass


class LocalApiResponseError(LocalApiError):
    def __init__(self, status, reason, body):
        LocalApiError.__init__(self, "local API returned %s %s" % (status, reason))
        self.status = status
        self.reason = reason
        self.body = body


class LocalApiContractError(LocalApiError):
    pass


def _optional_int(value, field):
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        raise LocalApiContractError("invalid %s %r" % (field, value))


def _plain_error_body(status, reason, raw):
    if status == 413:
        return {"error": "UDS_BODY_TOO_LARGE", "details": raw}
    return {"error": raw or reason}


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
        timeout=NEUTRON_TIMEOUT_MS / 1000.0,
        max_response_bytes=1048576,
        max_request_bytes=NEUTRON_BODY_MAX_BYTES,
        connection_factory=None,
    ):
        self.socket_path = socket_path
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.max_request_bytes = max_request_bytes
        self.connection_factory = connection_factory

    def capabilities(self, required_domains=None):
        body = self._request("GET", "/api/v1/neutron/capabilities")
        self._validate_capabilities(body, required_domains or [])
        return body

    def status(self):
        return self._request("GET", "/api/v1/neutron/status")

    def put_snapshot(self, snapshot):
        return self._request("PUT", "/api/v1/neutron/snapshot", snapshot)

    def put_port_snapshot(self, port_id, snapshot, required_domains=None):
        self._validate_port_snapshot_request(port_id, snapshot)
        capabilities = self.capabilities(required_domains=required_domains or [])
        if not capabilities.get("supports_port_scoped_snapshot"):
            raise LocalApiContractError(
                "local API does not advertise supports_port_scoped_snapshot"
            )
        encoded = urlquote(port_id, safe="")
        return self._request(
            "PUT",
            "/api/v1/neutron/ports/%s/snapshot" % encoded,
            snapshot,
        )

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
            payload_len = len(payload.encode("utf-8"))
            if payload_len > self.max_request_bytes:
                raise LocalApiContractError(
                    "request body too large: %s > %s"
                    % (payload_len, self.max_request_bytes)
                )
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
                try:
                    decoded = json.loads(raw)
                except ValueError:
                    if response.status < 400:
                        raise
                    decoded = _plain_error_body(response.status, response.reason, raw)
            if response.status >= 400:
                raise LocalApiResponseError(response.status, response.reason, decoded)
            return decoded
        except LocalApiError:
            raise
        except socket.timeout as exc:
            raise LocalApiTimeoutError(str(exc) or "timed out")
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

        contract_version = body.get("contract_version")
        if contract_version is not None and contract_version != NEUTRON_CONTRACT_VERSION:
            raise LocalApiContractError(
                "unsupported contract_version %r" % contract_version
            )

        schema_min = body.get("schema_version_min")
        schema_max = body.get("schema_version_max")
        if schema_min is not None or schema_max is not None:
            schema_min = _optional_int(schema_min, "schema_version_min") or 0
            schema_max = _optional_int(schema_max, "schema_version_max") or 0
            if schema_min > NEUTRON_SCHEMA_VERSION or schema_max < NEUTRON_SCHEMA_VERSION:
                raise LocalApiContractError(
                    "unsupported schema version range %s-%s" % (schema_min, schema_max)
                )

        body_max_bytes = body.get("body_max_bytes")
        body_max_bytes = _optional_int(body_max_bytes, "body_max_bytes")
        if body_max_bytes is not None and body_max_bytes <= 0:
            raise LocalApiContractError("invalid body_max_bytes %r" % body.get("body_max_bytes"))
        if body_max_bytes is not None:
            self.max_request_bytes = min(self.max_request_bytes, body_max_bytes)

        timeout_ms = body.get("timeout_ms")
        timeout_ms = _optional_int(timeout_ms, "timeout_ms")
        if timeout_ms is not None and timeout_ms <= 0:
            raise LocalApiContractError("invalid timeout_ms %r" % body.get("timeout_ms"))
        if timeout_ms is not None:
            timeout = timeout_ms / 1000.0
            self.timeout = min(self.timeout, timeout) if self.timeout is not None else timeout

        error_codes_hash = body.get("error_codes_hash")
        if error_codes_hash is not None and error_codes_hash != NEUTRON_ERROR_CODES_HASH:
            raise LocalApiContractError(
                "unsupported error_codes_hash %r" % error_codes_hash
            )

        peer_auth_policy = body.get("peer_auth_policy")
        if peer_auth_policy is not None and not str(peer_auth_policy).strip():
            raise LocalApiContractError("empty peer_auth_policy")

        capability_hash = body.get("capability_hash")
        if capability_hash is not None and capability_hash != NEUTRON_CAPABILITY_HASH:
            raise LocalApiContractError(
                "unsupported capability_hash %r" % capability_hash
            )

    def _validate_port_snapshot_request(self, port_id, snapshot):
        if not isinstance(snapshot, dict):
            raise LocalApiContractError("port-scoped snapshot body must be an object")
        ports = snapshot.get("ports")
        if not isinstance(ports, list) or len(ports) != 1:
            raise LocalApiContractError(
                "port-scoped snapshot requires exactly one body port"
            )
        actual_port_id = ports[0].get("port_id") if isinstance(ports[0], dict) else None
        if actual_port_id != port_id:
            raise LocalApiContractError(
                "port-scoped snapshot path/body mismatch: expected %s, got %s"
                % (port_id, actual_port_id)
            )
