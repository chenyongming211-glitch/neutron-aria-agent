from __future__ import absolute_import

import os


class PortSourceUnavailable(Exception):
    pass


class NeutronClientFactoryError(Exception):
    pass


class NeutronPortSource(object):
    """Thin adapter around legacy python-neutronclient.

    The real service will inject an authenticated neutronclient instance from
    the OpenStack runtime. Keeping this wrapper tiny makes unit tests and
    smoke scripts independent from the Neutron libraries.
    """

    def __init__(self, neutron_client, host, page_size=None):
        self.neutron_client = neutron_client
        self.host = host
        self.page_size = page_size

    def list_ports_for_host(self):
        ports = []
        marker = None

        while True:
            kwargs = {"binding:host_id": self.host}
            if self.page_size:
                kwargs["limit"] = self.page_size
            if marker:
                kwargs["marker"] = marker

            result = self.neutron_client.list_ports(**kwargs)
            batch, has_next = self._extract_ports_and_next(result)
            ports.extend(batch)

            if not has_next or not batch:
                break
            marker = batch[-1].get("id")
            if not marker:
                break

        return ports

    def _extract_ports_and_next(self, result):
        if isinstance(result, dict):
            return result.get("ports", []), self._has_next_link(result.get("ports_links", []))
        return result, False

    def _has_next_link(self, links):
        for link in links or []:
            if link.get("rel") == "next":
                return True
        return False


class NeutronFullResyncClient(object):
    def __init__(self, port_source):
        self.port_source = port_source

    def get_ports(self):
        return self.port_source.list_ports_for_host()


class AriaAclRestClient(object):
    """REST adapter for the aria_acl Neutron extension.

    python-neutronclient will not know product-specific aria_acl methods until a
    matching client extension is installed. The agent only needs read access, so
    this adapter uses the client's generic GET path and exposes the list methods
    consumed by NeutronAclSource.
    """

    COLLECTIONS = {
        "aria_acl_policies": "/aria-acl-policies",
        "aria_acl_rules": "/aria-acl-rules",
        "aria_acl_address_sets": "/aria-acl-address-sets",
        "aria_acl_bindings": "/aria-acl-bindings",
        "aria_acl_port_statuses": "/aria-acl-port-statuses",
    }

    def __init__(self, neutron_client, page_size=None):
        self.neutron_client = neutron_client
        self.page_size = page_size

    def list_aria_acl_policies(self):
        return self._list("aria_acl_policies")

    def list_aria_acl_rules(self):
        return self._list("aria_acl_rules")

    def list_aria_acl_address_sets(self):
        return self._list("aria_acl_address_sets")

    def list_aria_acl_bindings(self):
        return self._list("aria_acl_bindings")

    def list_aria_acl_port_statuses(self):
        return self._list("aria_acl_port_statuses")

    def report_aria_acl_port_status(self, port_status):
        post = getattr(self.neutron_client, "post", None)
        if post is None:
            raise NeutronClientFactoryError(
                "neutronclient does not expose generic POST for /aria-acl-port-statuses"
            )
        body = {"aria_acl_port_status": port_status}
        try:
            return post(self.COLLECTIONS["aria_acl_port_statuses"], body=body)
        except TypeError:
            return post(self.COLLECTIONS["aria_acl_port_statuses"], body)

    def _list(self, collection):
        values = []
        marker = None
        seen_markers = set()

        while True:
            payload = self._get_collection(collection, marker=marker)
            if not isinstance(payload, dict):
                return {collection: payload or []}

            if collection not in payload:
                raise NeutronClientFactoryError(
                    "aria_acl response for %s missing collection %s"
                    % (self.COLLECTIONS[collection], collection)
                )
            batch = payload[collection]
            if not isinstance(batch, list):
                raise NeutronClientFactoryError(
                    "aria_acl response for %s collection %s must be a list"
                    % (self.COLLECTIONS[collection], collection)
                )
            values.extend(batch)
            if not self._has_next_link(payload.get("%s_links" % collection, [])):
                break
            if not batch:
                raise NeutronClientFactoryError(
                    "aria_acl response for %s has a next page but no pagination marker"
                    % self.COLLECTIONS[collection]
                )
            next_marker = batch[-1].get("id")
            if not next_marker:
                raise NeutronClientFactoryError(
                    "aria_acl response for %s has a next page but no pagination marker"
                    % self.COLLECTIONS[collection]
                )
            if next_marker in seen_markers:
                raise NeutronClientFactoryError(
                    "aria_acl response for %s repeated pagination marker %s"
                    % (self.COLLECTIONS[collection], next_marker)
                )
            seen_markers.add(next_marker)
            marker = next_marker

        return {collection: values}

    def _get_collection(self, collection, marker=None):
        path = self.COLLECTIONS[collection]
        get = getattr(self.neutron_client, "get", None)
        if get is None:
            raise NeutronClientFactoryError(
                "neutronclient does not expose generic GET for %s" % path
            )
        params = {}
        if self.page_size:
            params["limit"] = self.page_size
        if marker:
            params["marker"] = marker
        if not params:
            try:
                return get(path)
            except TypeError:
                return get(path, params={})
        try:
            return get(path, params=params)
        except TypeError as exc:
            raise NeutronClientFactoryError(
                "neutronclient generic GET for %s does not support pagination params: %s"
                % (path, exc)
            )

    def _has_next_link(self, links):
        for link in links or []:
            if link.get("rel") == "next":
                return True
        return False


class StaticPortSource(object):
    def __init__(self, ports):
        self.ports = list(ports)

    def list_ports_for_host(self):
        return list(self.ports)


class UnavailablePortSource(object):
    def __init__(self, reason):
        self.reason = reason

    def list_ports_for_host(self):
        raise PortSourceUnavailable(self.reason)


def neutron_client_kwargs_from_env(env=None):
    env = env or os.environ
    auth_url = env.get("OS_AUTH_URL")
    username = env.get("OS_USERNAME")
    password = env.get("OS_PASSWORD")
    tenant_name = env.get("OS_TENANT_NAME") or env.get("OS_PROJECT_NAME")

    missing = []
    for key, value in (
        ("OS_AUTH_URL", auth_url),
        ("OS_USERNAME", username),
        ("OS_PASSWORD", password),
        ("OS_TENANT_NAME/OS_PROJECT_NAME", tenant_name),
    ):
        if not value:
            missing.append(key)
    if missing:
        raise NeutronClientFactoryError(
            "missing neutronclient auth environment: %s" % ", ".join(missing)
        )

    kwargs = {
        "auth_url": auth_url,
        "username": username,
        "password": password,
        "tenant_name": tenant_name,
    }
    optional_env = {
        "OS_REGION_NAME": "region_name",
        "OS_CACERT": "ca_cert",
        "OS_USER_DOMAIN_NAME": "user_domain_name",
        "OS_PROJECT_DOMAIN_NAME": "project_domain_name",
    }
    for env_key, kwarg_key in optional_env.items():
        value = env.get(env_key)
        if value:
            kwargs[kwarg_key] = value
    endpoint_type = env.get("OS_ENDPOINT_TYPE") or env.get("OS_INTERFACE")
    if endpoint_type:
        kwargs["endpoint_type"] = normalize_endpoint_type(endpoint_type)
    if env.get("OS_INSECURE"):
        kwargs["insecure"] = env.get("OS_INSECURE").lower() in ("1", "true", "yes")
    return kwargs


def normalize_endpoint_type(endpoint_type):
    endpoint_type = endpoint_type.strip()
    legacy = {
        "public": "publicURL",
        "internal": "internalURL",
        "admin": "adminURL",
    }
    return legacy.get(endpoint_type, endpoint_type)


def build_neutronclient_from_env(env=None):
    try:
        from neutronclient.v2_0 import client as neutron_client
    except Exception as exc:
        raise NeutronClientFactoryError("python-neutronclient unavailable: %s" % exc)
    return neutron_client.Client(**neutron_client_kwargs_from_env(env=env))


def build_aria_acl_client_from_env(env=None, page_size=None):
    return AriaAclRestClient(
        build_neutronclient_from_env(env=env),
        page_size=page_size,
    )


def build_port_source(config, host, env=None):
    source = (config.port_source or "disabled").strip().lower()
    if source in ("disabled", "none", "static"):
        return UnavailablePortSource(
            "full resync port source is disabled; set [neutron] port_source=neutronclient"
        )
    if source == "neutronclient":
        return NeutronPortSource(
            build_neutronclient_from_env(env=env),
            host,
            page_size=config.port_page_size,
        )
    return UnavailablePortSource("unsupported full resync port source: %s" % source)
