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
