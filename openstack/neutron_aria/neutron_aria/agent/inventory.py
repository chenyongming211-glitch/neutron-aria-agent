from __future__ import absolute_import

import socket
import struct

try:
    import fcntl
except ImportError:
    fcntl = None


ELIGIBLE_OVS_TAP = "eligible_ovs_tap"
PENDING_LOCAL_VALIDATION = "pending_local_validation"
NOT_LOCAL_HOST = "not_local_host"
TAP_NOT_FOUND = "tap_not_found"
IFINDEX_NOT_READY = "ifindex_not_ready"
OVS_BRIDGE_MISMATCH = "not_on_ovs_bridge"


def port_get(port, key, default=None):
    if key in port:
        return port.get(key)
    return port.get(key.replace(":", "_"), default)


def is_compute_owner(device_owner):
    return not device_owner or device_owner.startswith("compute:")


def is_normal_vnic(vnic_type):
    return vnic_type in (None, "", "normal")


def guess_tap_name(port_id):
    if not port_id:
        return ""
    return "tap" + port_id[:11]


def linux_ifindex(ifname):
    if hasattr(socket, "if_nametoindex"):
        return socket.if_nametoindex(ifname)

    if fcntl is None:
        raise OSError("ifindex lookup is not available on this platform")

    name = ifname[:15]
    if not isinstance(name, bytes):
        name = name.encode("utf-8")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = struct.pack("16sH14s", name, socket.AF_UNSPEC, b"\x00" * 14)
        result = fcntl.ioctl(sock.fileno(), 0x8933, ifreq)
        return struct.unpack("16sI12s", result)[1]
    finally:
        sock.close()


class PortInventoryBuilder(object):
    def __init__(
        self,
        host,
        managed_domains=None,
        ifindex_lookup=None,
        ovs_bridge="br-int",
        acl_index=None,
        qos_index=None,
    ):
        self.host = host
        self.managed_domains = list(managed_domains or ["acl"])
        self.ifindex_lookup = ifindex_lookup or linux_ifindex
        self.ovs_bridge = ovs_bridge
        self.acl_index = acl_index
        self.qos_index = qos_index

    def build_snapshot(self, neutron_ports, ovs_interfaces, generation):
        ports = []
        iface_by_port_id = self._iface_by_port_id(ovs_interfaces)
        for port in neutron_ports:
            if port_get(port, "binding:host_id") not in (None, "", self.host):
                continue
            ports.append(self._snapshot_port(port, iface_by_port_id))
        return {
            "generation": generation,
            "host": self.host,
            "ports": ports,
        }

    def _iface_by_port_id(self, ovs_interfaces):
        mapping = {}
        for iface in ovs_interfaces:
            iface_id = iface.external_ids.get("iface-id")
            if iface_id:
                mapping[iface_id] = iface
        return mapping

    def _snapshot_port(self, port, iface_by_port_id):
        port_id = port.get("id") or port.get("port_id") or ""
        device_owner = port.get("device_owner")
        vif_type = port_get(port, "binding:vif_type")
        vnic_type = port_get(port, "binding:vnic_type")
        iface = iface_by_port_id.get(port_id)
        ifname = iface.name if iface is not None else guess_tap_name(port_id)
        ovs_iface_id = iface.external_ids.get("iface-id") if iface is not None else None

        if not is_compute_owner(device_owner):
            return self._with_effective_domains(port, self._port_dict(
                port_id, ifname, None, False,
                "not_applicable_device_owner:%s" % device_owner,
                device_owner, vif_type, vnic_type, ovs_iface_id,
            ))

        if vif_type not in (None, "", "ovs"):
            return self._with_effective_domains(port, self._port_dict(
                port_id, ifname, None, False,
                "unsupported_vif_type:%s" % vif_type,
                device_owner, vif_type, vnic_type, ovs_iface_id,
            ))

        if not is_normal_vnic(vnic_type):
            return self._with_effective_domains(port, self._port_dict(
                port_id, ifname, None, False,
                "unsupported_vnic_type:%s" % vnic_type,
                device_owner, vif_type, vnic_type, ovs_iface_id,
            ))

        if iface is None:
            return self._with_effective_domains(port, self._port_dict(
                port_id, ifname, None, False, TAP_NOT_FOUND,
                device_owner, vif_type, vnic_type, ovs_iface_id,
            ))

        if iface.bridge != self.ovs_bridge:
            return self._with_effective_domains(port, self._port_dict(
                port_id, ifname, None, False,
                "%s:%s" % (OVS_BRIDGE_MISMATCH, self.ovs_bridge),
                device_owner, vif_type, vnic_type, ovs_iface_id,
            ))

        ifindex = iface.ifindex
        if ifindex is None:
            try:
                ifindex = self.ifindex_lookup(iface.name)
            except EnvironmentError:
                return self._with_effective_domains(port, self._port_dict(
                    port_id, ifname, None, False, IFINDEX_NOT_READY,
                    device_owner, vif_type, vnic_type, ovs_iface_id,
                ))
            except OSError:
                return self._with_effective_domains(port, self._port_dict(
                    port_id, ifname, None, False, IFINDEX_NOT_READY,
                    device_owner, vif_type, vnic_type, ovs_iface_id,
                ))

        return self._with_effective_domains(port, self._port_dict(
            port_id, ifname, ifindex, True, ELIGIBLE_OVS_TAP,
            device_owner, vif_type or "ovs", vnic_type or "normal", ovs_iface_id,
        ))

    def _port_dict(
        self,
        port_id,
        ifname,
        ifindex,
        eligible,
        disposition,
        device_owner,
        vif_type,
        vnic_type,
        ovs_iface_id,
    ):
        return {
            "port_id": port_id,
            "ifname": ifname,
            "ifindex": ifindex,
            "eligible": bool(eligible),
            "disposition": disposition,
            "device_owner": device_owner,
            "vif_type": vif_type,
            "vnic_type": vnic_type,
            "network_backend": "openvswitch",
            "ovs_iface_id": ovs_iface_id,
            "managed_domains": list(self.managed_domains) if eligible else [],
        }

    def _with_effective_domains(self, neutron_port, snapshot_port):
        if self.acl_index is not None:
            snapshot_port["acl"] = self.acl_index.effective_for_port(
                neutron_port,
                snapshot_port,
            )
        if self.qos_index is not None:
            snapshot_port["qos"] = self.qos_index.effective_for_port(
                neutron_port,
                snapshot_port,
            )
        return snapshot_port


class PortCandidateBuilder(object):
    """Build a Neutron-logical candidate snapshot.

    Product-mode neutron-aria-agent must not read OVSDB or inspect local tap
    interfaces. It projects Neutron's authoritative logical state and lets the
    local aria-datapath UDS endpoint validate br-int membership, ifname, and
    ifindex before attach.
    """

    def __init__(self, host, managed_domains=None, acl_index=None, qos_index=None):
        self.host = host
        self.managed_domains = list(managed_domains or ["acl"])
        self.acl_index = acl_index
        self.qos_index = qos_index

    def build_snapshot(self, neutron_ports, generation):
        ports = []
        for port in neutron_ports:
            if port_get(port, "binding:host_id") not in (None, "", self.host):
                continue
            ports.append(self._snapshot_port(port))
        return {
            "generation": generation,
            "host": self.host,
            "ports": ports,
        }

    def _snapshot_port(self, port):
        port_id = port.get("id") or port.get("port_id") or ""
        device_owner = port.get("device_owner")
        vif_type = port_get(port, "binding:vif_type")
        vnic_type = port_get(port, "binding:vnic_type")

        if not is_compute_owner(device_owner):
            return self._with_effective_domains(port, self._port_dict(
                port_id, False,
                "not_applicable_device_owner:%s" % device_owner,
                device_owner, vif_type, vnic_type,
            ))

        if vif_type not in (None, "", "ovs"):
            return self._with_effective_domains(port, self._port_dict(
                port_id, False,
                "unsupported_vif_type:%s" % vif_type,
                device_owner, vif_type, vnic_type,
            ))

        if not is_normal_vnic(vnic_type):
            return self._with_effective_domains(port, self._port_dict(
                port_id, False,
                "unsupported_vnic_type:%s" % vnic_type,
                device_owner, vif_type, vnic_type,
            ))

        return self._with_effective_domains(port, self._port_dict(
            port_id, True, PENDING_LOCAL_VALIDATION,
            device_owner, vif_type or "ovs", vnic_type or "normal",
        ))

    def _port_dict(
        self,
        port_id,
        eligible,
        disposition,
        device_owner,
        vif_type,
        vnic_type,
    ):
        return {
            "port_id": port_id,
            "ifname": "",
            "ifindex": None,
            "eligible": bool(eligible),
            "disposition": disposition,
            "device_owner": device_owner,
            "vif_type": vif_type,
            "vnic_type": vnic_type,
            "network_backend": "openvswitch",
            "ovs_iface_id": None,
            "managed_domains": list(self.managed_domains) if eligible else [],
        }

    def _with_effective_domains(self, neutron_port, snapshot_port):
        if self.acl_index is not None:
            snapshot_port["acl"] = self.acl_index.effective_for_port(
                neutron_port,
                snapshot_port,
            )
        if self.qos_index is not None:
            snapshot_port["qos"] = self.qos_index.effective_for_port(
                neutron_port,
                snapshot_port,
            )
        return snapshot_port
