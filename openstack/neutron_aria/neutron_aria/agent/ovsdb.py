from __future__ import absolute_import

import json
import subprocess


class OvsInterface(object):
    def __init__(self, name, ofport=None, external_ids=None, ifindex=None):
        self.name = name
        self.ofport = ofport
        self.external_ids = external_ids or {}
        self.ifindex = ifindex

    def to_dict(self):
        return {
            "name": self.name,
            "ofport": self.ofport,
            "external_ids": dict(self.external_ids),
            "ifindex": self.ifindex,
        }


def ovs_value_to_python(value):
    if isinstance(value, list) and len(value) == 2 and value[0] == "map":
        return dict(value[1])
    if isinstance(value, list) and len(value) == 2 and value[0] == "set":
        return list(value[1])
    if isinstance(value, list) and len(value) == 2 and value[0] == "uuid":
        return value[1]
    return value


def parse_ovs_interfaces_json(payload, ifindex_lookup=None):
    document = json.loads(payload)
    headings = document.get("headings", [])
    interfaces = []

    for row in document.get("data", []):
        values = {}
        for index, heading in enumerate(headings):
            values[heading] = ovs_value_to_python(row[index])

        name = values.get("name")
        if not name:
            continue

        ifindex = None
        if ifindex_lookup is not None:
            try:
                ifindex = ifindex_lookup(name)
            except EnvironmentError:
                ifindex = None
            except OSError:
                ifindex = None

        interfaces.append(
            OvsInterface(
                name=name,
                ofport=values.get("ofport"),
                external_ids=values.get("external_ids") or {},
                ifindex=ifindex,
            )
        )

    return interfaces


class OvsdbInterfaceReader(object):
    def __init__(self, ovs_vsctl="ovs-vsctl", ifindex_lookup=None):
        self.ovs_vsctl = ovs_vsctl
        self.ifindex_lookup = ifindex_lookup

    def list_interfaces(self):
        cmd = [
            self.ovs_vsctl,
            "--format=json",
            "--columns=name,ofport,external_ids",
            "list",
            "Interface",
        ]
        output = subprocess.check_output(cmd)
        if not isinstance(output, str):
            output = output.decode("utf-8")
        return parse_ovs_interfaces_json(output, self.ifindex_lookup)
