from __future__ import absolute_import

import copy
import json
import os


SCENARIO_PATH = os.path.abspath(os.path.join(
    os.path.dirname(__file__),
    "..",
    "..",
    "..",
    "..",
    "..",
    "docs",
    "neutron-status-contract-v1-scenarios.json",
))

V2_SCENARIO_PATH = os.path.abspath(os.path.join(
    os.path.dirname(__file__),
    "..",
    "..",
    "..",
    "..",
    "..",
    "docs",
    "neutron-status-contract-v2-scenarios.json",
))

V3_SCENARIO_PATH = os.path.abspath(os.path.join(
    os.path.dirname(__file__),
    "..",
    "..",
    "..",
    "..",
    "..",
    "docs",
    "neutron-status-contract-v3-scenarios.json",
))


def load_status_contract_fixture():
    with open(SCENARIO_PATH, "r") as stream:
        return json.load(stream)


def load_status_contract_v2_fixture():
    with open(V2_SCENARIO_PATH, "r") as stream:
        return json.load(stream)


def load_status_contract_v3_fixture():
    with open(V3_SCENARIO_PATH, "r") as stream:
        return json.load(stream)


def status_v2_scenario(scenario_id):
    for scenario in load_status_contract_v2_fixture()["scenarios"]:
        if scenario["id"] == scenario_id:
            return copy.deepcopy(scenario)
    raise KeyError("unknown status v2 scenario %s" % scenario_id)


def status_v3_scenario(scenario_id):
    for scenario in load_status_contract_v3_fixture()["scenarios"]:
        if scenario["id"] == scenario_id:
            return copy.deepcopy(scenario)
    raise KeyError("unknown status v3 scenario %s" % scenario_id)


def status_scenario(scenario_id):
    for scenario in load_status_contract_fixture()["scenarios"]:
        if scenario["id"] == scenario_id:
            return copy.deepcopy(scenario)
    raise KeyError("unknown status scenario %s" % scenario_id)


def _path_parent(payload, path):
    target = payload
    for component in path[:-1]:
        target = target[component]
    return target, path[-1]


def _apply_mutation(payload, mutation):
    operation = mutation["op"]
    target, key = _path_parent(payload, mutation["path"])
    if operation == "replace":
        target[key] = copy.deepcopy(mutation["value"])
    elif operation == "remove":
        del target[key]
    elif operation == "append_copy":
        collection = target[key]
        collection.append(copy.deepcopy(collection[mutation["index"]]))
    else:
        raise ValueError("unknown fixture mutation %s" % operation)
    return payload


def materialize_status_case(scenario, case):
    if "status" in case:
        return copy.deepcopy(case["status"])
    status = copy.deepcopy(scenario.get("base_status") or scenario["status"])
    status.update(copy.deepcopy(case.get("status_overrides") or {}))
    if case.get("mutation"):
        _apply_mutation(status, case["mutation"])
    return status


def status_scenario_cases(scenario_id):
    scenario = status_scenario(scenario_id)
    cases = scenario.get("cases") or []
    resolved = []
    for case in cases:
        item = copy.deepcopy(case)
        item.setdefault("capabilities", copy.deepcopy(scenario["capabilities"]))
        item.setdefault("expected_python", copy.deepcopy(
            scenario["expected_python"]
        ))
        item["status"] = materialize_status_case(scenario, item)
        resolved.append(item)
    return resolved


def status_scenario_negative_cases(scenario_id):
    scenario = status_scenario(scenario_id)
    resolved = []
    for case in scenario.get("negative_cases") or []:
        item = copy.deepcopy(case)
        item["status"] = materialize_status_case(scenario, item)
        resolved.append(item)
    return resolved


def status_scenario_contract_error_cases(scenario_id):
    scenario = status_scenario(scenario_id)
    resolved = []
    for case in scenario.get("contract_error_cases") or []:
        item = copy.deepcopy(case)
        item["status"] = materialize_status_case(scenario, item)
        resolved.append(item)
    return resolved
