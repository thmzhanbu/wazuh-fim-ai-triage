#!/usr/bin/env python3
"""Portable reference for the demonstrated Tines minimization step.

Reconstructed behavior, NOT an export of the deployed TypeScript step.
Read one native Wazuh JSON object on stdin; emit a minimized object or no output.
"""

import json
import sys

ALLOWED_RULES = {"100100", "100101", "100102"}


def object_or_empty(value):
    return value if isinstance(value, dict) else {}


def strings(value):
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def copy_strings(source, keys):
    return {key: source[key] for key in keys if isinstance(source.get(key), str)}


def minimize(alert):
    if not isinstance(alert, dict) or not isinstance(alert.get("rule"), dict):
        raise ValueError("Invalid alert")
    rule = alert["rule"]
    rule_id = rule.get("id")
    if not isinstance(rule_id, (str, int)) or isinstance(rule_id, bool):
        raise ValueError("Invalid rule")
    rule_id = str(rule_id)
    if rule_id not in ALLOWED_RULES:
        return None
    fim = object_or_empty(alert.get("syscheck"))
    if not isinstance(fim.get("path"), str) or fim.get("event") not in {"added", "modified", "deleted"}:
        raise ValueError("Invalid FIM event")
    result = {
        "alert_id": alert.get("id") if isinstance(alert.get("id"), str) else None,
        "rule": {"id": rule_id},
        "agent": copy_strings(object_or_empty(alert.get("agent")), ("id", "name", "ip")),
        "file": {"path": fim["path"], "event_type": fim["event"]},
    }
    if isinstance(alert.get("timestamp"), str):
        result["timestamp"] = alert["timestamp"]
    result["rule"].update(copy_strings(rule, ("description",)))
    if isinstance(rule.get("level"), int) and not isinstance(rule.get("level"), bool):
        result["rule"]["level"] = rule["level"]
    result["rule"]["groups"] = strings(rule.get("groups"))
    result["rule"]["mitre_techniques"] = strings(object_or_empty(rule.get("mitre")).get("id"))
    for side in ("before", "after"):
        hashes = {algorithm: fim[f"{algorithm}_{side}"] for algorithm in ("md5", "sha1", "sha256")
                  if isinstance(fim.get(f"{algorithm}_{side}"), str)}
        if hashes:
            result["file"][f"hashes_{side}"] = hashes
    if isinstance(fim.get("changed_attributes"), list):
        result["file"]["changed_attributes"] = strings(fim["changed_attributes"])
    if isinstance(fim.get("diff"), str):
        result["file"]["content_difference"] = fim["diff"]
    audit = object_or_empty(fim.get("audit"))
    user = object_or_empty(audit.get("user")).get("name")
    process = object_or_empty(audit.get("process")).get("name")
    result["audit"] = {}
    if isinstance(user, str):
        result["audit"]["user"] = user
    if isinstance(process, str):
        result["audit"]["process_name"] = process
    return result


def main():
    try:
        result = minimize(json.load(sys.stdin))
        if result is not None:
            print(json.dumps(result, indent=2))
        return 0
    except (ValueError, TypeError, RecursionError):
        print('{"error":"Invalid alert payload"}', file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
