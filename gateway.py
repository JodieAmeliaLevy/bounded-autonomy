"""gateway.py

The control point. Every tool call in this demo passes through check() before
anything actually runs. This is the Policy Enforcement Point: it doesn't decide
the rules itself, it asks Cedar (the Policy Decision Point) and writes down
what happened either way.
"""

import json
import time
from pathlib import Path

from cedarpy import is_authorized, AuthzResult

POLICY_FILE = Path(__file__).parent / "policies" / "agent_policies.cedar"
POLICIES = POLICY_FILE.read_text()

AUDIT_LOG = Path(__file__).parent / "audit_log.jsonl"

POLICY_NAMES = {
    "policy0": "allow reading files inside workspace/",
    "policy1": "allow fetching from allowlisted domains",
    "policy2": "forbid anything that looks like a secret",
    "policy3": "allow run_code only inside a sandbox",
}


def _build_request_and_entities(tool_name: str, tool_input: dict, context: dict):
    """Translate a tool call into Cedar's principal / action / resource shape."""

    principal = {"type": "Agent", "id": "demo-agent"}
    entities = [{"uid": principal, "attrs": {}, "parents": []}]

    if tool_name == "read_file":
        path = tool_input["path"]
        resource = {"type": "File", "id": path}
        entities.append({"uid": resource, "attrs": {"path": path}, "parents": []})

    elif tool_name == "fetch_url":
        url = tool_input["url"]
        domain = url.split("//", 1)[-1].split("/", 1)[0]
        resource = {"type": "Url", "id": url}
        entities.append({"uid": resource, "attrs": {"domain": domain}, "parents": []})

    elif tool_name == "run_code":
        resource = {"type": "Sandbox", "id": "e2b"}
        entities.append({"uid": resource, "attrs": {}, "parents": []})

    else:
        resource = {"type": "Unknown", "id": tool_name}
        entities.append({"uid": resource, "attrs": {}, "parents": []})

    action = {"type": "Action", "id": tool_name}

    request = {
        "principal": principal,
        "action": action,
        "resource": resource,
        "context": context or {},
    }
    return request, entities


def _log(event: dict):
    event["timestamp"] = time.time()
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(event) + "\n")


def check(tool_name: str, tool_input: dict, context: dict = None) -> dict:
    """Ask Cedar whether this tool call is allowed. Always logs the outcome."""

    request, entities = _build_request_and_entities(tool_name, tool_input, context or {})

    result: AuthzResult = is_authorized(request, POLICIES, entities)
    allowed = result.allowed
    reasons = list(result.diagnostics.reasons)

    if allowed and reasons:
        which = ", ".join(POLICY_NAMES.get(r, r) for r in reasons)
        reason = f"permitted by: {which}"
    elif not allowed and reasons:
        which = ", ".join(POLICY_NAMES.get(r, r) for r in reasons)
        reason = f"blocked by: {which}"
    else:
        reason = "blocked by default deny: no policy permits this call"

    _log({
        "tool": tool_name,
        "input": tool_input,
        "context": context or {},
        "decision": "ALLOW" if allowed else "DENY",
        "reason": reason,
    })

    return {"allowed": allowed, "reason": reason}
