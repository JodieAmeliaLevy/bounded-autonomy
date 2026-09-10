"""gateway.py

The control point. Every tool call in this project passes through check()
before anything actually runs.

This file is the Policy Enforcement Point. It does not decide the rules. It
translates a tool call into a question Cedar can answer, asks Cedar (the Policy
Decision Point), writes down what happened either way, and returns the verdict.

The thing worth noticing is the principal. There is no single "the agent"
identity here. Each tool acts as its own identity, all of them members of one
group, all of them acting on behalf of a named human. So:

  - the identity that can read files has no route to the network
  - the identity that can reach the network has no route to the filesystem
  - an identity presenting no delegation gets nothing at all

Least privilege is structural. It does not depend on anyone remembering to
write the right condition into the right policy.
"""

import json
import os
import re
import time
from pathlib import Path

from cedarpy import is_authorized, AuthzResult

HERE = Path(__file__).parent

POLICY_FILE = HERE / "policies" / "agent_policies.cedar"
POLICIES = POLICY_FILE.read_text()

# Overridable so the test suite does not write into the real log.
AUDIT_LOG = Path(os.environ.get("AUDIT_LOG", HERE / "audit_log.jsonl"))

# The human the agent is acting for. In a real deployment this comes from the
# authenticated session, not from a constant.
HUMAN_PRINCIPAL = {"type": "User", "id": os.environ.get("ACTING_FOR", "jodie")}

AGENT_GROUP = {"type": "AgentGroup", "id": "research-assistant"}

# One identity per tool. This mapping is the least privilege boundary.
TOOL_IDENTITIES = {
    "read_file": "reader",
    "fetch_url": "fetcher",
    "run_code": "executor",
}

# An identity for anything not in the table above. It is a group member with
# valid delegation, so its denial is an honest "no policy permits this" rather
# than an artefact of a missing attribute.
UNASSIGNED_IDENTITY = "unassigned"


def _policy_names() -> dict:
    """Map Cedar's positional policy ids onto the @id annotations in the file.

    cedarpy reports which policy fired as policy0, policy1 and so on, in file
    order. Reading the annotations out of the same file in the same order means
    the audit log can name the rule, and the names can never drift out of step
    with the policies themselves.
    """
    ids = re.findall(r'@id\("([^"]+)"\)', POLICIES)
    return {f"policy{i}": name for i, name in enumerate(ids)}


POLICY_NAMES = _policy_names()


def identity_for(tool_name: str) -> str:
    """Which identity does this tool act as?"""
    return TOOL_IDENTITIES.get(tool_name, UNASSIGNED_IDENTITY)


def _resource_for(tool_name: str, tool_input: dict):
    """Translate a tool call into the resource Cedar reasons about."""

    if tool_name == "read_file":
        path = tool_input.get("path", "")
        return {"type": "File", "id": path}, {"path": path}

    if tool_name == "fetch_url":
        url = tool_input.get("url", "")
        domain = url.split("//", 1)[-1].split("/", 1)[0]
        return {"type": "Url", "id": url}, {"domain": domain}

    if tool_name == "run_code":
        return {"type": "Sandbox", "id": "e2b"}, {}

    return {"type": "Unknown", "id": tool_name}, {}


def _build(tool_name: str, tool_input: dict, context: dict, identity: str, delegated: bool):
    """Assemble the Cedar request and the entity store it is evaluated against."""

    principal = {"type": "Agent", "id": identity}
    resource, resource_attrs = _resource_for(tool_name, tool_input)

    principal_attrs = {}
    if delegated:
        # An entity reference, not a string. Cedar compares it as an entity,
        # which is what makes the delegation chain checkable rather than
        # decorative.
        principal_attrs["on_behalf_of"] = {"__entity": HUMAN_PRINCIPAL}

    entities = [
        {"uid": AGENT_GROUP, "attrs": {}, "parents": []},
        {"uid": HUMAN_PRINCIPAL, "attrs": {}, "parents": []},
        {"uid": principal, "attrs": principal_attrs, "parents": [AGENT_GROUP]},
        {"uid": resource, "attrs": resource_attrs, "parents": []},
    ]

    request = {
        "principal": principal,
        "action": {"type": "Action", "id": tool_name},
        "resource": resource,
        "context": context or {},
    }
    return request, entities


def _log(event: dict):
    event["timestamp"] = time.time()
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(event) + "\n")


def check(
    tool_name: str,
    tool_input: dict,
    context: dict = None,
    identity: str = None,
    delegated: bool = True,
) -> dict:
    """Ask Cedar whether this tool call is allowed. Always logs the outcome.

    tool_name, tool_input, context
        The call being attempted.

    identity
        Normally derived from the tool. Override it to ask counterfactual
        questions, such as what happens when the reader identity tries to
        fetch a URL. The test suite uses this; the agent never does.

    delegated
        Whether the identity presents a human principal. Setting this False
        models an agent acting on nobody's authority.
    """

    identity = identity or identity_for(tool_name)
    request, entities = _build(tool_name, tool_input, context or {}, identity, delegated)

    result: AuthzResult = is_authorized(request, POLICIES, entities)
    allowed = result.allowed
    reasons = [POLICY_NAMES.get(r, r) for r in result.diagnostics.reasons]

    if allowed and reasons:
        reason = "permitted by: " + ", ".join(reasons)
    elif not allowed and reasons:
        reason = "blocked by: " + ", ".join(reasons)
    else:
        reason = "blocked by default deny: no policy permits this call"

    _log({
        "principal": f'Agent::"{identity}"',
        "on_behalf_of": f'User::"{HUMAN_PRINCIPAL["id"]}"' if delegated else None,
        "tool": tool_name,
        "input": tool_input,
        "context": context or {},
        "decision": "ALLOW" if allowed else "DENY",
        "reason": reason,
    })

    return {"allowed": allowed, "reason": reason, "identity": identity}
