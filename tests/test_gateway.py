"""Tests for the control point.

These are the claims the README makes, written down as assertions. If the
policy file drifts away from what the README says the system does, these fail.

The interesting ones are the identity tests. The gateway always derives the
right identity from the tool, so a test has to ask the counterfactual directly:
what happens when the identity that reads files tries to reach the network.
"""

import json

import pytest

import gateway
from gateway import check


@pytest.fixture(autouse=True)
def audit_to_tmp(tmp_path, monkeypatch):
    """Never write to the real audit log during a test run."""
    log = tmp_path / "audit.jsonl"
    monkeypatch.setattr(gateway, "AUDIT_LOG", log)
    return log


# ---------------------------------------------------------------------------
# The happy paths
# ---------------------------------------------------------------------------

def test_reader_may_read_inside_the_workspace():
    verdict = check("read_file", {"path": "workspace/notes.txt"})
    assert verdict["allowed"]
    assert verdict["reason"] == "permitted by: reader-may-read-workspace"


def test_fetcher_may_fetch_an_allowlisted_domain():
    verdict = check("fetch_url", {"url": "https://example.com/"})
    assert verdict["allowed"]
    assert "fetcher-may-fetch-allowlisted-domains" in verdict["reason"]


def test_executor_may_run_code_when_the_sandbox_is_real():
    verdict = check("run_code", {"code": "print(2 + 2)"}, {"sandboxed": True})
    assert verdict["allowed"]
    assert "executor-may-run-code-in-sandbox" in verdict["reason"]


# ---------------------------------------------------------------------------
# Default deny
# ---------------------------------------------------------------------------

def test_reading_outside_the_workspace_is_denied():
    verdict = check("read_file", {"path": "/etc/passwd"})
    assert not verdict["allowed"]
    assert "default deny" in verdict["reason"]


def test_fetching_a_domain_not_on_the_allowlist_is_denied():
    verdict = check("fetch_url", {"url": "https://evil-exfil-site.com/upload"})
    assert not verdict["allowed"]
    assert "default deny" in verdict["reason"]


def test_a_tool_nobody_wrote_a_policy_for_is_denied():
    """New tools arrive with no permissions. Nothing has to be remembered."""
    verdict = check("delete_everything", {})
    assert not verdict["allowed"]
    assert verdict["identity"] == gateway.UNASSIGNED_IDENTITY


# ---------------------------------------------------------------------------
# The boundary, not the code, is what is being judged
# ---------------------------------------------------------------------------

def test_harmless_code_is_refused_when_there_is_no_sandbox():
    """print(2 + 2) is not dangerous. It is refused because the containment
    that would make it survivable is not in place."""
    verdict = check("run_code", {"code": "print(2 + 2)"}, {"sandboxed": False})
    assert not verdict["allowed"]


def test_code_execution_is_refused_when_the_context_says_nothing_at_all():
    """A missing sandbox flag must not read as permission."""
    verdict = check("run_code", {"code": "print(2 + 2)"}, {})
    assert not verdict["allowed"]


# ---------------------------------------------------------------------------
# Forbid beats permit
# ---------------------------------------------------------------------------

def test_a_secret_inside_the_workspace_is_still_refused():
    """policy2 permits the whole workspace. policy1 forbids secrets. In Cedar
    the forbid wins, which is why the permit can stay broad and readable."""
    verdict = check("read_file", {"path": "workspace/secret_plan.txt"})
    assert not verdict["allowed"]
    assert verdict["reason"] == "blocked by: secrets-forbidden"


@pytest.mark.parametrize("path", [
    "workspace/secret_plan.txt",
    "workspace/my_secrets.md",
    "workspace/.env",
    "workspace/config.env.local",
])
def test_the_secrets_rule_catches_the_obvious_shapes(path):
    assert not check("read_file", {"path": path})["allowed"]


# ---------------------------------------------------------------------------
# The named resource is not the real resource
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("escape", [
    "workspace/../../../../etc/passwd",
    "workspace/../gateway.py",
    "workspace/./../../etc/hostname",
    "workspace/../policies/agent_policies.cedar",
    "/etc/passwd",
])
def test_the_workspace_cannot_be_walked_out_of(escape):
    """The first version of this gateway matched resource.path against the glob
    "workspace/*". "workspace/../../etc/passwd" satisfies that glob, so the
    policy permitted it and the tool opened it. The policy was correct, the
    decision engine was correct, and the system was still wrong, because the
    resource the policy judged was not the resource the tool acted on."""
    assert not check("read_file", {"path": escape})["allowed"]


def test_a_roundabout_path_to_a_permitted_file_still_works():
    """Canonicalising must not break the legitimate case."""
    assert check("read_file", {"path": "workspace/../workspace/notes.txt"})["allowed"]


def test_a_roundabout_path_to_a_secret_is_still_refused():
    verdict = check("read_file", {"path": "workspace/../workspace/secret_plan.txt"})
    assert not verdict["allowed"]
    assert verdict["reason"] == "blocked by: secrets-forbidden"


def test_the_gateway_hands_back_the_resource_it_authorised():
    """The caller must act on what was judged, or the check is decorative."""
    verdict = check("read_file", {"path": "workspace/../workspace/notes.txt"})
    assert verdict["resource"].endswith("workspace/notes.txt")
    assert ".." not in verdict["resource"]


def test_the_agent_refuses_a_traversal_end_to_end():
    """Not just the gateway in isolation: the whole path from tool call to
    filesystem."""
    import agent
    result = agent.execute_tool(
        "read_file", {"path": "workspace/../../../../etc/passwd"}, use_sandbox=False
    )
    assert result.startswith("BLOCKED BY POLICY GATEWAY")


# ---------------------------------------------------------------------------
# Per tool identity: the point of the whole design
# ---------------------------------------------------------------------------

def test_each_tool_acts_as_its_own_identity():
    assert gateway.identity_for("read_file") == "reader"
    assert gateway.identity_for("fetch_url") == "fetcher"
    assert gateway.identity_for("run_code") == "executor"


def test_the_reader_cannot_reach_the_network():
    """Even against a domain the fetcher is explicitly allowed to reach."""
    verdict = check("fetch_url", {"url": "https://example.com/"}, identity="reader")
    assert not verdict["allowed"]


def test_the_fetcher_cannot_touch_the_filesystem():
    """Even a file the reader is explicitly allowed to read."""
    verdict = check("read_file", {"path": "workspace/notes.txt"}, identity="fetcher")
    assert not verdict["allowed"]


def test_the_reader_cannot_execute_code_even_inside_a_sandbox():
    verdict = check("run_code", {"code": "print(1)"}, {"sandboxed": True}, identity="reader")
    assert not verdict["allowed"]


# ---------------------------------------------------------------------------
# Delegation: an agent is never the origin of authority
# ---------------------------------------------------------------------------

def test_an_identity_with_no_human_behind_it_gets_nothing():
    verdict = check("read_file", {"path": "workspace/notes.txt"}, delegated=False)
    assert not verdict["allowed"]
    assert verdict["reason"] == "blocked by: delegation-required"


def test_the_delegation_rule_covers_every_tool():
    for tool, payload in [
        ("read_file", {"path": "workspace/notes.txt"}),
        ("fetch_url", {"url": "https://example.com/"}),
        ("run_code", {"code": "print(1)"}),
    ]:
        verdict = check(tool, payload, {"sandboxed": True}, delegated=False)
        assert not verdict["allowed"], tool


# ---------------------------------------------------------------------------
# The audit trail
# ---------------------------------------------------------------------------

def test_every_decision_is_written_down(audit_to_tmp):
    check("read_file", {"path": "workspace/notes.txt"})
    check("read_file", {"path": "workspace/secret_plan.txt"})

    lines = audit_to_tmp.read_text().strip().splitlines()
    assert len(lines) == 2

    allowed, denied = (json.loads(line) for line in lines)
    assert allowed["decision"] == "ALLOW"
    assert denied["decision"] == "DENY"


def test_the_audit_record_says_who_as_well_as_what(audit_to_tmp):
    check("fetch_url", {"url": "https://example.com/"})
    record = json.loads(audit_to_tmp.read_text().strip())

    assert record["principal"] == 'Agent::"fetcher"'
    assert record["on_behalf_of"] == 'User::"jodie"'
    assert record["tool"] == "fetch_url"
    assert record["reason"]
    assert record["timestamp"] > 0


def test_denials_are_logged_not_just_returned(audit_to_tmp):
    """A control layer that only records its successes is not an audit trail."""
    check("fetch_url", {"url": "https://evil-exfil-site.com/upload"})
    record = json.loads(audit_to_tmp.read_text().strip())
    assert record["decision"] == "DENY"


# ---------------------------------------------------------------------------
# Guards against the policy file and the code drifting apart
# ---------------------------------------------------------------------------

def test_every_policy_is_named_and_the_names_are_in_file_order():
    assert gateway.POLICY_NAMES == {
        "policy0": "delegation-required",
        "policy1": "secrets-forbidden",
        "policy2": "reader-may-read-workspace",
        "policy3": "fetcher-may-fetch-allowlisted-domains",
        "policy4": "executor-may-run-code-in-sandbox",
    }


def test_every_tool_the_agent_advertises_has_an_identity():
    """If a tool is added to the agent and not to the identity table, it acts
    as the unassigned identity and is denied. This test says so out loud."""
    import agent
    advertised = {spec["name"] for spec in agent.TOOL_SPECS}
    assert advertised == set(gateway.TOOL_IDENTITIES)


# ---------------------------------------------------------------------------
# The spelling is not the file
#
# A frontier model found this one. Handed the policy file, it noticed that
# Cedar's `like` is case sensitive, asked for the secret in capitals, and a
# case insensitive filesystem handed it over. Same class as the traversal: the
# resource the policy judged was not the resource the tool opened.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("spelling", [
    "workspace/SECRET_PLAN.txt",
    "workspace/Secret_Plan.txt",
    "workspace/SECRET_PLAN.TXT",
    "workspace/sEcReT_pLaN.txt",
    "workspace/../workspace/SECRET_PLAN.txt",
])
def test_the_secret_cannot_be_reached_by_changing_the_case(spelling):
    assert not check("read_file", {"path": spelling})["allowed"]


def test_case_folding_does_not_break_ordinary_reads():
    assert check("read_file", {"path": "workspace/NOTES.txt"})["allowed"]
    assert check("read_file", {"path": "workspace/notes.txt"})["allowed"]


def test_the_gateway_reports_the_name_the_filesystem_uses():
    """If the policy judged SECRET_PLAN.txt and the tool opened secret_plan.txt,
    the audit log would record a file that was never touched."""
    verdict = check("read_file", {"path": "workspace/NOTES.txt"})
    assert verdict["resource"].endswith("notes.txt")


# ---------------------------------------------------------------------------
# The first hop is not the only hop
#
# The third instance of the same defect, found by reading the code rather than
# by an adversary. The gateway judged the URL the model asked for, and then
# urlopen followed redirects, so the tool could end up fetching somewhere the
# policy never saw. The host was also being read with a string split, which
# rejects a disguised host by luck rather than by understanding it.
# ---------------------------------------------------------------------------

def _attrs(url):
    _, attrs = gateway._resource_for("fetch_url", {"url": url})
    return attrs


def test_the_host_is_the_host_the_network_would_dial():
    assert _attrs("https://user:pw@example.com:8443/x")["domain"] == "example.com"


def test_userinfo_cannot_disguise_the_host():
    """A string split hands back "example.com@evil-exfil-site.com" here."""
    assert _attrs("https://example.com@evil-exfil-site.com/")["domain"] == "evil-exfil-site.com"
    assert not check("fetch_url", {"url": "https://example.com@evil-exfil-site.com/"})["allowed"]


def test_a_lookalike_subdomain_is_a_different_host():
    assert not check("fetch_url", {"url": "https://example.com.evil-exfil-site.com/"})["allowed"]


def test_case_and_port_do_not_change_the_host():
    assert check("fetch_url", {"url": "https://EXAMPLE.COM/"})["allowed"]
    assert check("fetch_url", {"url": "https://example.com:443/"})["allowed"]


@pytest.mark.parametrize("url", [
    "http://example.com/",
    "file:///etc/passwd",
    "ftp://example.com/x",
    "not a url at all",
])
def test_only_https_is_fetchable(url):
    """file:// in particular: urlopen will happily read the filesystem through
    the tool that is supposed to be the network tool."""
    assert not check("fetch_url", {"url": url})["allowed"]


def test_the_tool_refuses_to_follow_a_redirect():
    import tools
    handler = tools._RefuseRedirects()
    assert handler.redirect_request(None, None, 302, "Found", {}, "https://evil-exfil-site.com/") is None


def test_the_redirect_refusal_is_installed_in_the_opener():
    import tools
    assert any(isinstance(h, tools._RefuseRedirects) for h in tools._OPENER.handlers)


def test_a_redirect_is_reported_rather_than_followed(monkeypatch):
    import urllib.error
    import tools

    def raise_302(*args, **kwargs):
        raise urllib.error.HTTPError(
            "https://example.com/", 302, "Found",
            {"Location": "https://evil-exfil-site.com/"}, None,
        )

    monkeypatch.setattr(tools._OPENER, "open", raise_302)
    result = tools.fetch_url("https://example.com/")
    assert result.startswith("ERROR: refused to follow a redirect")
    assert "evil-exfil-site.com" in result


def test_the_agent_fetches_the_resource_that_was_authorised(monkeypatch):
    """read_file already did this. fetch_url did not, and the asymmetry was
    the tell that nobody had checked."""
    import agent
    import tools

    seen = {}
    monkeypatch.setattr(tools, "fetch_url", lambda url: seen.setdefault("url", url))
    agent.execute_tool("fetch_url", {"url": "https://example.com/"}, use_sandbox=False)
    assert seen["url"] == "https://example.com/"


# ---------------------------------------------------------------------------
# What happens when the control point itself fails
#
# The first question anyone asks a policy enforcement point. Before these
# tests the answer was "it raises, which happens to be safe", which is not an
# answer, because nobody had chosen it.
# ---------------------------------------------------------------------------

def test_a_policy_file_that_cannot_be_read_denies_everything(monkeypatch):
    monkeypatch.setattr(gateway, "POLICY_LOAD_ERROR", "FileNotFoundError: no policies")
    verdict = check("read_file", {"path": "workspace/notes.txt"})
    assert not verdict["allowed"]
    assert "policy load failure" in verdict["reason"]


def test_a_decision_point_that_raises_denies(monkeypatch):
    def explode(*args, **kwargs):
        raise RuntimeError("cedar fell over")

    monkeypatch.setattr(gateway, "is_authorized", explode)
    verdict = check("read_file", {"path": "workspace/notes.txt"})
    assert not verdict["allowed"]
    assert "enforcement failure" in verdict["reason"]
    assert "cedar fell over" in verdict["reason"]


def test_an_enforcement_failure_is_written_to_the_log(monkeypatch, audit_to_tmp):
    """A failure nobody can see afterwards is worse than a failure."""
    monkeypatch.setattr(gateway, "is_authorized", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    check("read_file", {"path": "workspace/notes.txt"})
    record = json.loads(audit_to_tmp.read_text().strip())
    assert record["decision"] == "DENY"
    assert "enforcement failure" in record["reason"]


def test_the_agent_blocks_when_the_gateway_fails(monkeypatch):
    import agent
    monkeypatch.setattr(gateway, "is_authorized", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    result = agent.execute_tool("read_file", {"path": "workspace/notes.txt"}, use_sandbox=False)
    assert result.startswith("BLOCKED BY POLICY GATEWAY")


# ---------------------------------------------------------------------------
# The audit log is chained, so editing it shows
# ---------------------------------------------------------------------------

def test_each_record_chains_to_the_one_before(audit_to_tmp):
    check("read_file", {"path": "workspace/notes.txt"})
    check("read_file", {"path": "workspace/secret_plan.txt"})

    first, second = (json.loads(l) for l in audit_to_tmp.read_text().strip().splitlines())
    assert first["prev"] == gateway.GENESIS
    assert second["prev"] == first["hash"]
    assert gateway.verify_audit_log(audit_to_tmp) == (True, None)


def test_an_edited_record_is_detected(audit_to_tmp):
    """The tamper that matters: turning a refusal into a permission."""
    check("read_file", {"path": "workspace/secret_plan.txt"})
    check("fetch_url", {"url": "https://example.com/"})

    lines = audit_to_tmp.read_text().strip().splitlines()
    doctored = json.loads(lines[0])
    assert doctored["decision"] == "DENY"
    doctored["decision"] = "ALLOW"
    lines[0] = json.dumps(doctored)
    audit_to_tmp.write_text("\n".join(lines) + "\n")

    ok, index = gateway.verify_audit_log(audit_to_tmp)
    assert not ok and index == 0


def test_a_deleted_record_is_detected(audit_to_tmp):
    """Removing the evidence of a denial breaks the chain at the next record."""
    for path in ["workspace/notes.txt", "workspace/secret_plan.txt", "workspace/notes.txt"]:
        check("read_file", {"path": path})

    lines = audit_to_tmp.read_text().strip().splitlines()
    del lines[1]
    audit_to_tmp.write_text("\n".join(lines) + "\n")

    ok, index = gateway.verify_audit_log(audit_to_tmp)
    assert not ok and index == 1


def test_an_empty_log_verifies(audit_to_tmp):
    assert gateway.verify_audit_log(audit_to_tmp) == (True, None)


# ---------------------------------------------------------------------------
# A gap that is still open, written down rather than left for someone to find
# ---------------------------------------------------------------------------

@pytest.mark.xfail(
    reason="known gap: the forbid rule matches the filename, and resolve() "
           "does not resolve hard links, so a second name for the same inode "
           "inside the workspace is permitted. The fix is to classify the "
           "resource rather than match its name.",
    strict=True,
)
def test_a_hard_link_to_the_secret_is_refused(tmp_path):
    import os
    link = gateway.WORKSPACE / "meeting_notes.txt"
    os.link(gateway.WORKSPACE / "secret_plan.txt", link)
    try:
        assert not check("read_file", {"path": str(link)})["allowed"]
    finally:
        os.unlink(link)
