// agent_policies.cedar
//
// The rules of the game. Cedar's built in default is DENY: if no permit below
// matches, the answer is no, and a forbid always beats a permit.
//
// Every policy carries an @id annotation. gateway.py reads those annotations
// out of this file in order, so the reason written into the audit log is the
// name of the rule that actually fired and cannot drift from this file.
//
// Note the principals. There is no single "the agent" here. Each tool acts as
// its own identity, so the identity that can read files has no route to the
// network, and the identity that can reach the network has no route to the
// filesystem. Least privilege is structural rather than a matter of remembering
// to write the right condition.

// ---------------------------------------------------------------------------
// policy0: no agent identity acts without a human principal behind it.
//
// An agent is never the origin of authority, only the carrier of someone
// else's. An identity presenting no delegation gets nothing at all, whatever
// else the policies below might permit.
// ---------------------------------------------------------------------------
@id("delegation-required")
forbid(
  principal in AgentGroup::"research-assistant",
  action,
  resource
) unless {
  principal has on_behalf_of
};

// ---------------------------------------------------------------------------
// policy1: nothing that looks like a secret is ever readable, by any identity,
// even inside an otherwise readable folder. A forbid always beats a permit.
// ---------------------------------------------------------------------------
@id("secrets-forbidden")
forbid(
  principal in AgentGroup::"research-assistant",
  action == Action::"read_file",
  resource
) when {
  resource.path like "*secret*" || resource.path like "*.env*"
};

// ---------------------------------------------------------------------------
// policy2: the reader identity may read files, and only inside the workspace.
// It is named in the principal position, so no other identity inherits this.
// ---------------------------------------------------------------------------
@id("reader-may-read-workspace")
permit(
  principal == Agent::"reader",
  action == Action::"read_file",
  resource
) when {
  principal has on_behalf_of &&
  resource.path like "workspace/*"
};

// ---------------------------------------------------------------------------
// policy3: the fetcher identity may fetch web pages, and only from an explicit
// allowlist of domains. Everything else falls through to default deny.
// ---------------------------------------------------------------------------
@id("fetcher-may-fetch-allowlisted-domains")
permit(
  principal == Agent::"fetcher",
  action == Action::"fetch_url",
  resource
) when {
  principal has on_behalf_of &&
  ["example.com", "raw.githubusercontent.com"].contains(resource.domain)
};

// ---------------------------------------------------------------------------
// policy4: the executor identity may run code, and only when the call is
// actually happening inside a sandbox.
//
// This is the thesis in one rule. The permission is not smaller than it would
// otherwise be. It is conditional on the boundary being real at the moment of
// the call. Remove the boundary and the permission ceases to exist.
// ---------------------------------------------------------------------------
@id("executor-may-run-code-in-sandbox")
permit(
  principal == Agent::"executor",
  action == Action::"run_code",
  resource == Sandbox::"e2b"
) when {
  principal has on_behalf_of &&
  context has sandboxed &&
  context.sandboxed == true
};
