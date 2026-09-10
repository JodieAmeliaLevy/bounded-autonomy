// agent_policies.cedar
// The rules of the game for the demo agent.
// Cedar's built in default is DENY: if no permit below matches, the answer is no.
// Policies are numbered by their order in this file: policy0, policy1, policy2, policy3.

// policy0: the agent may read files, but only inside the workspace folder.
permit(
  principal == Agent::"demo-agent",
  action == Action::"read_file",
  resource
) when {
  resource.path like "workspace/*"
};

// policy1: the agent may fetch web pages, but only from an explicit allowlist of domains.
permit(
  principal == Agent::"demo-agent",
  action == Action::"fetch_url",
  resource
) when {
  ["example.com", "raw.githubusercontent.com"].contains(resource.domain)
};

// policy2: nothing that looks like a secret is ever readable, even inside the workspace.
// A forbid always beats a permit in Cedar.
forbid(
  principal,
  action == Action::"read_file",
  resource
) when {
  resource.path like "*secret*" || resource.path like "*.env*"
};

// policy3: the agent may run code, but only when the call is happening inside a sandbox.
// The permission exists because the boundary exists. This is bounded autonomy in one rule.
permit(
  principal == Agent::"demo-agent",
  action == Action::"run_code",
  resource == Sandbox::"e2b"
) when {
  context.sandboxed == true
};