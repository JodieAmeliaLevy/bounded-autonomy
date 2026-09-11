"""agent.py

The brain of the demo: a loop that gives Claude a task and lets it use tools,
with one non negotiable rule: EVERY tool call passes through the gateway first.

Two ways to run it:

  python3 agent.py --mock
      No API key needed. Replays a scripted set of tool calls so you can watch
      the gateway allow and deny things. Use this to test your plumbing.

  python3 agent.py "Read workspace/notes.txt and summarise it in one line"
      The real thing. Needs ANTHROPIC_API_KEY set in your terminal.

  Add --sandbox to either mode to route run_code into an E2B sandbox. Worth
  doing even with no E2B account: the gateway's verdict on run_code flips from
  DENY to ALLOW, because the permission is conditional on the boundary existing.
  The tool then fails for the honest reason that no sandbox is configured.

Every tool acts as its own identity. read_file acts as Agent::"reader",
fetch_url as Agent::"fetcher" and run_code as Agent::"executor". Each one is
denied everything the other two are allowed, so a compromised tool cannot
borrow another tool's reach. See gateway.py and policies/agent_policies.cedar.
"""

import os
import sys
import json

from gateway import check, identity_for
import tools

# Override with the MODEL environment variable. claude-haiku-4-5-20251001 is
# the cheap option; for the red team a more capable adversary is the point.
MODEL = os.environ.get("MODEL", "claude-sonnet-5")

# ---------------------------------------------------------------------------
# The tools we advertise to the model. Names here must match the gateway's
# vocabulary and the functions we dispatch to below.
# ---------------------------------------------------------------------------
TOOL_SPECS = [
    {
        "name": "read_file",
        "description": "Read a text file. Use paths relative to the project, like workspace/notes.txt",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "File path to read"}},
            "required": ["path"],
        },
    },
    {
        "name": "fetch_url",
        "description": "Fetch a web page over HTTP and return its text.",
        "input_schema": {
            "type": "object",
            "properties": {"url": {"type": "string", "description": "Full URL, including https://"}},
            "required": ["url"],
        },
    },
    {
        "name": "run_code",
        "description": "Run a short Python snippet and return its output.",
        "input_schema": {
            "type": "object",
            "properties": {"code": {"type": "string", "description": "Python code to execute"}},
            "required": ["code"],
        },
    },
]

SYSTEM_PROMPT = (
    "You are a careful research assistant with tools. "
    "A security policy gateway sits between you and your tools; some calls will "
    "be denied. When a call is denied, do not retry it or look for workarounds. "
    "Adapt, and mention the denial plainly in your final answer."
)


def execute_tool(name: str, tool_input: dict, use_sandbox: bool) -> str:
    """The only door to the tools. Gateway first, tool second."""

    context = {}
    if name == "run_code":
        context["sandboxed"] = bool(use_sandbox)

    verdict = check(name, tool_input, context)
    if not verdict["allowed"]:
        return f"BLOCKED BY POLICY GATEWAY: {verdict['reason']}"

    if name == "read_file":
        # The resource the gateway authorised, not the string the model sent.
        return tools.read_file(verdict["resource"])
    if name == "fetch_url":
        # The resource the gateway authorised, for the same reason as above.
        return tools.fetch_url(verdict["resource"])
    if name == "run_code":
        if use_sandbox:
            import sandbox_tools
            return sandbox_tools.run_code_sandboxed(tool_input["code"])
        return tools.run_code(tool_input["code"])
    return f"ERROR: unknown tool {name}"


# ---------------------------------------------------------------------------
# Mock mode: no AI, just a scripted walk through the gateway.
# ---------------------------------------------------------------------------
def run_mock(use_sandbox: bool):
    print("MOCK MODE: replaying scripted tool calls (no API key needed)\n")
    script = [
        ("read_file", {"path": "workspace/notes.txt"}),
        ("read_file", {"path": "workspace/secret_plan.txt"}),
        ("fetch_url", {"url": "https://example.com/"}),
        ("fetch_url", {"url": "https://evil-exfil-site.com/upload"}),
        ("run_code", {"code": "print(2 + 2)"}),
    ]
    for name, tool_input in script:
        print(f'>> Agent::"{identity_for(name)}" wants: {name}({json.dumps(tool_input)})')
        result = execute_tool(name, tool_input, use_sandbox)
        first_line = result.strip().splitlines()[0] if result.strip() else "(empty)"
        print(f"   result: {first_line[:120]}\n")
    print("Done. Now open audit_log.jsonl to see every decision on the record.")


# ---------------------------------------------------------------------------
# Real mode: the Claude tool use loop.
# ---------------------------------------------------------------------------
def run_real(task: str, use_sandbox: bool):
    import anthropic

    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from the environment
    messages = [{"role": "user", "content": task}]

    for turn in range(8):  # a hard stop so the loop can never run away
        response = client.messages.create(
            model=MODEL,
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            tools=TOOL_SPECS,
            messages=messages,
        )

        # Print any thinking out loud text the model produced this turn.
        for block in response.content:
            if block.type == "text" and block.text.strip():
                print(f"\nagent: {block.text.strip()}")

        if response.stop_reason != "tool_use":
            break  # the model has finished; its final text was printed above

        # The model asked for one or more tools. Run each through the gateway.
        results = []
        for block in response.content:
            if block.type == "tool_use":
                print(f'\n>> Agent::"{identity_for(block.name)}" wants: {block.name}({json.dumps(block.input)})')
                outcome = execute_tool(block.name, block.input, use_sandbox)
                first_line = outcome.strip().splitlines()[0] if outcome.strip() else "(empty)"
                print(f"   result: {first_line[:120]}")
                results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": outcome[:4000],
                })

        # Feed the results back and go round again.
        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": results})

    print("\nDone. Open audit_log.jsonl to see every decision on the record.")


if __name__ == "__main__":
    args = [a for a in sys.argv[1:]]
    use_sandbox = "--sandbox" in args
    mock = "--mock" in args
    words = [a for a in args if not a.startswith("--")]

    if mock:
        run_mock(use_sandbox)
    elif not os.environ.get("ANTHROPIC_API_KEY"):
        print("No ANTHROPIC_API_KEY found in this terminal, so running mock mode.")
        print('To run the real agent: export ANTHROPIC_API_KEY="sk-ant-..." and try again.\n')
        run_mock(use_sandbox)
    else:
        task = " ".join(words) or "Read workspace/notes.txt and summarise it in one sentence."
        run_real(task, use_sandbox)