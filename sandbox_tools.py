"""sandbox_tools.py  (rung four)

Code execution, contained. Instead of running Python on YOUR laptop, we rent a
disposable computer in the cloud for a few seconds (an E2B sandbox), run the
agent's code there, bring back the printed output, and throw the computer away.

If the code deletes every file it can see, it deletes files on a machine that
stops existing moments later. That is what "bounded blast radius" means.

Needs: pip install e2b-code-interpreter
       an E2B account and API key: https://e2b.dev
       export E2B_API_KEY="e2b_..."
"""

import os


def run_code_sandboxed(code: str) -> str:
    if not os.environ.get("E2B_API_KEY"):
        return "ERROR: no E2B_API_KEY set. Sign up at e2b.dev, create a key, then: export E2B_API_KEY=\"e2b_...\""

    from e2b_code_interpreter import Sandbox

    try:
        with Sandbox.create() as sandbox:
            execution = sandbox.run_code(code, timeout=30)

            parts = []
            if execution.logs.stdout:
                parts.append("".join(execution.logs.stdout))
            if execution.logs.stderr:
                parts.append("STDERR: " + "".join(execution.logs.stderr))
            if execution.error:
                parts.append(f"ERROR in sandbox: {execution.error.name}: {execution.error.value}")
            return "\n".join(parts).strip() or "(ran with no output)"
    except Exception as e:
        return f"ERROR: sandbox failed: {e}"


if __name__ == "__main__":
    # A direct test of the sandbox, no agent and no gateway involved.
    print("1) Harmless code:")
    print(run_code_sandboxed("print('hello from inside the sandbox')"))
    print()
    print("2) Who and where is this machine?")
    print(run_code_sandboxed("import platform, getpass; print(platform.node(), getpass.getuser())"))
    print()
    print("3) Something you would NEVER run on your own laptop:")
    print(run_code_sandboxed(
        "import os\n"
        "os.system('rm -rf /home/user/* 2>/dev/null')\n"
        "print('files wiped. machine still fine, because it is disposable:', os.listdir('/home/user'))"
    ))
