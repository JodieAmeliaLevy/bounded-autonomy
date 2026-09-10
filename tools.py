"""tools.py

The tools themselves. On purpose, there is no security logic anywhere in this
file. The tools don't decide what they're allowed to do, the gateway does
that. This file just does the work once it's been told yes.
"""

MAX_BYTES = 20_000


def read_file(path: str) -> str:
    try:
        with open(path, "r") as f:
            return f.read()
    except FileNotFoundError:
        return f"ERROR: no such file: {path}"
    except Exception as e:
        return f"ERROR: could not read {path}: {e}"


def fetch_url(url: str) -> str:
    import urllib.request

    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            body = response.read(MAX_BYTES)
            return body.decode("utf-8", errors="replace")
    except Exception as e:
        return f"ERROR: could not fetch {url}: {e}"


def run_code(code: str) -> str:
    # This is a stub. Until rung four (the sandbox), running code on the
    # local machine is not something this demo does at all.
    return "ERROR: run_code is not available outside a sandbox. See rung four."
