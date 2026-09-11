"""tools.py

The tools themselves. On purpose, there is no security logic anywhere in this
file. The tools don't decide what they're allowed to do, the gateway does
that. This file just does the work once it's been told yes.
"""

import urllib.error
import urllib.request

MAX_BYTES = 20_000


def read_file(path: str) -> str:
    try:
        with open(path, "r") as f:
            return f.read()
    except FileNotFoundError:
        return f"ERROR: no such file: {path}"
    except Exception as e:
        return f"ERROR: could not read {path}: {e}"


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Do not follow redirects.

    urlopen follows them by default, which quietly defeats a domain allowlist:
    the gateway authorises example.com, the server answers 302, and the tool
    fetches wherever it was pointed. The authorised resource and the fetched
    resource are allowed to differ again, which is the one thing this project
    is about. Refusing here means any hop beyond the first has to come back
    through the gateway as a new call.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_RefuseRedirects)


def fetch_url(url: str) -> str:
    try:
        with _OPENER.open(url, timeout=10) as response:
            body = response.read(MAX_BYTES)
            return body.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            target = e.headers.get("Location", "an unstated location")
            return (
                f"ERROR: refused to follow a redirect from {url} to {target}. "
                "The gateway authorised the first URL, not wherever it points."
            )
        return f"ERROR: could not fetch {url}: {e}"
    except Exception as e:
        return f"ERROR: could not fetch {url}: {e}"


def run_code(code: str) -> str:
    # This is a stub. Until rung four (the sandbox), running code on the
    # local machine is not something this demo does at all.
    return "ERROR: run_code is not available outside a sandbox. See rung four."
