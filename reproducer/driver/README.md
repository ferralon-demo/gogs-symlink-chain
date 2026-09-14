# reproducer/driver — effect-only PoE driver

`poe_driver.py` exercises the Gogs symlink arbitrary-file-write bug
(CVE-2024-55947 → its symlink-bypass successor CVE-2025-8110) and records a
single **observable side-effect**: a benign per-trial canary appearing at a
sentinel path **outside** the repository working tree.

## What it does

1. Waits for the Gogs server to come up, drives the first-run `/install`
   (SQLite, self-contained/offline), and mints an API token.
2. Creates a repo and, over plain git, commits a **symlink** (`link`) whose
   target is the out-of-repo sentinel directory (`/srv/sentinel`).
3. Calls the contents API to write a canary to `link/poe.txt`. On a vulnerable
   build the server follows the symlink and the write lands at
   `/srv/sentinel/poe.txt` — outside any repo tree.

## The observable

| | |
|---|---|
| Observable | filesystem write to an **out-of-repo** sentinel (RFC 0009 fs observability) |
| Fired (PoE) | the per-trial canary bytes appear at `--sentinel`; driver exits `0` |
| Dark (PoNE) | sentinel stays absent (v0.13.4 rejects the symlink); driver exits `3` |

The verdict is decided by the **effect**, not by the API status code. The
canary is a fresh random token each run, so an observer matches *this* trial's
write and never a stale artifact.

## Effect-only stance (RFC 0003 / RFC 0001 invariant 8)

This driver writes **only** a benign canary token to a sentinel file. It does
not write an executable payload, a git hook, an `authorized_keys` entry, or
anything that gains code execution. The published artifact carries the *effect*
(the out-of-repo write), never the weaponization recipe.

## Status

**Setup path: live-verified against v0.13.0 (K8, 2026-09-14).** The image builds
and boots, and the driver's install → token-mint → repo-create → clone → commit
symlink → push sequence all succeed end-to-end. Three setup bugs were fixed in
the process: `admin` is a *reserved* username in Gogs 0.13.x (default user is now
`poeadmin`); `auto_init` needs an explicit `readme` template name (`Default`);
and the server needs `GOGS_WORK_DIR=/home/git` (set in the Dockerfiles) or it
fails to boot writing logs under `/usr/local/bin`. The default branch is `master`
(confirmed), matching what the driver writes against.

**Write vector: NOT yet firing — the assumed vector does not exist in Gogs.**
The driver targets `POST /api/v1/repos/{u}/{r}/contents/{path}`, which **404s**:
Gogs 0.13.x has no file-*write* contents API (that is a Gitea feature). Verified
in source at `8c21874c`: the only file-write ingress is the **web** route
`POST /{u}/{r}/_new/*` / `_edit/*` → `editFilePost` → `UpdateRepoFile`
(`internal/route/repo/editor.go`, `internal/db/repo_editor.go`). `editor.go` also
carries symlink/tree pre-checks on the committed tree that the real CVE-2025-8110
bypass must evade, and each checkpoint (0.13.0/.1/.3/.4) has a *different* guard
posture. Rewiring the driver to the web route and reconstructing the per-version
out-of-repo write is tracked in the repo `NOTES.md` and the K8 plan — it is
real, effect-only exploit reconstruction, not a config tweak.

## Usage

```
python3 poe_driver.py --base http://localhost:3000
```
