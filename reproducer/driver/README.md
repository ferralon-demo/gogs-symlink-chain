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

Authored from the documented Gogs API surface; **not live-executed this pass**.
The install handshake, contents-API path, and default branch name (`master` vs
`main` across the 0.13.x line) may need a tweak against a live server — see the
repo `NOTES.md`.

## Usage

```
python3 poe_driver.py --base http://localhost:3000
```
