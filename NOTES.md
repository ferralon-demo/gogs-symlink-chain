# NOTES — build deviations, uncertainties, and what needs a live pass

Build context: this repo was authored to the resolved Tegron demo architecture
(OSS Assess in-repo, Prove platform-side). The original build agent died to an
Opus cybersecurity safety filter mid-driver; the driver, workflow, READMEs, and
binaries were completed inline by the orchestrator.

## Deviations from the spec (`docs/demo-poe-chain-projects.md`)

1. **`bin/tegron` → `bin/open-tegron`.** The spec modeled a `bin/tegron prove|assert`
   CLI. No such CLI exists: the OSS surface is `baseline | pr-inherit | cve-watch
   | state`. We ship the real OSS scanner (`open-tegron` + `open-tegron-plugin`,
   the default non-stealth brand) and run `baseline`.
2. **No in-repo Prove.** PoE/PoNE, sandbox detonation, and the two-trace oracle
   run platform-side (with-account). `prove.yml` has no prove/assert step; it
   runs the OSS candidate tier + builds reproducers + documents the platform
   handoff.
3. **Corpus — RESOLVED.** The OSS advisory corpus now carries CVE-2024-55947
   (module `gogs.io/gogs`, sink `UpdateRepoFile`), and the analyzer resolves
   the first-party sink via macaron route-handler ingress detection. The
   candidate finding now emits at all four checkpoints (`reachable_candidate`,
   `attacker_tainted`); see `artifacts/` and the result table in the README.
4. **Module identity `gogs.io/gogs`** (not `github.com/gogs/gogs`) — that is the
   module in v0.13.0's go.mod and what the analyzer matches. The git clone URL is
   still `github.com/gogs/gogs` (the repo host).

## Uncertainties (live-pass results — K8, 2026-09-14)

- **Go base image per checkpoint — RESOLVED.** `golang:1.20` is correct (go.mod
  declares `go 1.18`). But: (a) 0.13.x ships **no `vendor/` dir**, so
  `GOFLAGS=-mod=vendor` was wrong and is removed — the build uses modules;
  (b) the `bullseye` bases had aged out of the Debian mirrors (apt 404s), so both
  stages moved to `bookworm`. Build incantation `go build -tags "sqlite
  sqlite_unlock_notify"` with `CGO_ENABLED=1` works. v0.13.0 image live-built.
- **Boot fix — GOGS_WORK_DIR.** Gogs derives its work dir from the binary
  location (`/usr/local/bin`), which the unprivileged `git` user can't write, so
  it `[FATAL]`ed creating `/usr/local/bin/log`. All four Dockerfiles now set
  `ENV GOGS_WORK_DIR=/home/git`.
- **Default branch name — RESOLVED: `master`.** Confirmed on a live 0.13.0
  instance; matches what the driver pushes/writes.
- **Install handshake — RESOLVED (two bugs).** `admin` is a *reserved* username
  in 0.13.x (install rejects it) — driver default is now `poeadmin`. And
  `auto_init` needs an explicit `readme` template name or Gogs errors
  `read readme: is a directory` — driver now passes `readme: "Default"`.
- **Ingress symbol — the driver's assumed vector does NOT exist. STILL OPEN.**
  The v1 **contents-write** API the driver POSTs to returns **404**: Gogs 0.13.x
  has no file-write contents API (Gitea-only). Source-verified at `8c21874c`: the
  sole file-write ingress is the **web** route `_new`/`_edit` → `editFilePost`
  (`internal/route/repo/editor.go`) → `UpdateRepoFile`
  (`internal/db/repo_editor.go`). `editor.go` runs symlink/tree pre-checks on the
  committed tree; `UpdateRepoFile` guards only `.git` (`isRepositoryGitPath`) in
  v0.13.0 and does `os.WriteFile(path.Join(localCopy, NewTreeName))`. So the base
  CVE-2024-55947 write escapes via **`..` path traversal**, and the symlink
  bypass (CVE-2025-8110) must evade the evolving `editor.go` symlink guards —
  a *different* posture per checkpoint (see the README guard table). Rewiring the
  driver to the web route + reconstructing the per-version out-of-repo write is
  the remaining work (K8 plan): real, effect-only exploit reconstruction.

## What needs a live pass

- ~~In-repo OSS candidate scan.~~ **Done locally.** The committed
  `bin/open-tegron` was run over the historic Gogs source at all four
  checkpoints; CVE-2024-55947 emits `reachable_candidate` / `attacker_tainted`
  at each, with the escalating guard sets captured per checkpoint. Artifacts
  (`report.json/html/sarif/openvex`) are committed under `artifacts/`. The
  analyzer gained **macaron route-handler ingress detection** + **advisory-
  declared "guard-on-path" mitigation evidence** to produce this.
- ~~Build all four reproducer Dockerfiles.~~ **Done (K8).** All four live-built
  after the bookworm + modules + `GOGS_WORK_DIR` fixes above.
- ~~Driver setup path.~~ **Done (K8) against v0.13.0:** install → token → repo →
  clone → commit symlink → push all succeed. **Write vector still open** — see
  the Ingress-symbol bullet above; the canary does not yet land at
  `/srv/sentinel/poe.txt` because the assumed contents-API vector 404s.
- Rewire the driver to the web `_new`/`_edit` route and reconstruct the
  effect-only out-of-repo write per checkpoint; confirm the canary lands on
  0.13.0/0.13.1/0.13.3 and is **dark** on 0.13.4.
- Feed `cases/cve-2024-55947.yaml` + the reproducer images into the platform
  Prove tier; confirm the realized verdicts (the PoE → incomplete-patch → PoNE
  flip) equal the `expect` blocks — the static candidate tier holds all four at
  `reachable_candidate`, so the flip is the Prove tier's to settle.
