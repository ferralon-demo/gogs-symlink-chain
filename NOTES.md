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
3. **Corpus pending.** The OSS advisory corpus does not yet carry CVE-2024-55947,
   so the candidate finding is not emitted *today*; the baseline still runs.
   Corpus facts are documented in the team brain (`gogs.io/gogs`, sink
   `UpdateRepoFile`). Proceeding per "assume the corpus feature lands shortly."
4. **Module identity `gogs.io/gogs`** (not `github.com/gogs/gogs`) — that is the
   module in v0.13.0's go.mod and what the analyzer matches. The git clone URL is
   still `github.com/gogs/gogs` (the repo host).

## Uncertainties (flag before the live pass)

- **Go base image per checkpoint.** All four Dockerfiles pin `golang:1.20`; the
  exact minor and build incantation (`-tags`, `-mod=vendor` vs modules, whether
  0.13.x ships a `vendor/` dir) may need a per-checkpoint tweak. Not live-built.
- **Default branch name.** The driver pushes/writes against `master`; confirm the
  0.13.x line uses `master` (likely) vs `main`.
- **Ingress symbol.** Driver uses the v1 contents API for a scriptable
  observable. It is not fully confirmed whether the demo should drive the web
  `_edit` route (`editFilePost`) instead; the shared file-write sink is
  `UpdateRepoFile` either way.
- **Install handshake.** The `/install` form fields are from the documented
  surface; field names/redirect behavior may need adjustment against a live
  server.

## What needs a live pass

- Build all four reproducer Dockerfiles (fix any toolchain/era drift).
- Run `poe_driver.py` against each running image; confirm the canary lands at
  `/srv/sentinel/poe.txt` on 0.13.0/0.13.1/0.13.3 and is **dark** on 0.13.4.
- Feed `cases/cve-2024-55947.yaml` + the reproducer images into the platform
  Prove tier; confirm realized verdicts equal the `expect` blocks.
- Once the OSS corpus carries CVE-2024-55947, rebuild `bin/` and confirm the
  reachable-candidate finding appears in the in-repo baseline.
