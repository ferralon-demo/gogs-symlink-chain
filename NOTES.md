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

- ~~In-repo OSS candidate scan.~~ **Done locally.** The committed
  `bin/open-tegron` was run over the historic Gogs source at all four
  checkpoints; CVE-2024-55947 emits `reachable_candidate` / `attacker_tainted`
  at each, with the escalating guard sets captured per checkpoint. Artifacts
  (`report.json/html/sarif/openvex`) are committed under `artifacts/`. The
  analyzer gained **macaron route-handler ingress detection** + **advisory-
  declared "guard-on-path" mitigation evidence** to produce this.
- Build all four reproducer Dockerfiles (fix any toolchain/era drift).
- Run `poe_driver.py` against each running image; confirm the canary lands at
  `/srv/sentinel/poe.txt` on 0.13.0/0.13.1/0.13.3 and is **dark** on 0.13.4.
- Feed `cases/cve-2024-55947.yaml` + the reproducer images into the platform
  Prove tier; confirm the realized verdicts (the PoE → incomplete-patch → PoNE
  flip) equal the `expect` blocks — the static candidate tier holds all four at
  `reachable_candidate`, so the flip is the Prove tier's to settle.
