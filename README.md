# gogs-symlink-chain

A Tegron demo that proves an **incomplete-patch chain** on Gogs: a CVSS/SBOM
view marks the bug "fixed" at v0.13.1, but the exploit still fires — and only
goes dark at v0.13.4. Tegron proves the difference between *"the version number
says fixed"* and *"the exploit actually fires."*

## The chain

| Role | Version | Git ref | Commit | Expected verdict |
|---|---|---|---|---|
| Vulnerable | 0.13.0 | `v0.13.0` | `8c21874c00b6100d46b662f65baeb40647442f42` | `exploitable` (PoE, CVE-2024-55947) |
| **Failed fix** | 0.13.1 | `v0.13.1` | `0c40e600a275d490481cfeea53705810fbe94d9b` | **incomplete-patch** (symlink bypass = CVE-2025-8110) |
| Still vulnerable | 0.13.3 | `v0.13.3` | `5084b4a9b77a506f5e287e82e945e1c6882b827a` | `exploitable` (PoE) |
| Real fix | 0.13.4 | `v0.13.4` | `d958a47a0e9d8747e399c687fdb3ec64a3b1a736` | `not_exploitable` (PoNE) |

**CVE-2024-55947** is a path-validation bypass enabling arbitrary file write.
v0.13.1 added path validation — closing CVE-2024-55947 — but ignored
**symlinks**: a committed symlink plus a write through the contents API still
escapes the repo (**CVE-2025-8110**, exploited as a 0-day; CISA KEV). v0.13.3
still fires; **v0.13.4** (2026-01-23) finally closes it.

## What this proves

An SBOM/CVSS view sees v0.13.1 as past the first fixed version and calls it
done. Tegron points the *same* effect-only reproducer at each build:

- it fires on 0.13.0, 0.13.1, and 0.13.3 — a **runnable** out-of-repo file
  write, not an inference;
- it goes **dark** on 0.13.4, and the two-trace shows the indicator gone.

So 0.13.1/0.13.3 are reported **still exploitable** (incomplete-patch findings),
and the verdict flips to PoNE only at the version that actually closed it.

## How the proof is produced (two tiers)

| Tier | Where | What it does here |
|---|---|---|
| OSS Assess / reachability **candidate** | **in-repo CI** | `open-tegron baseline` (Go, no-account) runs over the historic Gogs source at each checkpoint and emits a candidate verdict — `reachable_candidate` / `not_exploitable` / `disqualified`, never `exploitable`. |
| **Prove** (PoE/PoNE) | **platform-side** (Tegron, with-account) | detonates the reproducer images, runs the two-trace regression oracle against the v0.13.0 predecessor, and realizes the proven chain above from `cases/cve-2024-55947.yaml`. |

The in-repo workflow (`.github/workflows/prove.yml`) runs the OSS candidate tier
and builds the reproducer images; it deliberately has **no `bin/tegron prove`
step** (that CLI does not exist in the OSS surface). The repo carries the Case
manifest + effect-only reproducers as the platform Prove tier's input.

> **Corpus note.** The `open-tegron` candidate finding for CVE-2024-55947 lights
> up once the OSS advisory corpus carries the entry for it (module
> `gogs.io/gogs`, the path-validation/file-write sink). That corpus addition is
> a tracked follow-up; until then the baseline runs and reports the current
> corpus against the Gogs SBOM.

## Effect-only reproducers (RFC 0003 / RFC 0001 invariant 8)

The reproducers carry the **effect** — a benign canary written to an out-of-repo
sentinel — never a weaponized RCE. No payloads, hooks, or code-execution
recipes ship here. See `reproducer/driver/README.md`.

## Layout

- `bin/` — the prebuilt OSS scanner (`open-tegron`) and its Go analyzer
  (`open-tegron-plugin`), `linux/amd64`. See `bin/README.md`.
- `cases/cve-2024-55947.yaml` — the Case: predecessor + ordered checkpoints +
  expected verdicts (the platform Prove tier's input).
- `reproducer/` — per-checkpoint Dockerfiles (clone + build the pinned historic
  commit; source is not vendored) and the effect-only driver.
- `.github/workflows/prove.yml` — the OSS candidate run + reproducer builds +
  the chain summary.
