# gogs-symlink-chain

A Tegron demo that proves an **incomplete-patch chain** on Gogs: a CVSS/SBOM
view marks the bug "fixed" at v0.13.1, but the exploit still fires — and only
goes dark at v0.13.4. Tegron proves the difference between *"the version number
says fixed"* and *"the exploit actually fires."*

## The chain

This chain carries no local stage-tags: its significant checkpoint hashes are the upstream Gogs
commits already listed in the table below, which is the pin.

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

### Candidate-tier results (run locally, all four checkpoints)

The OSS advisory corpus now carries CVE-2024-55947 (module `gogs.io/gogs`), and
the analyzer resolves the first-party file-write sink via macaron route-handler
ingress detection. The headline CVE therefore emits a real candidate finding at
**every** checkpoint. The committed `bin/open-tegron` was run over the historic
Gogs source at each commit; the per-checkpoint outputs (`report.json`,
`report.html`, `report.sarif.json`, `openvex.json`) live under `artifacts/`.

For CVE-2024-55947 (alias CVE-2025-8110; KEV-listed, EPSS ~0.75) all four
checkpoints report the **same** verdict — `reachable_candidate`, reachability
grade `attacker_tainted` — over an attacker-controllable `http_route` ingress
(`EditFilePost`) into the `UpdateRepoFile` sink in `gogs.io/gogs/internal/db`.
What escalates across versions is the set of **mitigating guards present on the
path**:

| Role | Version | Verdict | Reachability | Mitigating guards on path |
|---|---|---|---|---|
| Vulnerable | 0.13.0 | `reachable_candidate` | `attacker_tainted` | `isRepositoryGitPath` |
| **Failed fix** | 0.13.1 | `reachable_candidate` | `attacker_tainted` | `isRepositoryGitPath` |
| Still vulnerable | 0.13.3 | `reachable_candidate` | `attacker_tainted` | `isRepositoryGitPath`, `IsSymlink` |
| Real fix | 0.13.4 | `reachable_candidate` | `attacker_tainted` | `isRepositoryGitPath`, `hasSymlinkInPath` |

Two honest readings fall out of this table:

- **The "fix" never touched the symlink path.** v0.13.1 (failed fix) carries the
  *identical* guard set to v0.13.0 — the CVE-2024-55947 patch added `.git`-path
  validation but did nothing to the symlink hole on this sink.
- **Guard presence ≠ guard sufficiency.** v0.13.3 and v0.13.4 both show a
  symlink guard present, yet only v0.13.4 actually closes the hole: v0.13.3's
  `IsSymlink` is a leaf-only check, bypassable via an intermediate-directory
  symlink, while v0.13.4's `hasSymlinkInPath` walks the whole path hierarchy.

The candidate tier is **static**, so it deliberately keeps all four at
`reachable_candidate`. It cannot — and does not — claim the bug is fixed at
v0.13.4: `UpdateRepoFile` still exists and is still reachable from the
editor/contents-API ingress in every version, and whether a runtime
path-validation guard actually closes the hole is not an SBOM/CVSS/static-
reachability question. Adjudicating the **PoE → incomplete-patch → PoNE flip**
is the platform **Prove tier's** job (two-trace detonation). That boundary is
the whole point of the demo: static analysis can surface the guard escalation,
but only runtime proof can tell a real fix from a bypassable one.

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
