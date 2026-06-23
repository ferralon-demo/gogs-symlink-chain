# artifacts — OSS candidate-tier scan outputs

These are the real outputs of the committed OSS scanner (`bin/open-tegron`,
candidate tier) run over the historic Gogs source at each checkpoint commit.
One subdirectory per chain role; each contains:

- `report.json` — the native Tegron Report (SBOM + advisories + reachability
  evidence, including the `mitigating_guards` on the path to the sink).
- `report.html` — the human-readable rendering of the same Report.
- `report.sarif.json` — SARIF for code-scanning / CI ingestion.
- `openvex.json` — OpenVEX statements for the resolved advisories.

## Subdirectories

| Dir | Role | Version | Git ref |
|---|---|---|---|
| `vulnerable/` | Vulnerable | 0.13.0 | `v0.13.0` |
| `failed_fix/` | Failed fix | 0.13.1 | `v0.13.1` |
| `still_vuln/` | Still vulnerable | 0.13.3 | `v0.13.3` |
| `real_fix/` | Real fix | 0.13.4 | `v0.13.4` |

## One-line summary (CVE-2024-55947, alias CVE-2025-8110; KEV-listed, EPSS ~0.75)

All four checkpoints report the same candidate verdict — `reachable_candidate`,
reachability grade `attacker_tainted` — over an attacker-controllable
`http_route` ingress (`EditFilePost`) into the `UpdateRepoFile` sink in
`gogs.io/gogs/internal/db`. What changes is the set of mitigating guards on the
path:

| Dir | Mitigating guards on path |
|---|---|
| `vulnerable/` | `isRepositoryGitPath` |
| `failed_fix/` | `isRepositoryGitPath` |
| `still_vuln/` | `isRepositoryGitPath`, `IsSymlink` |
| `real_fix/` | `isRepositoryGitPath`, `hasSymlinkInPath` |

The static candidate tier deliberately holds all four at `reachable_candidate`:
guard *presence* is not guard *sufficiency* (v0.13.3's leaf-only `IsSymlink` is
bypassable; only v0.13.4's full-hierarchy `hasSymlinkInPath` closes the hole),
and that runtime distinction — the PoE → incomplete-patch → PoNE flip — is the
platform Prove tier's to settle. See the repo `README.md` for the full framing.
