# bin/

The prebuilt OSS scanner binaries land here. They are committed (like
`ferralon-demo/nucleon`'s `bin/nucleon` + `bin/nucleon-plugin`), not built in CI:

| Binary | Role |
|---|---|
| `open-tegron` | the deterministic OSS scanner (Assess / reachability "candidate" tier) |
| `open-tegron-plugin` | the out-of-process Go language analyzer the scanner drives |

Both are **`linux/amd64`** (the workflow runner is `ubuntu-latest`) and are
cross-built and dropped in separately — no scanner source ships in this repo.
`prove.yml` `chmod +x`'s them before the run.

Only the OSS Assess tier runs here. The Prove tier (PoE/PoNE, sandbox detonation,
two-trace regression oracle) is **not** in these binaries — it runs platform-side
(Tegron, with-account). See the repo `README.md` for the OSS-tier vs. platform-Prove
honesty boundary.
