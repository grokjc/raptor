# `packages/sca` — Software Composition Analysis

Mechanical dependency-vulnerability scanner. Walks a project's manifests,
resolves dependencies (including transitives via cascade), queries OSV /
KEV / EPSS for known vulnerabilities, runs supply-chain heuristics
(typosquat, install hooks, low-bus-factor), and emits findings as
markdown / SARIF / CycloneDX SBOM / SPDX SBOM.

The user-facing CLI is `bin/raptor-sca`. This README covers the
behaviour: what it scans, what it produces, and what flags adjust.

---

## Common workflows

```sh
# Scan a project, emit findings.json + report.md + SBOM under ./out/
raptor-sca /path/to/project

# Scan with a CI gate (exit 1 if any high-severity or KEV-listed CVE)
raptor-sca /path/to/project --fail-on-severity high --fail-on-kev

# Plan upgrades for vulnerable deps (read-only)
raptor-sca fix /path/to/project

# Apply the upgrade plan in-place
raptor-sca fix /path/to/project --apply --allow-major

# Pre-install safety verdict for a specific package
raptor-sca check PyPI django 4.2.10

# Compare two findings.json files (CI baseline vs current)
raptor-sca diff baseline.json current.json
```

---

## Scan stages

The mechanical pipeline runs eight stages in order, each cancellable
with a `--no-*` flag:

| Stage | Default | Disable with | What it does |
|---|---|---|---|
| Discovery | on | — | Walk the project tree finding manifests + lockfiles |
| Parsing | on | — | Parse each manifest to a deduplicated dep list |
| Inline-installs | on | `--no-inline-installs` | Extract pip/apt/yum/dnf/apk install commands from Dockerfiles + devcontainer + shell + GHA workflows |
| Image-source scanning | on | `--no-image-scanning` | Fetch base-image SBOMs from OCI registries (Dockerfile FROM, compose `image:`, k8s `spec.containers[*].image`, GitLab CI `image:`) |
| Transitive resolution | on | `--no-resolve-transitive` | Run native resolvers (`pip-compile`, `npm install --dry-run`, `cargo metadata`, etc.) for manifests without lockfiles |
| OSV + KEV + EPSS | on | `--no-kev` / `--no-epss` | Query OSV.dev for advisories, CISA KEV for in-the-wild exploitation, FIRST.org for EPSS scores |
| Reachability | on | `--no-reachability` | Module-level + function-level: is the vulnerable code path imported / called? |
| Supply-chain heuristics | on | `--no-supply-chain` | Typosquat similarity, install-hook content review, low-bus-factor detection, sentinel-package match |

LLM-driven stages are off by default unless explicitly enabled. The
umbrella switch is `--no-llm` (forces all off).

---

## Output files

A successful scan writes the following to `--out`:

| File | Format | Consumer |
|---|---|---|
| `findings.json` | JSON list of finding rows | Programmatic consumers (other RAPTOR tools, downstream CI). Canonical schema. |
| `report.md` | Markdown | Humans. Severity-sorted, KEV-flagged, dedup-grouped. |
| `report.html` | HTML | CI artefact uploads / compliance attachments. Enable with `--html`. |
| `sbom.cdx.json` | CycloneDX 1.5 + VEX | Dependency-Track, OWASP CycloneDX CLI, GitHub dependency review. |
| `sbom.spdx.json` | SPDX 2.3 | Operators that need SPDX over CycloneDX. Enable with `--spdx`. |
| `findings.sarif` | SARIF 2.1.0 | GitHub code-scanning, GitLab SAST, Sonar, etc. Suppressed findings emit a `suppressions` block. |
| `coverage-sca.json` | JSON | RAPTOR coverage layer (which files were examined). |

The `findings.json` schema is canonical — every other emitter
re-derives from it. External tools should consume that one.

---

## Finding categories

| Category | `vuln_type` prefix | Source |
|---|---|---|
| Vulnerable dependency | `sca:vulnerable_dependency` | OSV.dev (with KEV / EPSS / GH-PoC enrichment) |
| Hygiene | `sca:hygiene:<kind>` | RAPTOR-internal heuristics (lockfile drift, pin too loose, unpinned, missing lockfile, dep declared in wrong scope, etc.) |
| Supply-chain | `sca:supply_chain:<kind>` | RAPTOR-internal heuristics (typosquat, install-hook risky, sentinel package match, low-bus-factor, version_publish age, etc.) |
| License | `sca:license:<kind>` | License-policy violations (`license_restricted`, `license_mismatch`, etc.) |

Each finding row carries a `severity` (`info` / `low` / `medium` /
`high` / `critical`), a `description`, and a category-specific
`sca` block with the dep + advisory metadata.

---

## Ecosystems

OSV-queryable: PyPI, npm, Maven, Cargo (translated to `crates.io`
at the OSV boundary), Go, RubyGems, NuGet, Packagist.

C/C++ via vcpkg + ConanCenter; falls back to OSS-Fuzz when those
return no advisories. `.gitmodules` rows surface in the SBOM but
aren't OSV-queryable.

Inline-installs emit deps tagged `Debian` / `Red Hat` / `Alpine` /
`Homebrew` / `GitHub Actions` per the install-command surface
(only OSV-queryable for the subset OSV indexes; others appear in
the SBOM only).

### Risk-scoring coverage caveats

Findings are ranked by a calibrated risk score that combines
KEV / EPSS / Exploit-DB / Metasploit / OSV-EVIDENCE signals.
Coverage isn't uniform across ecosystems — three are
**cold-start** today (per 2026-05-09 validation snapshot):

- **Cargo** (Rust), **NuGet** (.NET), **Packagist** (PHP):
  zero or near-zero signaled findings even with five
  ground-truth signal sources combined. Findings still
  surface; risk-ranking quality is reduced because the
  underlying CVE-exploit-signal sources structurally
  under-cover these ecosystems. Adopters relying heavily on
  risk-ranked output for Rust/.NET/PHP projects should
  treat the top-N selection as a starting point, not a
  finished prioritisation.
- Go / Maven / PyPI / npm have validated_v1 calibration
  (Spearman ρ 0.50–0.56, top-20 precision 1.0 globally).

**C/C++ coverage** depends on OSV's `OSS-Fuzz` ecosystem
which indexes ~700 widely-used projects (curl / openssl /
libpng / sqlite / ffmpeg / …). Long-tail enterprise
libraries or less-popular projects may return no advisories
even when CVEs exist for them upstream. Direct GHSA-API
querying for C/C++ is on the post-release backlog — pull
forward when this gap bites.

**NVD CPE matching is not implemented** and is unlikely to
be — CPE's noise structurally outweighs its coverage gains
for the use cases SCA targets. If you need
deep-enterprise-CVE coverage that GHSA + OSS-Fuzz can't
satisfy, a different tool is the right answer.

---

## Fix mode

`raptor-sca fix <target>` reads a recent `findings.json` (or runs
the analyse pipeline first) and emits a `proposed/` directory of
manifest rewrites that bump every vulnerable dependency to the
smallest fix version above the installed one. Default is plan-only;
`--apply` writes in-place.

```sh
raptor-sca fix /path                  # Show the plan
raptor-sca fix /path --apply          # Apply rewrites
raptor-sca fix /path --apply --allow-major  # Allow major-version bumps
raptor-sca fix /path --fix=GHSA-xxx-yyy --apply  # Restrict to one advisory
raptor-sca fix /path --pin-only       # Skip wildcards / caret / range entries
raptor-sca fix /path --validate-against=their-pr-manifest.txt  # Check Dependabot's plan
```

Manifests the rewriter can't safely modify (Maven properties,
computed npm specifiers, etc.) get logged + skipped rather than
mangled.

---

## Caching

OSV / KEV / EPSS / OCI / registry-metadata responses are cached
under `~/.raptor/cache/sca/`. Default TTLs:

| Source | TTL | Why |
|---|---|---|
| OCI per-digest SBOM | forever | Digest is content-addressed |
| OCI tag → digest mapping | forever | Resolved digest is immutable |
| PyPI per-version `requires_dist` | forever | PyPI forbids re-publishing |
| OSV / KEV / EPSS | 24 h | New CVEs / exploitations land daily |
| Registry per-package version lists | 24 h | New versions publish |
| Failed manifest fetches (negative cache) | 1 h | Long enough to amortise across one CI sweep |

Disable with `--no-cache`. Force a refresh with
`raptor-sca clean-cache --max-age 0`.

---

## CI integration

```sh
raptor-sca <target> --fail-on-severity high --fail-on-kev
```

Exit codes: `0` = below threshold, `1` = above threshold (build
fail), `2` = invalid args, `3` = internal error.

For pre-commit / PR-comment workflows see `raptor-sca fix --format=pr-comment`.

---

## Sandbox + egress

When invoked under `core.sandbox.run`, all egress flows through
the in-process proxy with `SCA_ALLOWED_HOSTS` as the hostname
allowlist (registries + vuln feeds + archive CDNs). Resolver
subprocesses (`pip-compile`, `npm`, `cargo`, etc.) get per-tool
allowlists from `packages/sca/resolvers/_proxy_hosts.py` —
operators on private mirrors override via
`~/.config/raptor/sca-proxy-hosts.json`.

The egress proxy is deny-by-default — a tool reaching off-allowlist
fails with a clear error. Operators discover gaps and update the
override config.

---

## What raptor-sca does NOT do (by design)

- **No mass remediation across many projects** — `fix` is per-target.
- **No SaaS dependency.** Everything runs locally; no telemetry.
- **No pretend-confidence on transitives the resolver couldn't compute.**
  When a project lacks a lockfile and the resolver fails (network
  restricted, toolchain absent), transitives are listed with
  `confidence=low` and the operator decides.
- **No silent network calls in `--offline` mode.** OSV / KEV /
  EPSS / registry calls all skip; only cached data flows.
- **No mutation under `--apply` if the rewriter can't safely apply.**
  Skipped entries are logged with reasons.

---

## Where to look in the code

| Subsystem | File |
|---|---|
| CLI dispatch | `cli.py` |
| Pipeline orchestrator | `pipeline.py` |
| Discovery + parser dispatch | `discovery.py`, `parsers/` |
| OSV / KEV / EPSS clients | `osv.py`, `kev.py`, `epss.py` |
| Native resolver wrappers | `resolvers/` |
| Reachability tiers | `reachability/` |
| Hygiene / supply-chain / license heuristics | `hygiene.py`, `supply_chain/`, `license.py` |
| Image-source scanning | `dockerfile_from.py` |
| Risk scoring | `risk.py` |
| Output emitters | `findings.py`, `report.py`, `report_html.py`, `sarif.py`, `sbom.py`, `sbom_spdx.py` |
| Calibration substrate | `calibration/` |
| Fix-mode rewriters | `update.py`, `_rewrite_*` helpers in same |
