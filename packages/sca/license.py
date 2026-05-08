"""License-policy engine — emits :class:`LicenseFinding` rows when a
dependency's declared license matches operator-defined rules.

Two-stage flow:

  * :func:`enrich_licenses` — populate ``Dependency.declared_license``
    for ecosystems where it isn't supplied by the manifest itself.
    PyPI / npm parsers don't have license info (manifests pin
    versions, not licenses); registry metadata does. We only fetch
    when the dep's license is currently None and the operator
    cares (policy is non-empty).
  * :func:`evaluate` — walk the deps, classify each license against
    the policy, emit :class:`LicenseFinding` rows.

## Policy file format

YAML at ``<target>/.raptor-sca-license-policy.yml``::

    # Licenses operators explicitly allow — no finding.
    allow:
      - MIT
      - Apache-2.0
      - BSD-2-Clause
      - BSD-3-Clause
      - ISC

    # Licenses operators explicitly disallow — high severity.
    deny:
      - AGPL-3.0
      - AGPL-3.0-only
      - AGPL-3.0-or-later
      - SSPL-1.0
      - Commons-Clause

    # Licenses to flag as warning — medium severity.
    warn:
      - GPL-3.0
      - GPL-3.0-only
      - GPL-3.0-or-later

    # When a dep's license isn't in any list, this kind:
    #   "warn"  -> emit a warning finding
    #   "allow" -> permissive default (no finding)
    #   "deny"  -> strict default (every unmatched license is denied)
    default: allow

    # When a dep has no license at all (registry didn't provide):
    #   "warn"  -> info-severity finding ("license unknown")
    #   "deny"  -> high-severity finding (refused; explicit declaration required)
    #   "allow" -> no finding
    on_unknown: warn

The default policy (when no file exists) is permissive: allow is
empty, deny is AGPL-family + SSPL + Commons-Clause, warn is the
GPL-3 family, default=allow, on_unknown=warn. Operators committed
to compliance ship a tighter policy.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .models import (
    Confidence,
    Dependency,
    LicenseFinding,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LicensePolicy:
    """Operator-defined license rules. Use :func:`load_policy` to read
    from disk; :data:`DEFAULT_POLICY` is the no-config baseline."""

    allow: Set[str] = field(default_factory=set)
    deny: Set[str] = field(default_factory=set)
    warn: Set[str] = field(default_factory=set)
    default: str = "allow"          # "allow" | "warn" | "deny"
    on_unknown: str = "warn"        # "allow" | "warn" | "deny"


# Sensible default — out-of-the-box behaviour without a policy file.
# Reflects "most operators are fine with permissive licences but want
# AGPL / SSPL / Commons-Clause flagged as a compliance risk".
DEFAULT_POLICY = LicensePolicy(
    allow=set(),
    deny={
        "AGPL-3.0",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "SSPL-1.0",
        "Commons-Clause",
        "BUSL-1.1",                 # Business Source License — non-OSS
    },
    warn={
        "GPL-2.0",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "LGPL-3.0",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
    },
    default="allow",
    on_unknown="warn",
)


def load_policy(target: Path) -> LicensePolicy:
    """Load policy from ``<target>/.raptor-sca-license-policy.yml`` or
    return :data:`DEFAULT_POLICY`.

    Tolerates: missing file, missing optional keys, malformed YAML
    (logs + falls back). A genuinely-broken policy file shouldn't
    abort the SCA run — operators get the default + a warning so
    they notice and fix the file.
    """
    path = target / ".raptor-sca-license-policy.yml"
    if not path.is_file():
        return DEFAULT_POLICY
    try:
        import yaml
    except ImportError:
        logger.warning(
            "sca.license: PyYAML not installed — skipping operator "
            "policy file at %s, using default", path,
        )
        return DEFAULT_POLICY
    try:
        text = path.read_text(encoding="utf-8")
        data = yaml.safe_load(text) or {}
    except (OSError, yaml.YAMLError) as e:
        logger.warning(
            "sca.license: failed to read %s (%s) — using default",
            path, e,
        )
        return DEFAULT_POLICY
    if not isinstance(data, dict):
        logger.warning(
            "sca.license: %s is not a YAML mapping — using default",
            path,
        )
        return DEFAULT_POLICY
    return LicensePolicy(
        allow=_as_set(data.get("allow")),
        deny=_as_set(data.get("deny")),
        warn=_as_set(data.get("warn")),
        default=_as_action(data.get("default"), default="allow"),
        on_unknown=_as_action(data.get("on_unknown"), default="warn"),
    )


def _as_set(v: Any) -> Set[str]:
    if v is None:
        return set()
    if isinstance(v, list):
        return {str(x).strip() for x in v if str(x).strip()}
    if isinstance(v, str):
        return {v.strip()} if v.strip() else set()
    return set()


def _as_action(v: Any, *, default: str) -> str:
    if v in ("allow", "warn", "deny"):
        return v
    return default


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def evaluate(
    deps: List[Dependency],
    policy: LicensePolicy,
) -> List[LicenseFinding]:
    """Classify each dep's declared_license against the policy.

    Dedups by (ecosystem, name, version) — no point reporting the
    same dep twice when it appears in multiple manifests; the dep
    keys are stable across appearances.
    """
    seen: Set[str] = set()
    out: List[LicenseFinding] = []
    for d in deps:
        key = d.key()
        if key in seen:
            continue
        seen.add(key)
        finding = _evaluate_one(d, policy)
        if finding is not None:
            out.append(finding)
    return out


def _evaluate_one(
    dep: Dependency,
    policy: LicensePolicy,
) -> Optional[LicenseFinding]:
    spdx = dep.declared_license
    if spdx is None or not spdx.strip():
        return _unknown_finding(dep, policy)

    spdx = spdx.strip()
    # Multi-license SPDX expressions (``MIT OR Apache-2.0``,
    # ``GPL-3.0 AND BSD-3-Clause``) — best-effort split. For OR
    # the operator only needs ONE acceptable license; for AND
    # ALL must be acceptable.
    if " OR " in spdx:
        choices = [s.strip() for s in spdx.split(" OR ")]
        if any(c in policy.allow for c in choices):
            return None
        if all(c in policy.deny for c in choices):
            return _deny_finding(dep, spdx)
        # Mixed / no acceptable choice — emit incompatible.
        return LicenseFinding(
            finding_id=_finding_id(dep, "license_incompatible"),
            kind="license_incompatible",
            dependency=dep,
            spdx=spdx,
            detail=(
                f"Multi-license OR expression {spdx!r} has no choice "
                f"in policy.allow; operator must pick one or add to allow"
            ),
            severity="medium",
            confidence=Confidence(
                "medium",
                reason="OR expression with no allowlisted choice",
            ),
        )
    if " AND " in spdx:
        choices = [s.strip() for s in spdx.split(" AND ")]
        for c in choices:
            f = _classify(dep, c, policy)
            if f is not None:
                # First denied / warned terminates — operator sees the
                # most-significant violation.
                return f
        return None

    return _classify(dep, spdx, policy)


def _classify(
    dep: Dependency,
    spdx: str,
    policy: LicensePolicy,
) -> Optional[LicenseFinding]:
    if spdx in policy.deny:
        return _deny_finding(dep, spdx)
    if spdx in policy.warn:
        return _warn_finding(dep, spdx)
    if spdx in policy.allow:
        return None
    # Unmatched — apply default.
    if policy.default == "deny":
        return _deny_finding(dep, spdx, why="not in policy.allow")
    if policy.default == "warn":
        return _warn_finding(dep, spdx, why="not in policy.allow")
    return None


def _deny_finding(
    dep: Dependency,
    spdx: str,
    *,
    why: str = "in policy.deny",
) -> LicenseFinding:
    return LicenseFinding(
        finding_id=_finding_id(dep, "license_denied"),
        kind="license_denied",
        dependency=dep,
        spdx=spdx,
        detail=f"License {spdx!r} {why}",
        severity="high",
        confidence=Confidence("high", reason=why),
    )


def _warn_finding(
    dep: Dependency,
    spdx: str,
    *,
    why: str = "in policy.warn",
) -> LicenseFinding:
    return LicenseFinding(
        finding_id=_finding_id(dep, "license_warned"),
        kind="license_warned",
        dependency=dep,
        spdx=spdx,
        detail=f"License {spdx!r} {why}",
        severity="medium",
        confidence=Confidence("high", reason=why),
    )


def _unknown_finding(
    dep: Dependency,
    policy: LicensePolicy,
) -> Optional[LicenseFinding]:
    if policy.on_unknown == "allow":
        return None
    severity = "high" if policy.on_unknown == "deny" else "info"
    return LicenseFinding(
        finding_id=_finding_id(dep, "license_unknown"),
        kind="license_unknown",
        dependency=dep,
        spdx=None,
        detail=(
            f"No license metadata for {dep.ecosystem}:{dep.name}"
            f"@{dep.version or '*'} — registry returned no SPDX field"
        ),
        severity=severity,
        confidence=Confidence(
            "medium",
            reason="declared_license is None after enrichment",
        ),
    )


def _finding_id(dep: Dependency, kind: str) -> str:
    return (
        f"sca:{kind}:{dep.ecosystem}:{dep.name}@{dep.version or '*'}"
        f":{dep.declared_in}"
    )


# ---------------------------------------------------------------------------
# Enrichment — fetch license metadata from registries when manifests
# don't carry it.
# ---------------------------------------------------------------------------


def enrich_licenses(
    deps: List[Dependency],
    *,
    http: Optional[Any] = None,
    cache: Optional[Any] = None,
    enabled: bool = True,
) -> int:
    """Populate ``Dependency.declared_license`` for deps where it's
    None by querying registry metadata. Returns the number of deps
    enriched.

    Currently covers PyPI and npm (the two largest ecosystems with
    registry-side license metadata). Other ecosystems will fall
    through to ``on_unknown`` policy handling.

    When ``http`` is None, returns 0 — license enrichment is
    network-dependent and tests that don't supply an http stub
    skip the network.
    """
    if not enabled or http is None:
        return 0
    try:
        from .registries.pypi import PyPIClient
        from .registries.npm import NpmClient
    except ImportError as e:
        logger.debug("sca.license: registry clients unavailable: %s", e)
        return 0

    pypi: Optional[PyPIClient] = None
    npm: Optional[NpmClient] = None
    enriched = 0
    for d in deps:
        if d.declared_license:
            continue
        try:
            if d.ecosystem == "PyPI":
                if pypi is None:
                    pypi = PyPIClient(http=http, cache=cache)
                meta = pypi.get_metadata(d.name)
                spdx = _spdx_from_pypi(meta)
                if spdx:
                    d.declared_license = spdx
                    enriched += 1
            elif d.ecosystem == "npm":
                if npm is None:
                    npm = NpmClient(http=http, cache=cache)
                meta = npm.get_metadata(d.name)
                spdx = _spdx_from_npm(meta, d.version)
                if spdx:
                    d.declared_license = spdx
                    enriched += 1
        except Exception as e:                          # noqa: BLE001
            logger.debug(
                "sca.license: enrichment failed for %s:%s (%s)",
                d.ecosystem, d.name, e,
            )
    return enriched


def _spdx_from_pypi(meta: Optional[dict]) -> Optional[str]:
    if not isinstance(meta, dict):
        return None
    info = meta.get("info") or {}
    # PEP 639 (Python 3.12+): info.license_expression is SPDX. Older
    # packages: info.license is a free-text license name.
    expr = info.get("license_expression")
    if isinstance(expr, str) and expr.strip():
        return expr.strip()
    license_text = info.get("license")
    if isinstance(license_text, str) and license_text.strip():
        # Only use when it looks like a single SPDX id (no spaces,
        # short). Free-text descriptions like "see LICENSE file" are
        # not useful to the policy engine.
        text = license_text.strip()
        if " " not in text and len(text) < 60:
            return text
    # Trove classifier fallback: "License :: OSI Approved :: MIT License"
    classifiers = info.get("classifiers") or []
    if isinstance(classifiers, list):
        for c in classifiers:
            if not isinstance(c, str):
                continue
            spdx = _spdx_from_trove(c)
            if spdx is not None:
                return spdx
    return None


def _spdx_from_trove(classifier: str) -> Optional[str]:
    """Map a single PyPI ``License ::`` Trove classifier to an SPDX id.

    Covers the common cases. Unknown classifiers return None — the
    policy engine treats those as "license unknown" via ``on_unknown``.
    """
    return _TROVE_TO_SPDX.get(classifier.strip())


_TROVE_TO_SPDX: Dict[str, str] = {
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)": "GPL-2.0",
    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)": "GPL-3.0",
    "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)":
        "GPL-3.0-or-later",
    "License :: OSI Approved :: GNU Affero General Public License v3":
        "AGPL-3.0",
    "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)":
        "AGPL-3.0-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)":
        "LGPL-2.0",
    "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)":
        "LGPL-2.0-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)":
        "LGPL-3.0",
    "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)":
        "LGPL-3.0-or-later",
    "License :: Public Domain": "Unlicense",
    "License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication": "CC0-1.0",
}


def _spdx_from_npm(
    meta: Optional[dict], version: Optional[str],
) -> Optional[str]:
    """Extract the SPDX license string from npm registry metadata.

    Schema: top-level ``license`` is the package-level default; per-
    version overrides live in ``versions[<v>].license``. Per-version
    wins. Format is sometimes a string (modern), sometimes an
    object ``{"type": "MIT", "url": "..."}`` (legacy), sometimes
    a list of objects (very legacy). Handle all three.
    """
    if not isinstance(meta, dict):
        return None
    if version and isinstance(meta.get("versions"), dict):
        v_meta = meta["versions"].get(version)
        if isinstance(v_meta, dict):
            spdx = _spdx_from_npm_block(v_meta.get("license"))
            if spdx:
                return spdx
            spdx = _spdx_from_npm_block(v_meta.get("licenses"))
            if spdx:
                return spdx
    spdx = _spdx_from_npm_block(meta.get("license"))
    if spdx:
        return spdx
    return _spdx_from_npm_block(meta.get("licenses"))


def _spdx_from_npm_block(block: Any) -> Optional[str]:
    if isinstance(block, str):
        return block.strip() or None
    if isinstance(block, dict):
        t = block.get("type")
        if isinstance(t, str) and t.strip():
            return t.strip()
    if isinstance(block, list):
        # Take the first ``type``-bearing entry.
        for item in block:
            if isinstance(item, dict):
                t = item.get("type")
                if isinstance(t, str) and t.strip():
                    return t.strip()
            elif isinstance(item, str) and item.strip():
                return item.strip()
    return None


__all__ = [
    "DEFAULT_POLICY",
    "LicensePolicy",
    "enrich_licenses",
    "evaluate",
    "load_policy",
]
