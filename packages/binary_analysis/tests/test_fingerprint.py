"""Tests for ``packages.binary_analysis.fingerprint``.

The fingerprint primitive wraps ``analyse_binary_context`` to
produce a stable, comparable capability snapshot. Tests cover:

  * Bucket classification via the shared taxonomy
  * Stable JSON serialisation (sorted, no whitespace variance)
  * Round-trip dict ↔ dataclass
  * Content-hash computation
  * Graceful degradation: radare2 unavailable, analyser fail

The full radare2 wire-through is gated by ``probe_capability``
— tests use stubs so the suite doesn't require r2pipe.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

import pytest

from packages.binary_analysis.fingerprint import (
    BUCKETS,
    CapabilityFingerprint,
    FINGERPRINT_SCHEMA_VERSION,
    HIGH_SEVERITY_BUCKETS,
    bucket_imports,
    capability_fingerprint,
)
from packages.binary_analysis.radare2_understand import (
    BinaryContextMap, FunctionInfo,
)


# ---------------------------------------------------------------------------
# bucket_imports — bucket classification
# ---------------------------------------------------------------------------


class TestBucketImports:
    def test_exec_imports_classified(self):
        out = bucket_imports({"execve", "popen", "fread"})
        assert "exec" in out
        assert out["exec"] == {"execve", "popen"}

    def test_ubiquitous_imports_dropped(self):
        """``malloc`` / ``printf`` / ``read`` aren't in any
        high-CVE bucket — return empty."""
        assert bucket_imports({"malloc", "printf", "read"}) == {}

    def test_multiple_buckets(self):
        out = bucket_imports({"execve", "recv", "strcpy"})
        assert "exec" in out
        assert "network" in out
        assert "string_overflow" in out

    def test_empty_input_empty_output(self):
        assert bucket_imports(set()) == {}


class TestBucketTaxonomy:
    """The BUCKETS table is shared between fingerprint + SCA bump
    detector — these tests pin its shape so a tiny refactor in
    one consumer doesn't silently change the other."""

    def test_all_bucket_names_present(self):
        names = [b[0] for b in BUCKETS]
        assert names == [
            "exec", "network", "string_overflow", "scan",
            "memory_copy", "format_string", "alloc", "parser",
            "integer_parse", "toctou",
        ]

    def test_high_severity_buckets_subset_of_buckets(self):
        bucket_names = {b[0] for b in BUCKETS}
        assert HIGH_SEVERITY_BUCKETS <= bucket_names


# ---------------------------------------------------------------------------
# CapabilityFingerprint serialisation
# ---------------------------------------------------------------------------


class TestFingerprintSerialisation:
    def test_to_dict_stable_ordering(self):
        """Same fingerprint → same to_dict output regardless of
        insertion order of internal dicts / lists. Needed for
        content-hash-based dedup."""
        fp1 = CapabilityFingerprint(
            schema_version=1,
            binary_path="/x", binary_sha256="abc",
            arch="x86_64", bits=64, binary_format="elf",
            capability_buckets={"exec": ["execve", "popen"],
                                  "network": ["recv"]},
            dangerous_sinks=["b", "a"],
        )
        fp2 = CapabilityFingerprint(
            schema_version=1,
            binary_path="/x", binary_sha256="abc",
            arch="x86_64", bits=64, binary_format="elf",
            capability_buckets={"network": ["recv"],
                                  "exec": ["popen", "execve"]},
            dangerous_sinks=["a", "b"],
        )
        assert fp1.to_dict() == fp2.to_dict()
        assert fp1.canonical_json() == fp2.canonical_json()

    def test_canonical_json_no_whitespace_variance(self):
        fp = CapabilityFingerprint(
            schema_version=1,
            binary_path="/x", binary_sha256="abc",
            arch="x86_64", bits=64, binary_format="elf",
            capability_buckets={"exec": ["execve"]},
            dangerous_sinks=["sym.imp.execve"],
        )
        out = fp.canonical_json()
        # Compact: no whitespace around separators
        assert ": " not in out
        assert ", " not in out
        # Round-trips back to identical dict
        assert json.loads(out) == fp.to_dict()

    def test_from_dict_roundtrip(self):
        fp = CapabilityFingerprint(
            schema_version=1,
            binary_path="/x", binary_sha256="abc",
            arch="x86_64", bits=64, binary_format="elf",
            capability_buckets={"exec": ["execve"]},
            dangerous_sinks=["sym.imp.execve"],
        )
        restored = CapabilityFingerprint.from_dict(fp.to_dict())
        assert restored.to_dict() == fp.to_dict()

    def test_schema_version_in_dict(self):
        fp = CapabilityFingerprint(
            schema_version=FINGERPRINT_SCHEMA_VERSION,
            binary_path="/x", binary_sha256="abc",
            arch="x86_64", bits=64, binary_format="elf",
        )
        d = fp.to_dict()
        assert d["schema_version"] == FINGERPRINT_SCHEMA_VERSION


# ---------------------------------------------------------------------------
# capability_fingerprint — full path with stubbed analyser
# ---------------------------------------------------------------------------


@pytest.fixture
def patched_analyser(monkeypatch):
    """Replace ``analyse_binary_context`` + ``probe_capability``
    on the radare2 module so tests can drive the fingerprint
    primitive without r2pipe."""
    state = {"available": True, "ctx": None, "raise": None}

    def fake_probe():
        return {"available": state["available"], "reason": "stub"}

    def fake_analyse(path, **kwargs):
        if state["raise"] is not None:
            raise state["raise"]
        return state["ctx"]

    monkeypatch.setattr(
        "packages.binary_analysis.radare2_understand.probe_capability",
        fake_probe,
    )
    monkeypatch.setattr(
        "packages.binary_analysis.radare2_understand.analyse_binary_context",
        fake_analyse,
    )
    yield state


def _real_bytes_tempfile(tmp_path: Path, name: str, content: bytes) -> Path:
    """Write a file we can actually SHA-256 — fingerprint needs
    real bytes for the content hash."""
    out = tmp_path / name
    out.write_bytes(content)
    return out


class TestCapabilityFingerprint:
    def test_full_path_returns_fingerprint(
        self, patched_analyser, tmp_path,
    ):
        bin_path = _real_bytes_tempfile(
            tmp_path, "test.bin", b"\x7fELF\x00\x01" * 50,
        )
        patched_analyser["ctx"] = BinaryContextMap(
            binary_path=bin_path,
            arch="x86_64", bits=64, binary_format="elf",
            imports=["execve", "recv", "malloc", "printf"],
            dangerous_sinks=[
                FunctionInfo(name="sym.imp.execve", address=0x1000),
            ],
        )
        fp = capability_fingerprint(bin_path)
        assert fp is not None
        assert fp.schema_version == FINGERPRINT_SCHEMA_VERSION
        assert fp.arch == "x86_64"
        assert fp.bits == 64
        assert fp.binary_format == "elf"
        assert "exec" in fp.capability_buckets
        assert "network" in fp.capability_buckets
        assert "malloc" not in {
            fn for fns in fp.capability_buckets.values() for fn in fns
        }
        assert "sym.imp.execve" in fp.dangerous_sinks
        # Real bytes → real hash, 64 hex chars
        assert len(fp.binary_sha256) == 64
        assert all(c in "0123456789abcdef" for c in fp.binary_sha256)

    def test_same_bytes_same_hash(
        self, patched_analyser, tmp_path,
    ):
        """Two files with identical bytes produce identical
        ``binary_sha256``. Drift detection depends on this
        property — same image-content → same fingerprint."""
        ctx_a = BinaryContextMap(
            binary_path=Path("/a"),
            arch="x86_64", bits=64, binary_format="elf",
            imports=["execve"],
        )
        ctx_b = BinaryContextMap(
            binary_path=Path("/b"),
            arch="x86_64", bits=64, binary_format="elf",
            imports=["execve"],
        )
        bin_a = _real_bytes_tempfile(
            tmp_path, "a.bin", b"identical bytes",
        )
        bin_b = _real_bytes_tempfile(
            tmp_path, "b.bin", b"identical bytes",
        )
        patched_analyser["ctx"] = ctx_a
        fp_a = capability_fingerprint(bin_a)
        patched_analyser["ctx"] = ctx_b
        fp_b = capability_fingerprint(bin_b)
        assert fp_a.binary_sha256 == fp_b.binary_sha256

    def test_radare2_unavailable_returns_none(
        self, patched_analyser, tmp_path,
    ):
        patched_analyser["available"] = False
        bin_path = _real_bytes_tempfile(tmp_path, "x", b"bytes")
        assert capability_fingerprint(bin_path) is None

    def test_analyse_exception_returns_none(
        self, patched_analyser, tmp_path,
    ):
        patched_analyser["raise"] = RuntimeError("parse failed")
        bin_path = _real_bytes_tempfile(tmp_path, "x", b"bytes")
        assert capability_fingerprint(bin_path) is None

    def test_missing_file_returns_none(self, patched_analyser):
        """File doesn't exist → SHA-256 read fails → None."""
        patched_analyser["ctx"] = BinaryContextMap(
            binary_path=Path("/nope"), arch="x86_64", bits=64,
            binary_format="elf", imports=[],
        )
        assert capability_fingerprint(Path("/does/not/exist")) is None

    def test_empty_capabilities_still_emits_fingerprint(
        self, patched_analyser, tmp_path,
    ):
        """Binary with NO dangerous imports → fingerprint with
        empty ``capability_buckets``. That's a valid baseline —
        means 'this binary doesn't do anything dangerous we
        recognise' and is the safest snapshot."""
        bin_path = _real_bytes_tempfile(tmp_path, "x", b"safe")
        patched_analyser["ctx"] = BinaryContextMap(
            binary_path=bin_path,
            arch="x86_64", bits=64, binary_format="elf",
            imports=["malloc", "free", "printf"],   # all ubiquitous
        )
        fp = capability_fingerprint(bin_path)
        assert fp is not None
        assert fp.capability_buckets == {}
        assert fp.dangerous_sinks == []
