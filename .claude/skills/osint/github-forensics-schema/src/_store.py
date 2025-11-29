"""
Evidence Store - Persistent storage for evidence collections.

Provides save/load/query functionality for evidence objects.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterator, Sequence

from ._schema import (
    AnyEvidence,
    AnyEvent,
    AnyObservation,
    EvidenceSource,
)


class EvidenceStore:
    """
    A simple store for managing collections of evidence.

    Features:
    - Save evidence to JSON file
    - Load evidence from JSON file
    - Query by type, source, date range
    - Iterate over evidence

    Example:
        store = EvidenceStore()

        # Add evidence
        store.add(commit_observation)
        store.add(issue_event)

        # Save to file
        store.save("evidence.json")

        # Load from file
        store = EvidenceStore.load("evidence.json")

        # Query
        commits = store.filter(observation_type="commit")
        recent = store.filter(after=datetime(2025, 7, 1))
    """

    def __init__(self, evidence: Sequence[AnyEvidence] | None = None):
        """
        Initialize the store.

        Args:
            evidence: Optional initial list of evidence objects
        """
        self._evidence: list[AnyEvidence] = list(evidence) if evidence else []
        self._by_id: dict[str, AnyEvidence] = {e.evidence_id: e for e in self._evidence}

    def add(self, evidence: AnyEvidence) -> None:
        """Add evidence to the store."""
        if evidence.evidence_id in self._by_id:
            # Replace existing
            self._evidence = [e for e in self._evidence if e.evidence_id != evidence.evidence_id]
        self._evidence.append(evidence)
        self._by_id[evidence.evidence_id] = evidence

    def add_all(self, evidence_list: Sequence[AnyEvidence]) -> None:
        """Add multiple evidence objects to the store."""
        for evidence in evidence_list:
            self.add(evidence)

    def get(self, evidence_id: str) -> AnyEvidence | None:
        """Get evidence by ID."""
        return self._by_id.get(evidence_id)

    def remove(self, evidence_id: str) -> bool:
        """Remove evidence by ID. Returns True if removed."""
        if evidence_id in self._by_id:
            del self._by_id[evidence_id]
            self._evidence = [e for e in self._evidence if e.evidence_id != evidence_id]
            return True
        return False

    def clear(self) -> None:
        """Remove all evidence from the store."""
        self._evidence.clear()
        self._by_id.clear()

    def __len__(self) -> int:
        """Return number of evidence items."""
        return len(self._evidence)

    def __iter__(self) -> Iterator[AnyEvidence]:
        """Iterate over all evidence."""
        return iter(self._evidence)

    def __contains__(self, evidence_id: str) -> bool:
        """Check if evidence ID exists in store."""
        return evidence_id in self._by_id

    @property
    def events(self) -> list[AnyEvent]:
        """Get all events."""
        return [e for e in self._evidence if hasattr(e, "event_type")]

    @property
    def observations(self) -> list[AnyObservation]:
        """Get all observations."""
        return [e for e in self._evidence if hasattr(e, "observation_type")]

    def filter(
        self,
        *,
        event_type: str | None = None,
        observation_type: str | None = None,
        source: EvidenceSource | str | None = None,
        repo: str | None = None,
        after: datetime | None = None,
        before: datetime | None = None,
        is_verified: bool | None = None,
        predicate: Callable[[AnyEvidence], bool] | None = None,
    ) -> list[AnyEvidence]:
        """
        Filter evidence by various criteria.

        Args:
            event_type: Filter to specific event type (e.g., "push", "issue")
            observation_type: Filter to specific observation type (e.g., "commit", "ioc")
            source: Filter by verification source
            repo: Filter by repository (full name, e.g., "aws/aws-toolkit-vscode")
            after: Filter to evidence with timestamp after this datetime
            before: Filter to evidence with timestamp before this datetime
            is_verified: Filter by verification status
            predicate: Custom filter function

        Returns:
            List of matching evidence
        """
        results = []

        for evidence in self._evidence:
            # Event type filter
            if event_type is not None:
                if not hasattr(evidence, "event_type") or evidence.event_type != event_type:
                    continue

            # Observation type filter
            if observation_type is not None:
                if not hasattr(evidence, "observation_type") or evidence.observation_type != observation_type:
                    continue

            # Source filter
            if source is not None:
                source_val = source if isinstance(source, EvidenceSource) else EvidenceSource(source)
                if evidence.verification.source != source_val:
                    continue

            # Repository filter
            if repo is not None:
                repo_obj = getattr(evidence, "repository", None)
                if repo_obj is None or repo_obj.full_name != repo:
                    continue

            # Date range filters
            timestamp = self._get_timestamp(evidence)
            if timestamp:
                if after is not None and timestamp < after:
                    continue
                if before is not None and timestamp > before:
                    continue

            # Verification status filter
            if is_verified is not None:
                if getattr(evidence, "is_verified", True) != is_verified:
                    continue

            # Custom predicate
            if predicate is not None and not predicate(evidence):
                continue

            results.append(evidence)

        return results

    def _get_timestamp(self, evidence: AnyEvidence) -> datetime | None:
        """Get the primary timestamp for an evidence object."""
        if hasattr(evidence, "when"):
            return evidence.when
        if hasattr(evidence, "original_when") and evidence.original_when:
            return evidence.original_when
        if hasattr(evidence, "observed_when"):
            return evidence.observed_when
        return None

    def to_json(self, indent: int = 2) -> str:
        """Serialize store to JSON string."""
        data = [e.model_dump(mode="json") for e in self._evidence]
        return json.dumps(data, indent=indent, default=str)

    def save(self, path: str | Path) -> None:
        """Save store to JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json())

    @classmethod
    def from_json(cls, json_str: str) -> "EvidenceStore":
        """Create store from JSON string."""
        from . import load_evidence_from_json

        data = json.loads(json_str)
        evidence = [load_evidence_from_json(item) for item in data]
        return cls(evidence)

    @classmethod
    def load(cls, path: str | Path) -> "EvidenceStore":
        """Load store from JSON file."""
        path = Path(path)
        return cls.from_json(path.read_text())

    def merge(self, other: "EvidenceStore") -> None:
        """Merge another store into this one."""
        self.add_all(list(other))

    def summary(self) -> dict:
        """Get a summary of the store contents."""
        event_counts: dict[str, int] = {}
        obs_counts: dict[str, int] = {}
        source_counts: dict[str, int] = {}

        for evidence in self._evidence:
            # Count by type
            if hasattr(evidence, "event_type"):
                event_counts[evidence.event_type] = event_counts.get(evidence.event_type, 0) + 1
            if hasattr(evidence, "observation_type"):
                obs_counts[evidence.observation_type] = obs_counts.get(evidence.observation_type, 0) + 1

            # Count by source
            source = evidence.verification.source.value
            source_counts[source] = source_counts.get(source, 0) + 1

        return {
            "total": len(self._evidence),
            "events": event_counts,
            "observations": obs_counts,
            "by_source": source_counts,
        }

    def verify_all(self) -> tuple[bool, list[str]]:
        """
        Verify all evidence in the store against their original sources.

        Returns:
            Tuple of (all_valid, aggregated_errors)
        """
        from ._verification import verify_all as _verify_all
        return _verify_all(self._evidence)
