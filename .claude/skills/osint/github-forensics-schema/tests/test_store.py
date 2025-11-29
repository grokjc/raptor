#!/usr/bin/env python3
"""
Unit tests for EvidenceStore.

Tests save/load/query functionality for evidence collections.
"""

import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src import EvidenceStore, EvidenceSource, load_evidence_from_json


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def sample_push_event() -> dict:
    """Sample push event data."""
    return {
        "event_type": "push",
        "evidence_id": "push-test-001",
        "when": "2025-07-13T20:37:04Z",
        "who": {"login": "testuser", "id": 12345},
        "what": "Pushed 1 commit(s) to refs/heads/master",
        "repository": {
            "owner": "aws",
            "name": "aws-toolkit-vscode",
            "full_name": "aws/aws-toolkit-vscode",
        },
        "verification": {
            "source": "gharchive",
            "bigquery_table": "githubarchive.day.*",
        },
        "ref": "refs/heads/master",
        "before_sha": "d1959b996841883b3c14eadc5bc195fe8f65a63b",
        "after_sha": "678851bbe9776228f55e0460e66a6167ac2a1685",
        "size": 1,
        "commits": [],
        "is_force_push": False,
    }


@pytest.fixture
def sample_commit_observation() -> dict:
    """Sample commit observation data."""
    return {
        "observation_type": "commit",
        "evidence_id": "commit-test-001",
        "original_when": "2025-07-13T20:30:24Z",
        "original_who": {"login": "lkmanka58"},
        "original_what": "Malicious commit",
        "observed_when": "2025-11-28T21:00:00Z",
        "observed_by": "github",
        "observed_what": "Commit observed via GitHub API",
        "repository": {
            "owner": "aws",
            "name": "aws-toolkit-vscode",
            "full_name": "aws/aws-toolkit-vscode",
        },
        "verification": {
            "source": "github",
            "url": "https://github.com/aws/aws-toolkit-vscode/commit/678851b",
        },
        "sha": "678851bbe9776228f55e0460e66a6167ac2a1685",
        "message": "fix(amazonq): test commit",
        "author": {
            "name": "lkmanka58",
            "email": "lkmanka58@users.noreply.github.com",
            "date": "2025-07-13T20:30:24Z",
        },
        "committer": {
            "name": "lkmanka58",
            "email": "lkmanka58@users.noreply.github.com",
            "date": "2025-07-13T20:30:24Z",
        },
        "parents": [],
        "files": [],
    }


@pytest.fixture
def sample_ioc() -> dict:
    """Sample IOC data."""
    return {
        "observation_type": "ioc",
        "evidence_id": "ioc-test-001",
        "observed_when": "2025-07-24T12:00:00Z",
        "observed_by": "security_vendor",
        "observed_what": "IOC commit_sha identified",
        "verification": {
            "source": "security_vendor",
            "url": "https://example.com/report",
        },
        "ioc_type": "commit_sha",
        "value": "678851bbe9776228f55e0460e66a6167ac2a1685",
        "first_seen": "2025-07-13T20:30:24Z",
        "last_seen": "2025-07-18T23:21:03Z",
    }


# =============================================================================
# STORE BASIC OPERATIONS
# =============================================================================


class TestEvidenceStoreBasics:
    """Test basic store operations."""

    def test_create_empty_store(self):
        """Create an empty store."""
        store = EvidenceStore()
        assert len(store) == 0

    def test_add_and_get_evidence(self, sample_push_event):
        """Add evidence and retrieve by ID."""
        store = EvidenceStore()
        event = load_evidence_from_json(sample_push_event)

        store.add(event)

        assert len(store) == 1
        assert store.get("push-test-001") is not None
        assert store.get("push-test-001").evidence_id == "push-test-001"

    def test_add_replaces_existing(self, sample_push_event):
        """Adding evidence with same ID replaces existing."""
        store = EvidenceStore()
        event1 = load_evidence_from_json(sample_push_event)

        # Modify and add again
        sample_push_event["what"] = "Modified description"
        event2 = load_evidence_from_json(sample_push_event)

        store.add(event1)
        store.add(event2)

        assert len(store) == 1
        assert store.get("push-test-001").what == "Modified description"

    def test_remove_evidence(self, sample_push_event):
        """Remove evidence by ID."""
        store = EvidenceStore()
        event = load_evidence_from_json(sample_push_event)
        store.add(event)

        assert store.remove("push-test-001") is True
        assert len(store) == 0
        assert store.remove("push-test-001") is False

    def test_clear_store(self, sample_push_event, sample_commit_observation):
        """Clear all evidence from store."""
        store = EvidenceStore()
        store.add(load_evidence_from_json(sample_push_event))
        store.add(load_evidence_from_json(sample_commit_observation))

        assert len(store) == 2
        store.clear()
        assert len(store) == 0

    def test_contains_check(self, sample_push_event):
        """Check if evidence ID exists in store."""
        store = EvidenceStore()
        event = load_evidence_from_json(sample_push_event)
        store.add(event)

        assert "push-test-001" in store
        assert "nonexistent" not in store

    def test_iterate_over_store(self, sample_push_event, sample_commit_observation):
        """Iterate over all evidence in store."""
        store = EvidenceStore()
        store.add(load_evidence_from_json(sample_push_event))
        store.add(load_evidence_from_json(sample_commit_observation))

        evidence_ids = [e.evidence_id for e in store]
        assert len(evidence_ids) == 2
        assert "push-test-001" in evidence_ids
        assert "commit-test-001" in evidence_ids


# =============================================================================
# STORE FILTERING
# =============================================================================


class TestEvidenceStoreFiltering:
    """Test store filtering capabilities."""

    def test_filter_by_event_type(self, sample_push_event, sample_commit_observation):
        """Filter by event type."""
        store = EvidenceStore()
        store.add(load_evidence_from_json(sample_push_event))
        store.add(load_evidence_from_json(sample_commit_observation))

        push_events = store.filter(event_type="push")
        assert len(push_events) == 1
        assert push_events[0].evidence_id == "push-test-001"

    def test_filter_by_observation_type(self, sample_push_event, sample_commit_observation, sample_ioc):
        """Filter by observation type."""
        store = EvidenceStore()
        store.add(load_evidence_from_json(sample_push_event))
        store.add(load_evidence_from_json(sample_commit_observation))
        store.add(load_evidence_from_json(sample_ioc))

        commits = store.filter(observation_type="commit")
        assert len(commits) == 1
        assert commits[0].evidence_id == "commit-test-001"

        iocs = store.filter(observation_type="ioc")
        assert len(iocs) == 1

    def test_filter_by_source(self, sample_push_event, sample_commit_observation):
        """Filter by verification source."""
        store = EvidenceStore()
        store.add(load_evidence_from_json(sample_push_event))
        store.add(load_evidence_from_json(sample_commit_observation))

        github_evidence = store.filter(source=EvidenceSource.GITHUB)
        assert len(github_evidence) == 1

        gharchive_evidence = store.filter(source="gharchive")
        assert len(gharchive_evidence) == 1

    def test_filter_by_repository(self, sample_push_event, sample_commit_observation):
        """Filter by repository."""
        store = EvidenceStore()
        store.add(load_evidence_from_json(sample_push_event))
        store.add(load_evidence_from_json(sample_commit_observation))

        aws_evidence = store.filter(repo="aws/aws-toolkit-vscode")
        assert len(aws_evidence) == 2

        other_evidence = store.filter(repo="other/repo")
        assert len(other_evidence) == 0

    def test_filter_by_date_range(self, sample_push_event, sample_commit_observation):
        """Filter by date range."""
        store = EvidenceStore()
        store.add(load_evidence_from_json(sample_push_event))
        store.add(load_evidence_from_json(sample_commit_observation))

        # Filter after July 1st
        after_july = store.filter(after=datetime(2025, 7, 1, tzinfo=timezone.utc))
        assert len(after_july) == 2

        # Filter before July 14th
        before_july14 = store.filter(before=datetime(2025, 7, 14, tzinfo=timezone.utc))
        assert len(before_july14) == 2

        # Filter outside range
        future = store.filter(after=datetime(2026, 1, 1, tzinfo=timezone.utc))
        assert len(future) == 0

    def test_filter_with_predicate(self, sample_push_event, sample_commit_observation):
        """Filter with custom predicate."""
        store = EvidenceStore()
        store.add(load_evidence_from_json(sample_push_event))
        store.add(load_evidence_from_json(sample_commit_observation))

        # Custom predicate
        has_sha = store.filter(predicate=lambda e: hasattr(e, "sha"))
        assert len(has_sha) == 1

    def test_events_property(self, sample_push_event, sample_commit_observation):
        """Get all events via property."""
        store = EvidenceStore()
        store.add(load_evidence_from_json(sample_push_event))
        store.add(load_evidence_from_json(sample_commit_observation))

        events = store.events
        assert len(events) == 1
        assert events[0].evidence_id == "push-test-001"

    def test_observations_property(self, sample_push_event, sample_commit_observation, sample_ioc):
        """Get all observations via property."""
        store = EvidenceStore()
        store.add(load_evidence_from_json(sample_push_event))
        store.add(load_evidence_from_json(sample_commit_observation))
        store.add(load_evidence_from_json(sample_ioc))

        observations = store.observations
        assert len(observations) == 2


# =============================================================================
# STORE SERIALIZATION
# =============================================================================


class TestEvidenceStoreSerialization:
    """Test store save/load functionality."""

    def test_to_json(self, sample_push_event, sample_commit_observation):
        """Serialize store to JSON string."""
        store = EvidenceStore()
        store.add(load_evidence_from_json(sample_push_event))
        store.add(load_evidence_from_json(sample_commit_observation))

        json_str = store.to_json()
        data = json.loads(json_str)

        assert isinstance(data, list)
        assert len(data) == 2

    def test_from_json(self, sample_push_event, sample_commit_observation):
        """Create store from JSON string."""
        # Create and serialize
        store1 = EvidenceStore()
        store1.add(load_evidence_from_json(sample_push_event))
        store1.add(load_evidence_from_json(sample_commit_observation))
        json_str = store1.to_json()

        # Deserialize
        store2 = EvidenceStore.from_json(json_str)

        assert len(store2) == 2
        assert store2.get("push-test-001") is not None
        assert store2.get("commit-test-001") is not None

    def test_save_and_load(self, sample_push_event, sample_commit_observation):
        """Save to file and load back."""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "evidence.json"

            # Save
            store1 = EvidenceStore()
            store1.add(load_evidence_from_json(sample_push_event))
            store1.add(load_evidence_from_json(sample_commit_observation))
            store1.save(filepath)

            # Load
            store2 = EvidenceStore.load(filepath)

            assert len(store2) == 2
            assert store2.get("push-test-001") is not None

    def test_save_creates_directories(self, sample_push_event):
        """Save creates parent directories if needed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "nested" / "path" / "evidence.json"

            store = EvidenceStore()
            store.add(load_evidence_from_json(sample_push_event))
            store.save(filepath)

            assert filepath.exists()


# =============================================================================
# STORE MERGE AND SUMMARY
# =============================================================================


class TestEvidenceStoreMerge:
    """Test store merge and summary."""

    def test_merge_stores(self, sample_push_event, sample_commit_observation, sample_ioc):
        """Merge two stores."""
        store1 = EvidenceStore()
        store1.add(load_evidence_from_json(sample_push_event))

        store2 = EvidenceStore()
        store2.add(load_evidence_from_json(sample_commit_observation))
        store2.add(load_evidence_from_json(sample_ioc))

        store1.merge(store2)

        assert len(store1) == 3
        assert "push-test-001" in store1
        assert "commit-test-001" in store1
        assert "ioc-test-001" in store1

    def test_summary(self, sample_push_event, sample_commit_observation, sample_ioc):
        """Get store summary."""
        store = EvidenceStore()
        store.add(load_evidence_from_json(sample_push_event))
        store.add(load_evidence_from_json(sample_commit_observation))
        store.add(load_evidence_from_json(sample_ioc))

        summary = store.summary()

        assert summary["total"] == 3
        assert summary["events"]["push"] == 1
        assert summary["observations"]["commit"] == 1
        assert summary["observations"]["ioc"] == 1
        assert "gharchive" in summary["by_source"]
        assert "github" in summary["by_source"]
        assert "security_vendor" in summary["by_source"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
