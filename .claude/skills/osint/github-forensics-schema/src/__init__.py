"""
GitHub Forensics Evidence Schema

Evidence objects are created ONLY through the EvidenceFactory which fetches
and verifies data from trusted third-party sources (GitHub API, GH Archive BigQuery,
Wayback Machine, security vendor URLs).

Usage:
    from src import EvidenceFactory

    factory = EvidenceFactory()

    # Verified from GitHub API
    commit = factory.commit("aws", "aws-toolkit-vscode", "678851b...")
    pr = factory.pull_request("aws", "aws-toolkit-vscode", 7710)

    # Verified from GH Archive BigQuery
    events = factory.events_from_gharchive(from_date="20250713", repo="aws/aws-toolkit-vscode")

    # Verified IOC (fetches source URL to confirm value exists)
    ioc = factory.ioc(IOCType.COMMIT_SHA, "678851b...", source_url="https://...")

For loading previously serialized evidence from JSON:
    from src import load_evidence_from_json
    evidence = load_evidence_from_json(json_data)

Type hints only (for static analysis):
    from src.types import CommitObservation, IssueObservation
"""

from ._creation import (
    # Factory - THE ONLY WAY to create verified evidence
    EvidenceFactory,
    # Query Models - For type hints in factory method signatures
    RepositoryQuery,
    CommitQuery,
    IssueQuery,
    FileQuery,
    BranchQuery,
    TagQuery,
    ReleaseQuery,
    ForkQuery,
    WikiQuery,
    WaybackQuery,
    GHArchiveQuery,
)

from ._store import EvidenceStore
from ._verification import verify_all

# Enums - Safe to expose, these are just constants
from ._schema import (
    EvidenceSource,
    EventType,
    RefType,
    PRAction,
    IssueAction,
    WorkflowConclusion,
    IOCType,
)


def load_evidence_from_json(data: dict) -> "AnyEvidence":
    """
    Load a previously serialized evidence object from JSON.

    Args:
        data: Dictionary from JSON deserialization (e.g., json.load())

    Returns:
        The appropriate Event or Observation instance

    Raises:
        ValueError: If the data cannot be parsed into a known evidence type
    """
    from ._schema import (
        # Events
        PushEvent,
        PullRequestEvent,
        IssueEvent,
        IssueCommentEvent,
        CreateEvent,
        DeleteEvent,
        ForkEvent,
        WorkflowRunEvent,
        ReleaseEvent,
        WatchEvent,
        MemberEvent,
        PublicEvent,
        # Observations
        CommitObservation,
        IssueObservation,
        FileObservation,
        WikiObservation,
        ForkObservation,
        BranchObservation,
        TagObservation,
        ReleaseObservation,
        SnapshotObservation,
        IOC,
        ArticleObservation,
    )

    # Determine type from discriminator fields
    if "event_type" in data:
        event_map = {
            "push": PushEvent,
            "pull_request": PullRequestEvent,
            "issue": IssueEvent,
            "issue_comment": IssueCommentEvent,
            "create": CreateEvent,
            "delete": DeleteEvent,
            "fork": ForkEvent,
            "workflow_run": WorkflowRunEvent,
            "release": ReleaseEvent,
            "watch": WatchEvent,
            "member": MemberEvent,
            "public": PublicEvent,
        }
        event_cls = event_map.get(data["event_type"])
        if event_cls:
            return event_cls.model_validate(data)
        raise ValueError(f"Unknown event_type: {data['event_type']}")

    if "observation_type" in data:
        obs_map = {
            "commit": CommitObservation,
            "issue": IssueObservation,
            "file": FileObservation,
            "wiki": WikiObservation,
            "fork": ForkObservation,
            "branch": BranchObservation,
            "tag": TagObservation,
            "release": ReleaseObservation,
            "snapshot": SnapshotObservation,
            "ioc": IOC,
            "article": ArticleObservation,
        }
        obs_cls = obs_map.get(data["observation_type"])
        if obs_cls:
            return obs_cls.model_validate(data)
        raise ValueError(f"Unknown observation_type: {data['observation_type']}")

    raise ValueError("Data must contain 'event_type' or 'observation_type' field")


# Type alias for return type
from ._schema import AnyEvidence, AnyEvent, AnyObservation

__all__ = [
    # Factory - Create evidence from sources
    "EvidenceFactory",
    # Store - Persist and query evidence collections
    "EvidenceStore",
    # Verification - Validate evidence against sources
    "verify_all",
    # Query Models (for type hints)
    "RepositoryQuery",
    "CommitQuery",
    "IssueQuery",
    "FileQuery",
    "BranchQuery",
    "TagQuery",
    "ReleaseQuery",
    "ForkQuery",
    "WikiQuery",
    "WaybackQuery",
    "GHArchiveQuery",
    # Enums
    "EvidenceSource",
    "EventType",
    "RefType",
    "PRAction",
    "IssueAction",
    "WorkflowConclusion",
    "IOCType",
    # Loading from JSON
    "load_evidence_from_json",
    # Type aliases
    "AnyEvidence",
    "AnyEvent",
    "AnyObservation",
]
