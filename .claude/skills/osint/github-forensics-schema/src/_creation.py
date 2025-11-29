"""
GitHub Forensics Evidence Creation Functions (OSINT)

Factory functions for creating verified evidence objects from public sources.
Consumer provides identifiers + source, we look up and verify independently.

All sources are public - no authentication required:
- GHArchive: BigQuery for Events (immutable, free 1TB/month)
- GitHub: REST API for Observations (60 req/hr unauthenticated)
- Wayback: CDX API for archived Observations (public)
- Git: Local git commands for Events
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Annotated, Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field, HttpUrl, field_validator, model_validator

from ._schema import (
    AnyEvent,
    AnyObservation,
    ArticleObservation,
    BranchObservation,
    CommitAuthor,
    CommitInPush,
    CommitObservation,
    CreateEvent,
    DeleteEvent,
    EvidenceSource,
    FileChange,
    FileObservation,
    ForkEvent,
    ForkObservation,
    GitHubActor,
    GitHubRepository,
    IOC,
    IOCType,
    IssueAction,
    IssueCommentEvent,
    IssueEvent,
    IssueObservation,
    MemberEvent,
    PRAction,
    PublicEvent,
    PullRequestEvent,
    PushEvent,
    RefType,
    ReleaseEvent,
    ReleaseObservation,
    SnapshotObservation,
    TagObservation,
    VerificationInfo,
    WatchEvent,
    WaybackSnapshot,
    WikiObservation,
    WorkflowConclusion,
    WorkflowRunEvent,
)


# =============================================================================
# QUERY MODELS - Input validation for lookups
# =============================================================================


class RepositoryQuery(BaseModel):
    """Repository identifier."""

    owner: str = Field(..., min_length=1, max_length=39)
    name: str = Field(..., min_length=1, max_length=100)

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"

    @field_validator("owner", "name")
    @classmethod
    def validate_github_name(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$", v):
            if len(v) == 1 and v.isalnum():
                return v
            raise ValueError(f"Invalid GitHub name format: {v}")
        return v


class CommitQuery(BaseModel):
    """Query for a commit observation."""

    repo: RepositoryQuery
    sha: Annotated[str, Field(min_length=7, max_length=40)]

    @field_validator("sha")
    @classmethod
    def validate_sha(cls, v: str) -> str:
        if not re.match(r"^[a-f0-9]+$", v.lower()):
            raise ValueError(f"Invalid commit SHA: {v}")
        return v.lower()


class IssueQuery(BaseModel):
    """Query for an issue/PR observation."""

    repo: RepositoryQuery
    number: int = Field(..., gt=0)
    is_pull_request: bool = False


class FileQuery(BaseModel):
    """Query for a file observation."""

    repo: RepositoryQuery
    path: str = Field(..., min_length=1)
    ref: str = "HEAD"


class BranchQuery(BaseModel):
    """Query for a branch observation."""

    repo: RepositoryQuery
    branch_name: str = Field(..., min_length=1)


class TagQuery(BaseModel):
    """Query for a tag observation."""

    repo: RepositoryQuery
    tag_name: str = Field(..., min_length=1)


class ReleaseQuery(BaseModel):
    """Query for a release observation."""

    repo: RepositoryQuery
    tag_name: str = Field(..., min_length=1)


class ForkQuery(BaseModel):
    """Query for fork relationships."""

    repo: RepositoryQuery


class WikiQuery(BaseModel):
    """Query for a wiki page observation."""

    repo: RepositoryQuery
    page_name: str = "Home"


class WaybackQuery(BaseModel):
    """Query for Wayback Machine snapshots."""

    url: HttpUrl
    from_date: str | None = None
    to_date: str | None = None

    @field_validator("from_date", "to_date")
    @classmethod
    def validate_date(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not re.match(r"^\d{4,14}$", v):
            raise ValueError("Date must be YYYY, YYYYMM, YYYYMMDD, or YYYYMMDDHHMMSS")
        return v


class GHArchiveQuery(BaseModel):
    """Query for GH Archive events."""

    repo: RepositoryQuery | None = None
    actor: str | None = None
    event_type: str | None = None
    from_date: str = Field(..., pattern=r"^\d{12}$")  # YYYYMMDDHHMM
    to_date: str | None = None

    @model_validator(mode="after")
    def validate_at_least_one_filter(self) -> "GHArchiveQuery":
        if not self.repo and not self.actor:
            raise ValueError("Must specify at least repo or actor")
        return self




# =============================================================================
# SOURCE CLIENTS - Protocols and implementations
# =============================================================================


@runtime_checkable
class SourceClient(Protocol):
    """Protocol for source clients."""

    @property
    def source(self) -> EvidenceSource: ...


class GitHubClient:
    """Client for GitHub REST API (unauthenticated OSINT).

    Rate limits: 60 requests/hour unauthenticated.
    All public repository data is accessible without authentication.
    """

    BASE_URL = "https://api.github.com"

    def __init__(self):
        self._session: Any = None

    @property
    def source(self) -> EvidenceSource:
        return EvidenceSource.GITHUB

    def _get_session(self) -> Any:
        if self._session is None:
            import requests

            self._session = requests.Session()
            self._session.headers.update({"Accept": "application/vnd.github+json"})
        return self._session

    def get_commit(self, owner: str, repo: str, sha: str) -> dict[str, Any]:
        """Fetch commit from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/commits/{sha}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_issue(self, owner: str, repo: str, number: int) -> dict[str, Any]:
        """Fetch issue from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/issues/{number}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_pull_request(self, owner: str, repo: str, number: int) -> dict[str, Any]:
        """Fetch PR from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/pulls/{number}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_file(self, owner: str, repo: str, path: str, ref: str = "HEAD") -> dict[str, Any]:
        """Fetch file content from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/contents/{path}"
        params = {"ref": ref}
        resp = session.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

    def get_branch(self, owner: str, repo: str, branch: str) -> dict[str, Any]:
        """Fetch branch from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/branches/{branch}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_tag(self, owner: str, repo: str, tag: str) -> dict[str, Any]:
        """Fetch tag from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/git/refs/tags/{tag}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_release(self, owner: str, repo: str, tag: str) -> dict[str, Any]:
        """Fetch release by tag from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/releases/tags/{tag}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_forks(self, owner: str, repo: str, per_page: int = 100) -> list[dict[str, Any]]:
        """Fetch forks from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/forks"
        params = {"per_page": per_page}
        resp = session.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

    def get_repo(self, owner: str, repo: str) -> dict[str, Any]:
        """Fetch repository info from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()


class WaybackClient:
    """Client for Wayback Machine CDX API."""

    CDX_URL = "https://web.archive.org/cdx/search/cdx"
    AVAILABILITY_URL = "https://archive.org/wayback/available"
    ARCHIVE_URL = "https://web.archive.org/web"

    def __init__(self):
        self._session: Any = None

    @property
    def source(self) -> EvidenceSource:
        return EvidenceSource.WAYBACK

    def _get_session(self) -> Any:
        if self._session is None:
            import requests

            self._session = requests.Session()
        return self._session

    def search_cdx(
        self,
        url: str,
        match_type: str = "exact",
        from_date: str | None = None,
        to_date: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, str]]:
        """Search CDX API for archived snapshots."""
        session = self._get_session()
        params: dict[str, Any] = {
            "url": url,
            "output": "json",
            "matchType": match_type,
            "filter": "statuscode:200",
            "limit": limit,
        }
        if from_date:
            params["from"] = from_date
        if to_date:
            params["to"] = to_date

        resp = session.get(self.CDX_URL, params=params)
        resp.raise_for_status()
        data = resp.json()

        if len(data) <= 1:
            return []

        headers = data[0]
        return [dict(zip(headers, row)) for row in data[1:]]

    def get_snapshot(self, url: str, timestamp: str) -> str | None:
        """Fetch archived page content."""
        session = self._get_session()
        archive_url = f"{self.ARCHIVE_URL}/{timestamp}/{url}"
        resp = session.get(archive_url)
        if resp.status_code == 200:
            return resp.text
        return None


class GHArchiveClient:
    """Client for GH Archive BigQuery queries."""

    def __init__(self, credentials_path: str | None = None, project_id: str | None = None):
        self.credentials_path = credentials_path
        self.project_id = project_id
        self._client: Any = None

    @property
    def source(self) -> EvidenceSource:
        return EvidenceSource.GHARCHIVE

    def _get_client(self) -> Any:
        if self._client is None:
            from google.cloud import bigquery
            from google.oauth2 import service_account

            if self.credentials_path:
                credentials = service_account.Credentials.from_service_account_file(
                    self.credentials_path, scopes=["https://www.googleapis.com/auth/bigquery"]
                )
                self._client = bigquery.Client(credentials=credentials, project=credentials.project_id)
            else:
                self._client = bigquery.Client(project=self.project_id)
        return self._client

    def query_events(
        self,
        repo: str | None = None,
        actor: str | None = None,
        event_type: str | None = None,
        from_date: str = "",
        to_date: str | None = None,
    ) -> list[dict[str, Any]]:
        """Query GH Archive for events."""
        client = self._get_client()

        # Build table reference - use daily table
        # from_date is YYYYMMDDHHMM format (12 digits), extract day part
        day = from_date[:8]
        table = f"`githubarchive.day.{day}`"

        # Build WHERE clauses
        clauses = []

        # Filter by hour and minute using created_at timestamp
        hour = int(from_date[8:10])
        minute = int(from_date[10:12])
        clauses.append(f"EXTRACT(HOUR FROM created_at) = {hour}")
        clauses.append(f"EXTRACT(MINUTE FROM created_at) = {minute}")

        if repo:
            clauses.append(f"repo.name = '{repo}'")
        if actor:
            clauses.append(f"actor.login = '{actor}'")
        if event_type:
            clauses.append(f"type = '{event_type}'")

        where = " AND ".join(clauses) if clauses else "1=1"

        query = f"""
        SELECT
            type,
            created_at,
            actor.login as actor_login,
            actor.id as actor_id,
            repo.name as repo_name,
            repo.id as repo_id,
            payload
        FROM {table}
        WHERE {where}
        ORDER BY created_at
        LIMIT 1000
        """

        results = client.query(query)
        return [dict(row) for row in results]


class GitClient:
    """Client for local git operations."""

    def __init__(self, repo_path: str = "."):
        self.repo_path = repo_path

    @property
    def source(self) -> EvidenceSource:
        return EvidenceSource.GIT

    def _run(self, *args: str) -> str:
        result = subprocess.run(
            ["git", "-C", self.repo_path, *args],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()

    def get_commit(self, sha: str) -> dict[str, Any]:
        """Get commit info from local git."""
        format_str = "%H%n%an%n%ae%n%aI%n%cn%n%ce%n%cI%n%P%n%B"
        output = self._run("show", "-s", f"--format={format_str}", sha)
        lines = output.split("\n")

        return {
            "sha": lines[0],
            "author_name": lines[1],
            "author_email": lines[2],
            "author_date": lines[3],
            "committer_name": lines[4],
            "committer_email": lines[5],
            "committer_date": lines[6],
            "parents": lines[7].split() if lines[7] else [],
            "message": "\n".join(lines[8:]),
        }

    def get_commit_files(self, sha: str) -> list[dict[str, Any]]:
        """Get files changed in a commit."""
        output = self._run("diff-tree", "--no-commit-id", "--name-status", "-r", sha)
        files = []
        for line in output.split("\n"):
            if line:
                parts = line.split("\t")
                status_map = {"A": "added", "M": "modified", "D": "removed", "R": "renamed"}
                files.append({"status": status_map.get(parts[0][0], "modified"), "filename": parts[-1]})
        return files

    def get_log(
        self,
        ref: str = "HEAD",
        since: str | None = None,
        until: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get commit log."""
        args = ["log", f"--max-count={limit}", "--format=%H|%an|%ae|%aI|%s", ref]
        if since:
            args.append(f"--since={since}")
        if until:
            args.append(f"--until={until}")

        output = self._run(*args)
        commits = []
        for line in output.split("\n"):
            if line:
                parts = line.split("|", 4)
                commits.append(
                    {
                        "sha": parts[0],
                        "author_name": parts[1],
                        "author_email": parts[2],
                        "author_date": parts[3],
                        "message": parts[4] if len(parts) > 4 else "",
                    }
                )
        return commits


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def _generate_evidence_id(prefix: str, *parts: str) -> str:
    """Generate a deterministic evidence ID."""
    content = ":".join(parts)
    hash_val = hashlib.sha256(content.encode()).hexdigest()[:12]
    return f"{prefix}-{hash_val}"


def _parse_datetime(dt_str: str | None) -> datetime | None:
    """Parse datetime from various formats."""
    if dt_str is None:
        return None
    if isinstance(dt_str, datetime):
        return dt_str

    formats = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S %Z",
        "%Y-%m-%d %H:%M:%S",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(dt_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise ValueError(f"Unable to parse datetime: {dt_str}")


def _make_github_repo(owner: str, name: str) -> GitHubRepository:
    """Create GitHubRepository from components."""
    return GitHubRepository(owner=owner, name=name, full_name=f"{owner}/{name}")


def _make_github_actor(login: str, actor_id: int | None = None) -> GitHubActor:
    """Create GitHubActor from components."""
    return GitHubActor(login=login, id=actor_id)


# =============================================================================
# EVENT CREATION FUNCTIONS - From GHArchive/Git
# =============================================================================


def create_push_event_from_gharchive(row: dict[str, Any]) -> PushEvent:
    """Create PushEvent from GH Archive row."""
    payload = json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
    owner, name = row["repo_name"].split("/", 1)

    commits = []
    for c in payload.get("commits", []):
        commits.append(
            CommitInPush(
                sha=c["sha"],
                message=c.get("message", ""),
                author_name=c.get("author", {}).get("name", ""),
                author_email=c.get("author", {}).get("email", ""),
            )
        )

    before_sha = payload.get("before", "0" * 40)
    after_sha = payload.get("head", payload.get("after", "0" * 40))
    size = int(payload.get("size", len(commits)))
    is_force_push = size == 0 and before_sha != "0" * 40

    return PushEvent(
        evidence_id=_generate_evidence_id("push", row["repo_name"], after_sha),
        when=_parse_datetime(row["created_at"]),
        who=_make_github_actor(row["actor_login"], row.get("actor_id")),
        what=f"Pushed {size} commit(s) to {payload.get('ref', 'unknown')}",
        repository=_make_github_repo(owner, name),
        verification=VerificationInfo(
            source=EvidenceSource.GHARCHIVE,
            bigquery_table=f"githubarchive.day.*",
            query=f"actor.login='{row['actor_login']}' AND repo.name='{row['repo_name']}'",
        ),
        ref=payload.get("ref", ""),
        before_sha=before_sha,
        after_sha=after_sha,
        size=size,
        commits=commits,
        is_force_push=is_force_push,
    )


def create_pull_request_event_from_gharchive(row: dict[str, Any]) -> PullRequestEvent:
    """Create PullRequestEvent from GH Archive row."""
    payload = json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
    owner, name = row["repo_name"].split("/", 1)
    pr = payload.get("pull_request", {})

    action_str = payload.get("action", "opened")
    action_map = {"opened": PRAction.OPENED, "closed": PRAction.CLOSED, "reopened": PRAction.REOPENED}
    action = action_map.get(action_str, PRAction.OPENED)
    if action_str == "closed" and pr.get("merged"):
        action = PRAction.MERGED

    return PullRequestEvent(
        evidence_id=_generate_evidence_id("pr", row["repo_name"], str(pr.get("number", 0)), action_str),
        when=_parse_datetime(row["created_at"]),
        who=_make_github_actor(row["actor_login"], row.get("actor_id")),
        what=f"PR #{pr.get('number')} {action_str}",
        repository=_make_github_repo(owner, name),
        verification=VerificationInfo(
            source=EvidenceSource.GHARCHIVE,
            bigquery_table="githubarchive.day.*",
        ),
        action=action,
        pr_number=pr.get("number", 0),
        pr_title=pr.get("title", ""),
        pr_body=pr.get("body"),
        head_sha=pr.get("head", {}).get("sha"),
        merged=pr.get("merged", False),
    )


def create_issue_event_from_gharchive(row: dict[str, Any]) -> IssueEvent:
    """Create IssueEvent from GH Archive row."""
    payload = json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
    owner, name = row["repo_name"].split("/", 1)
    issue = payload.get("issue", {})

    action_str = payload.get("action", "opened")
    action_map = {
        "opened": IssueAction.OPENED,
        "closed": IssueAction.CLOSED,
        "reopened": IssueAction.REOPENED,
        "deleted": IssueAction.DELETED,
    }
    action = action_map.get(action_str, IssueAction.OPENED)

    return IssueEvent(
        evidence_id=_generate_evidence_id("issue", row["repo_name"], str(issue.get("number", 0)), action_str),
        when=_parse_datetime(row["created_at"]),
        who=_make_github_actor(row["actor_login"], row.get("actor_id")),
        what=f"Issue #{issue.get('number')} {action_str}",
        repository=_make_github_repo(owner, name),
        verification=VerificationInfo(
            source=EvidenceSource.GHARCHIVE,
            bigquery_table="githubarchive.day.*",
        ),
        action=action,
        issue_number=issue.get("number", 0),
        issue_title=issue.get("title", ""),
        issue_body=issue.get("body"),
    )


def create_issue_comment_event_from_gharchive(row: dict[str, Any]) -> IssueCommentEvent:
    """Create IssueCommentEvent from GH Archive row."""
    payload = json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
    owner, name = row["repo_name"].split("/", 1)
    issue = payload.get("issue", {})
    comment = payload.get("comment", {})

    return IssueCommentEvent(
        evidence_id=_generate_evidence_id("comment", row["repo_name"], str(comment.get("id", 0))),
        when=_parse_datetime(row["created_at"]),
        who=_make_github_actor(row["actor_login"], row.get("actor_id")),
        what=f"Comment on issue #{issue.get('number')}",
        repository=_make_github_repo(owner, name),
        verification=VerificationInfo(
            source=EvidenceSource.GHARCHIVE,
            bigquery_table="githubarchive.day.*",
        ),
        action=payload.get("action", "created"),
        issue_number=issue.get("number", 0),
        comment_id=comment.get("id", 0),
        comment_body=comment.get("body", ""),
    )


def create_create_event_from_gharchive(row: dict[str, Any]) -> CreateEvent:
    """Create CreateEvent from GH Archive row."""
    payload = json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
    owner, name = row["repo_name"].split("/", 1)

    ref_type_str = payload.get("ref_type", "branch")
    ref_type_map = {"branch": RefType.BRANCH, "tag": RefType.TAG, "repository": RefType.REPOSITORY}
    ref_type = ref_type_map.get(ref_type_str, RefType.BRANCH)

    ref_name = payload.get("ref", "")

    return CreateEvent(
        evidence_id=_generate_evidence_id("create", row["repo_name"], ref_type_str, ref_name),
        when=_parse_datetime(row["created_at"]),
        who=_make_github_actor(row["actor_login"], row.get("actor_id")),
        what=f"Created {ref_type_str} '{ref_name}'",
        repository=_make_github_repo(owner, name),
        verification=VerificationInfo(
            source=EvidenceSource.GHARCHIVE,
            bigquery_table="githubarchive.day.*",
        ),
        ref_type=ref_type,
        ref_name=ref_name,
    )


def create_delete_event_from_gharchive(row: dict[str, Any]) -> DeleteEvent:
    """Create DeleteEvent from GH Archive row."""
    payload = json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
    owner, name = row["repo_name"].split("/", 1)

    ref_type_str = payload.get("ref_type", "branch")
    ref_type_map = {"branch": RefType.BRANCH, "tag": RefType.TAG}
    ref_type = ref_type_map.get(ref_type_str, RefType.BRANCH)

    ref_name = payload.get("ref", "")

    return DeleteEvent(
        evidence_id=_generate_evidence_id("delete", row["repo_name"], ref_type_str, ref_name),
        when=_parse_datetime(row["created_at"]),
        who=_make_github_actor(row["actor_login"], row.get("actor_id")),
        what=f"Deleted {ref_type_str} '{ref_name}'",
        repository=_make_github_repo(owner, name),
        verification=VerificationInfo(
            source=EvidenceSource.GHARCHIVE,
            bigquery_table="githubarchive.day.*",
        ),
        ref_type=ref_type,
        ref_name=ref_name,
    )


def create_fork_event_from_gharchive(row: dict[str, Any]) -> ForkEvent:
    """Create ForkEvent from GH Archive row."""
    payload = json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
    owner, name = row["repo_name"].split("/", 1)
    forkee = payload.get("forkee", {})

    return ForkEvent(
        evidence_id=_generate_evidence_id("fork", row["repo_name"], forkee.get("full_name", "")),
        when=_parse_datetime(row["created_at"]),
        who=_make_github_actor(row["actor_login"], row.get("actor_id")),
        what=f"Forked to {forkee.get('full_name', '')}",
        repository=_make_github_repo(owner, name),
        verification=VerificationInfo(
            source=EvidenceSource.GHARCHIVE,
            bigquery_table="githubarchive.day.*",
        ),
        fork_full_name=forkee.get("full_name", ""),
    )


def create_workflow_run_event_from_gharchive(row: dict[str, Any]) -> WorkflowRunEvent:
    """Create WorkflowRunEvent from GH Archive row."""
    payload = json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
    owner, name = row["repo_name"].split("/", 1)
    workflow_run = payload.get("workflow_run", {})

    conclusion_str = workflow_run.get("conclusion")
    conclusion_map = {
        "success": WorkflowConclusion.SUCCESS,
        "failure": WorkflowConclusion.FAILURE,
        "cancelled": WorkflowConclusion.CANCELLED,
    }
    conclusion = conclusion_map.get(conclusion_str) if conclusion_str else None

    return WorkflowRunEvent(
        evidence_id=_generate_evidence_id("workflow", row["repo_name"], str(workflow_run.get("id", 0))),
        when=_parse_datetime(row["created_at"]),
        who=_make_github_actor(row["actor_login"], row.get("actor_id")),
        what=f"Workflow '{workflow_run.get('name', '')}' {payload.get('action', '')}",
        repository=_make_github_repo(owner, name),
        verification=VerificationInfo(
            source=EvidenceSource.GHARCHIVE,
            bigquery_table="githubarchive.day.*",
        ),
        action=payload.get("action", "requested"),
        workflow_name=workflow_run.get("name", ""),
        head_sha=workflow_run.get("head_sha", ""),
        conclusion=conclusion,
    )


def create_release_event_from_gharchive(row: dict[str, Any]) -> ReleaseEvent:
    """Create ReleaseEvent from GH Archive row."""
    payload = json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
    owner, name = row["repo_name"].split("/", 1)
    release = payload.get("release", {})

    return ReleaseEvent(
        evidence_id=_generate_evidence_id("release", row["repo_name"], release.get("tag_name", "")),
        when=_parse_datetime(row["created_at"]),
        who=_make_github_actor(row["actor_login"], row.get("actor_id")),
        what=f"Release '{release.get('tag_name', '')}' {payload.get('action', '')}",
        repository=_make_github_repo(owner, name),
        verification=VerificationInfo(
            source=EvidenceSource.GHARCHIVE,
            bigquery_table="githubarchive.day.*",
        ),
        action=payload.get("action", "published"),
        tag_name=release.get("tag_name", ""),
        release_name=release.get("name"),
        release_body=release.get("body"),
    )


def create_watch_event_from_gharchive(row: dict[str, Any]) -> WatchEvent:
    """Create WatchEvent from GH Archive row."""
    owner, name = row["repo_name"].split("/", 1)

    return WatchEvent(
        evidence_id=_generate_evidence_id("watch", row["repo_name"], row["actor_login"]),
        when=_parse_datetime(row["created_at"]),
        who=_make_github_actor(row["actor_login"], row.get("actor_id")),
        what="Starred repository",
        repository=_make_github_repo(owner, name),
        verification=VerificationInfo(
            source=EvidenceSource.GHARCHIVE,
            bigquery_table="githubarchive.day.*",
        ),
    )


def create_member_event_from_gharchive(row: dict[str, Any]) -> MemberEvent:
    """Create MemberEvent from GH Archive row."""
    payload = json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
    owner, name = row["repo_name"].split("/", 1)
    member = payload.get("member", {})

    return MemberEvent(
        evidence_id=_generate_evidence_id("member", row["repo_name"], member.get("login", "")),
        when=_parse_datetime(row["created_at"]),
        who=_make_github_actor(row["actor_login"], row.get("actor_id")),
        what=f"Member {member.get('login', '')} {payload.get('action', '')}",
        repository=_make_github_repo(owner, name),
        verification=VerificationInfo(
            source=EvidenceSource.GHARCHIVE,
            bigquery_table="githubarchive.day.*",
        ),
        action=payload.get("action", "added"),
        member=_make_github_actor(member.get("login", ""), member.get("id")),
    )


def create_public_event_from_gharchive(row: dict[str, Any]) -> PublicEvent:
    """Create PublicEvent from GH Archive row."""
    owner, name = row["repo_name"].split("/", 1)

    return PublicEvent(
        evidence_id=_generate_evidence_id("public", row["repo_name"]),
        when=_parse_datetime(row["created_at"]),
        who=_make_github_actor(row["actor_login"], row.get("actor_id")),
        what="Made repository public",
        repository=_make_github_repo(owner, name),
        verification=VerificationInfo(
            source=EvidenceSource.GHARCHIVE,
            bigquery_table="githubarchive.day.*",
        ),
    )


# Dispatch table for GH Archive event creation
GHARCHIVE_EVENT_CREATORS: dict[str, Any] = {
    "PushEvent": create_push_event_from_gharchive,
    "PullRequestEvent": create_pull_request_event_from_gharchive,
    "IssuesEvent": create_issue_event_from_gharchive,
    "IssueCommentEvent": create_issue_comment_event_from_gharchive,
    "CreateEvent": create_create_event_from_gharchive,
    "DeleteEvent": create_delete_event_from_gharchive,
    "ForkEvent": create_fork_event_from_gharchive,
    "WorkflowRunEvent": create_workflow_run_event_from_gharchive,
    "ReleaseEvent": create_release_event_from_gharchive,
    "WatchEvent": create_watch_event_from_gharchive,
    "MemberEvent": create_member_event_from_gharchive,
    "PublicEvent": create_public_event_from_gharchive,
}


def create_event_from_gharchive(row: dict[str, Any]) -> AnyEvent:
    """Create appropriate Event from GH Archive row based on type."""
    event_type = row.get("type", "")
    creator = GHARCHIVE_EVENT_CREATORS.get(event_type)
    if not creator:
        raise ValueError(f"Unsupported event type: {event_type}")
    return creator(row)


# =============================================================================
# OBSERVATION CREATION FUNCTIONS - From GH Archive (deleted content recovery)
# =============================================================================


def create_issue_observation_from_gharchive(
    repo: str,
    issue_number: int,
    timestamp: str,
    client: GHArchiveClient,
) -> IssueObservation:
    """Query GH Archive and create IssueObservation.

    Args:
        repo: Full repo name (owner/repo)
        issue_number: Issue number
        timestamp: ISO timestamp when event occurred (e.g. "2025-07-13T20:30:24Z")
        client: GH Archive BigQuery client

    Raises ValueError if issue not found at specified timestamp.
    """
    owner, name = repo.split("/", 1)
    date = timestamp[:10].replace("-", "")  # YYYYMMDD

    rows = client.query_events(
        repo=repo,
        event_type="IssuesEvent",
        from_date=date,
    )

    # Find matching issue at timestamp
    for row in rows:
        payload = json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
        issue = payload.get("issue", {})
        row_ts = str(row.get("created_at", ""))

        if issue.get("number") == issue_number and timestamp in row_ts:
            state = issue.get("state", "open")
            return IssueObservation(
                        evidence_id=_generate_evidence_id("issue-gharchive", repo, str(issue_number), timestamp),
                original_when=_parse_datetime(issue.get("created_at")),
                original_who=_make_github_actor(issue.get("user", {}).get("login", row["actor_login"])),
                original_what=f"Issue #{issue_number} created",
                observed_when=_parse_datetime(row["created_at"]),
                observed_by=EvidenceSource.GHARCHIVE,
                observed_what=f"Issue #{issue_number} recovered from GH Archive",
                repository=_make_github_repo(owner, name),
                verification=VerificationInfo(
                    source=EvidenceSource.GHARCHIVE,
                    bigquery_table=f"githubarchive.day.{date}",
                    query=f"repo.name='{repo}' AND type='IssuesEvent' AND created_at='{timestamp}'",
                ),
                issue_number=issue_number,
                is_pull_request=False,
                title=issue.get("title"),
                body=issue.get("body"),
                state=state,
                is_deleted=True,
            )

    raise ValueError(f"Issue #{issue_number} not found in GH Archive for {repo} at {timestamp}")


def create_pr_observation_from_gharchive(
    repo: str,
    pr_number: int,
    timestamp: str,
    client: GHArchiveClient,
) -> IssueObservation:
    """Query GH Archive and create PR observation.

    Args:
        repo: Full repo name (owner/repo)
        pr_number: PR number
        timestamp: ISO timestamp when event occurred
        client: GH Archive BigQuery client

    Raises ValueError if PR not found at specified timestamp.
    """
    owner, name = repo.split("/", 1)
    date = timestamp[:10].replace("-", "")

    rows = client.query_events(
        repo=repo,
        event_type="PullRequestEvent",
        from_date=date,
    )

    for row in rows:
        payload = json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
        pr = payload.get("pull_request", {})
        row_ts = str(row.get("created_at", ""))

        if pr.get("number") == pr_number and timestamp in row_ts:
            state = pr.get("state", "open")
            if pr.get("merged"):
                state = "merged"
            return IssueObservation(
                        evidence_id=_generate_evidence_id("pr-gharchive", repo, str(pr_number), timestamp),
                original_when=_parse_datetime(pr.get("created_at")),
                original_who=_make_github_actor(pr.get("user", {}).get("login", row["actor_login"])),
                original_what=f"PR #{pr_number} created",
                observed_when=_parse_datetime(row["created_at"]),
                observed_by=EvidenceSource.GHARCHIVE,
                observed_what=f"PR #{pr_number} recovered from GH Archive",
                repository=_make_github_repo(owner, name),
                verification=VerificationInfo(
                    source=EvidenceSource.GHARCHIVE,
                    bigquery_table=f"githubarchive.day.{date}",
                    query=f"repo.name='{repo}' AND type='PullRequestEvent' AND created_at='{timestamp}'",
                ),
                issue_number=pr_number,
                is_pull_request=True,
                title=pr.get("title"),
                body=pr.get("body"),
                state=state,
                is_deleted=True,
            )

    raise ValueError(f"PR #{pr_number} not found in GH Archive for {repo} at {timestamp}")


def create_commit_observation_from_gharchive(
    repo: str,
    sha: str,
    timestamp: str,
    client: GHArchiveClient,
) -> CommitObservation:
    """Query GH Archive and create CommitObservation.

    Args:
        repo: Full repo name (owner/repo)
        sha: Commit SHA (full or prefix)
        timestamp: ISO timestamp when push event occurred
        client: GH Archive BigQuery client

    Raises ValueError if commit not found at specified timestamp.
    """
    owner, name = repo.split("/", 1)
    date = timestamp[:10].replace("-", "")

    rows = client.query_events(
        repo=repo,
        event_type="PushEvent",
        from_date=date,
    )

    for row in rows:
        row_ts = str(row.get("created_at", ""))
        if timestamp not in row_ts:
            continue

        payload = json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
        for commit in payload.get("commits", []):
            if commit["sha"].startswith(sha) or sha.startswith(commit["sha"]):
                return CommitObservation(
                                evidence_id=_generate_evidence_id("commit-gharchive", repo, commit["sha"]),
                    original_when=_parse_datetime(row["created_at"]),
                    original_who=GitHubActor(login=commit.get("author", {}).get("name", "")),
                    original_what=commit.get("message", "").split("\n")[0],
                    observed_when=_parse_datetime(row["created_at"]),
                    observed_by=EvidenceSource.GHARCHIVE,
                    observed_what=f"Commit {commit['sha'][:8]} recovered from GH Archive",
                    repository=_make_github_repo(owner, name),
                    verification=VerificationInfo(
                        source=EvidenceSource.GHARCHIVE,
                        bigquery_table=f"githubarchive.day.{date}",
                        query=f"repo.name='{repo}' AND type='PushEvent' AND created_at='{timestamp}'",
                    ),
                    sha=commit["sha"],
                    message=commit.get("message", ""),
                    author=CommitAuthor(
                        name=commit.get("author", {}).get("name", ""),
                        email=commit.get("author", {}).get("email", ""),
                        date=_parse_datetime(row["created_at"]),
                    ),
                    committer=CommitAuthor(
                        name=commit.get("author", {}).get("name", ""),
                        email=commit.get("author", {}).get("email", ""),
                        date=_parse_datetime(row["created_at"]),
                    ),
                    parents=[],
                    files=[],
                    is_dangling=True,
                )

    raise ValueError(f"Commit {sha} not found in GH Archive for {repo} at {timestamp}")


def create_force_push_observation_from_gharchive(
    repo: str,
    timestamp: str,
    client: GHArchiveClient,
) -> CommitObservation:
    """Query GH Archive for a specific force push event.

    Args:
        repo: Full repo name (owner/repo)
        timestamp: ISO timestamp when force push occurred
        client: GH Archive BigQuery client

    Raises ValueError if no force push found at specified timestamp.
    """
    owner, name = repo.split("/", 1)
    date = timestamp[:10].replace("-", "")

    rows = client.query_events(
        repo=repo,
        event_type="PushEvent",
        from_date=date,
    )

    for row in rows:
        row_ts = str(row.get("created_at", ""))
        if timestamp not in row_ts:
            continue

        payload = json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
        size = int(payload.get("size", 0))
        before_sha = payload.get("before", "0" * 40)

        if size == 0 and before_sha != "0" * 40:
            return CommitObservation(
                        evidence_id=_generate_evidence_id("forcepush-gharchive", repo, before_sha, timestamp),
                original_when=_parse_datetime(row["created_at"]),
                original_who=_make_github_actor(row["actor_login"]),
                original_what="Commit overwritten by force push",
                observed_when=_parse_datetime(row["created_at"]),
                observed_by=EvidenceSource.GHARCHIVE,
                observed_what=f"Force push detected, before SHA: {before_sha[:8]}",
                repository=_make_github_repo(owner, name),
                verification=VerificationInfo(
                    source=EvidenceSource.GHARCHIVE,
                    bigquery_table=f"githubarchive.day.{date}",
                    query=f"repo.name='{repo}' AND type='PushEvent' AND created_at='{timestamp}' AND size=0",
                ),
                sha=before_sha,
                message="[Force pushed - fetch content via GitHub API]",
                author=CommitAuthor(
                    name="unknown",
                    email="unknown",
                    date=_parse_datetime(row["created_at"]),
                ),
                committer=CommitAuthor(
                    name="unknown",
                    email="unknown",
                    date=_parse_datetime(row["created_at"]),
                ),
                parents=[],
                files=[],
                is_dangling=True,
            )

    raise ValueError(f"Force push not found in GH Archive for {repo} at {timestamp}")


# =============================================================================
# OBSERVATION CREATION FUNCTIONS - From GitHub/Wayback
# =============================================================================


def create_commit_observation(
    query: CommitQuery,
    client: GitHubClient,
    observed_when: datetime | None = None,
) -> CommitObservation:
    """Create CommitObservation by fetching from GitHub API."""
    data = client.get_commit(query.repo.owner, query.repo.name, query.sha)
    commit = data["commit"]
    now = observed_when or datetime.now(timezone.utc)

    files = []
    for f in data.get("files", []):
        files.append(
            FileChange(
                filename=f["filename"],
                status=f.get("status", "modified"),
                additions=f.get("additions", 0),
                deletions=f.get("deletions", 0),
                patch=f.get("patch"),
            )
        )

    author = commit["author"]
    committer = commit["committer"]

    # GitHub user may be None for old commits (no linked account)
    gh_author = data.get("author") or {}
    actor_login = gh_author.get("login") or author["name"]

    return CommitObservation(
        evidence_id=_generate_evidence_id("commit", query.repo.full_name, data["sha"]),
        original_when=_parse_datetime(author.get("date")),
        original_who=_make_github_actor(actor_login),
        original_what=commit["message"].split("\n")[0],
        observed_when=now,
        observed_by=EvidenceSource.GITHUB,
        observed_what=f"Commit {data['sha'][:8]} observed via GitHub API",
        repository=_make_github_repo(query.repo.owner, query.repo.name),
        verification=VerificationInfo(
            source=EvidenceSource.GITHUB,
            url=HttpUrl(data["html_url"]),
        ),
        sha=data["sha"],
        message=commit["message"],
        author=CommitAuthor(
            name=author["name"],
            email=author["email"],
            date=_parse_datetime(author["date"]),
        ),
        committer=CommitAuthor(
            name=committer["name"],
            email=committer["email"],
            date=_parse_datetime(committer["date"]),
        ),
        parents=[p["sha"] for p in data.get("parents", [])],
        files=files,
        is_dangling=False,
    )


def create_commit_observation_from_git(
    sha: str,
    client: GitClient,
    repo: RepositoryQuery | None = None,
    observed_when: datetime | None = None,
) -> CommitObservation:
    """Create CommitObservation from local git repository."""
    data = client.get_commit(sha)
    files_data = client.get_commit_files(sha)
    now = observed_when or datetime.now(timezone.utc)

    files = [FileChange(filename=f["filename"], status=f["status"]) for f in files_data]

    repository = None
    if repo:
        repository = _make_github_repo(repo.owner, repo.name)

    return CommitObservation(
        evidence_id=_generate_evidence_id("commit", data["sha"]),
        original_when=_parse_datetime(data["author_date"]),
        original_who=GitHubActor(login=data["author_name"]),
        original_what=data["message"].split("\n")[0],
        observed_when=now,
        observed_by=EvidenceSource.GIT,
        observed_what=f"Commit {data['sha'][:8]} observed via local git",
        repository=repository,
        verification=VerificationInfo(source=EvidenceSource.GIT),
        sha=data["sha"],
        message=data["message"],
        author=CommitAuthor(
            name=data["author_name"],
            email=data["author_email"],
            date=_parse_datetime(data["author_date"]),
        ),
        committer=CommitAuthor(
            name=data["committer_name"],
            email=data["committer_email"],
            date=_parse_datetime(data["committer_date"]),
        ),
        parents=data["parents"],
        files=files,
    )


def create_issue_observation(
    query: IssueQuery,
    client: GitHubClient,
    observed_when: datetime | None = None,
) -> IssueObservation:
    """Create IssueObservation by fetching from GitHub API."""
    if query.is_pull_request:
        data = client.get_pull_request(query.repo.owner, query.repo.name, query.number)
    else:
        data = client.get_issue(query.repo.owner, query.repo.name, query.number)

    now = observed_when or datetime.now(timezone.utc)

    # Determine state
    state = data.get("state", "open")
    if query.is_pull_request and data.get("merged"):
        state = "merged"

    return IssueObservation(
        evidence_id=_generate_evidence_id("issue", query.repo.full_name, str(query.number)),
        original_when=_parse_datetime(data.get("created_at")),
        original_who=_make_github_actor(data["user"]["login"], data["user"].get("id")),
        original_what=f"{'PR' if query.is_pull_request else 'Issue'} #{query.number} opened",
        observed_when=now,
        observed_by=EvidenceSource.GITHUB,
        observed_what=f"Issue #{query.number} observed via GitHub API",
        repository=_make_github_repo(query.repo.owner, query.repo.name),
        verification=VerificationInfo(
            source=EvidenceSource.GITHUB,
            url=HttpUrl(data["html_url"]),
        ),
        issue_number=query.number,
        is_pull_request=query.is_pull_request,
        title=data.get("title"),
        body=data.get("body"),
        state=state,
    )


def create_file_observation(
    query: FileQuery,
    client: GitHubClient,
    observed_when: datetime | None = None,
) -> FileObservation:
    """Create FileObservation by fetching from GitHub API."""
    import base64

    data = client.get_file(query.repo.owner, query.repo.name, query.path, query.ref)
    now = observed_when or datetime.now(timezone.utc)

    # Decode content
    content = ""
    if data.get("content"):
        content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")

    content_hash = hashlib.sha256(content.encode()).hexdigest()

    return FileObservation(
        evidence_id=_generate_evidence_id("file", query.repo.full_name, query.path, query.ref),
        observed_when=now,
        observed_by=EvidenceSource.GITHUB,
        observed_what=f"File {query.path} observed via GitHub API",
        repository=_make_github_repo(query.repo.owner, query.repo.name),
        verification=VerificationInfo(
            source=EvidenceSource.GITHUB,
            url=HttpUrl(data["html_url"]),
        ),
        file_path=query.path,
        branch=query.ref if query.ref != "HEAD" else None,
        content=content,
        content_hash=content_hash,
    )


def create_branch_observation(
    query: BranchQuery,
    client: GitHubClient,
    observed_when: datetime | None = None,
) -> BranchObservation:
    """Create BranchObservation by fetching from GitHub API."""
    data = client.get_branch(query.repo.owner, query.repo.name, query.branch_name)
    now = observed_when or datetime.now(timezone.utc)

    return BranchObservation(
        evidence_id=_generate_evidence_id("branch", query.repo.full_name, query.branch_name),
        observed_when=now,
        observed_by=EvidenceSource.GITHUB,
        observed_what=f"Branch {query.branch_name} observed via GitHub API",
        repository=_make_github_repo(query.repo.owner, query.repo.name),
        verification=VerificationInfo(
            source=EvidenceSource.GITHUB,
            url=HttpUrl(f"https://github.com/{query.repo.full_name}/tree/{query.branch_name}"),
        ),
        branch_name=query.branch_name,
        head_sha=data["commit"]["sha"],
    )


def create_tag_observation(
    query: TagQuery,
    client: GitHubClient,
    observed_when: datetime | None = None,
) -> TagObservation:
    """Create TagObservation by fetching from GitHub API."""
    data = client.get_tag(query.repo.owner, query.repo.name, query.tag_name)
    now = observed_when or datetime.now(timezone.utc)

    return TagObservation(
        evidence_id=_generate_evidence_id("tag", query.repo.full_name, query.tag_name),
        observed_when=now,
        observed_by=EvidenceSource.GITHUB,
        observed_what=f"Tag {query.tag_name} observed via GitHub API",
        repository=_make_github_repo(query.repo.owner, query.repo.name),
        verification=VerificationInfo(
            source=EvidenceSource.GITHUB,
            url=HttpUrl(f"https://github.com/{query.repo.full_name}/releases/tag/{query.tag_name}"),
        ),
        tag_name=query.tag_name,
        target_sha=data["object"]["sha"],
    )


def create_release_observation(
    query: ReleaseQuery,
    client: GitHubClient,
    observed_when: datetime | None = None,
) -> ReleaseObservation:
    """Create ReleaseObservation by fetching from GitHub API."""
    data = client.get_release(query.repo.owner, query.repo.name, query.tag_name)
    now = observed_when or datetime.now(timezone.utc)

    return ReleaseObservation(
        evidence_id=_generate_evidence_id("release", query.repo.full_name, query.tag_name),
        original_when=_parse_datetime(data.get("created_at")),
        original_who=_make_github_actor(data["author"]["login"], data["author"].get("id")),
        original_what=f"Release {query.tag_name} published",
        observed_when=now,
        observed_by=EvidenceSource.GITHUB,
        observed_what=f"Release {query.tag_name} observed via GitHub API",
        repository=_make_github_repo(query.repo.owner, query.repo.name),
        verification=VerificationInfo(
            source=EvidenceSource.GITHUB,
            url=HttpUrl(data["html_url"]),
        ),
        tag_name=query.tag_name,
        release_name=data.get("name"),
        release_body=data.get("body"),
    )


def create_fork_observations(
    query: ForkQuery,
    client: GitHubClient,
    observed_when: datetime | None = None,
) -> list[ForkObservation]:
    """Create ForkObservations by fetching from GitHub API."""
    data = client.get_forks(query.repo.owner, query.repo.name)
    now = observed_when or datetime.now(timezone.utc)

    observations = []
    for fork in data:
        observations.append(
            ForkObservation(
                        evidence_id=_generate_evidence_id("fork", query.repo.full_name, fork["full_name"]),
                original_when=_parse_datetime(fork.get("created_at")),
                original_who=_make_github_actor(fork["owner"]["login"], fork["owner"].get("id")),
                original_what=f"Forked {query.repo.full_name}",
                observed_when=now,
                observed_by=EvidenceSource.GITHUB,
                observed_what=f"Fork {fork['full_name']} observed via GitHub API",
                repository=_make_github_repo(query.repo.owner, query.repo.name),
                verification=VerificationInfo(
                    source=EvidenceSource.GITHUB,
                    url=HttpUrl(fork["html_url"]),
                ),
                fork_full_name=fork["full_name"],
                parent_full_name=query.repo.full_name,
            )
        )

    return observations


def create_snapshot_observation(
    query: WaybackQuery,
    client: WaybackClient,
    observed_when: datetime | None = None,
) -> SnapshotObservation:
    """Create SnapshotObservation by querying Wayback CDX API."""
    results = client.search_cdx(
        str(query.url),
        from_date=query.from_date,
        to_date=query.to_date,
    )
    now = observed_when or datetime.now(timezone.utc)

    snapshots = []
    for r in results:
        # Parse timestamp: YYYYMMDDHHMMSS
        ts = r["timestamp"]
        captured = datetime(
            int(ts[:4]),
            int(ts[4:6]),
            int(ts[6:8]),
            int(ts[8:10]) if len(ts) > 8 else 0,
            int(ts[10:12]) if len(ts) > 10 else 0,
            int(ts[12:14]) if len(ts) > 12 else 0,
            tzinfo=timezone.utc,
        )
        snapshots.append(
            WaybackSnapshot(
                timestamp=ts,
                captured_at=captured,
                archive_url=HttpUrl(f"https://web.archive.org/web/{ts}/{r['original']}"),
                original_url=HttpUrl(r["original"]),
                status_code=int(r.get("statuscode", 200)),
            )
        )

    return SnapshotObservation(
        evidence_id=_generate_evidence_id("snapshot", str(query.url)),
        observed_when=now,
        observed_by=EvidenceSource.WAYBACK,
        observed_what=f"Found {len(snapshots)} Wayback snapshots for {query.url}",
        verification=VerificationInfo(
            source=EvidenceSource.WAYBACK,
            url=HttpUrl(f"https://web.archive.org/cdx/search/cdx?url={query.url}"),
        ),
        original_url=query.url,
        snapshots=snapshots,
        total_snapshots=len(snapshots),
    )


def create_ioc(
    ioc_type: IOCType,
    value: str,
    source_url: HttpUrl,
    extracted_from: str | None = None,
) -> IOC:
    """Create an IOC by verifying it exists in the vendor report.

    Fetches source_url and confirms IOC value appears in content.
    Raises ValueError if IOC cannot be verified at source.
    """
    import requests

    # Fetch and verify at source
    try:
        resp = requests.get(str(source_url), timeout=30)
        resp.raise_for_status()
        content = resp.text
    except Exception as e:
        raise ValueError(f"Failed to fetch source URL {source_url}: {e}")

    # Check if IOC value appears in the page
    if value.lower() not in content.lower():
        raise ValueError(f"IOC value '{value[:50]}' not found in source {source_url}")

    now = datetime.now(timezone.utc)

    return IOC(
        evidence_id=_generate_evidence_id("ioc", ioc_type.value, value),
        observed_when=now,
        observed_by=EvidenceSource.SECURITY_VENDOR,
        observed_what=f"IOC {ioc_type.value}: {value[:50]}{'...' if len(value) > 50 else ''}",
        verification=VerificationInfo(
            source=EvidenceSource.SECURITY_VENDOR,
            url=source_url,
        ),
        ioc_type=ioc_type,
        value=value,
        first_seen=now,
        last_seen=now,
        extracted_from=extracted_from,
    )


def create_article_observation(
    url: str,
    title: str,
    author: str | None = None,
    published_date: datetime | None = None,
    source_name: str | None = None,
    summary: str | None = None,
    observed_when: datetime | None = None,
) -> ArticleObservation:
    """Create an ArticleObservation for a blog post or security report.

    Args:
        url: URL of the article
        title: Title of the article
        author: Author name (optional)
        published_date: When the article was published (optional)
        source_name: Name of the publication (e.g., "404media", "mbgsec.com")
        summary: Brief summary of the article
        observed_when: When we observed/documented this article
    """
    now = observed_when or datetime.now(timezone.utc)

    return ArticleObservation(
        evidence_id=_generate_evidence_id("article", url),
        observed_when=now,
        observed_by=EvidenceSource.SECURITY_VENDOR,
        observed_what=f"Article: {title[:50]}{'...' if len(title) > 50 else ''}",
        verification=VerificationInfo(
            source=EvidenceSource.SECURITY_VENDOR,
            url=HttpUrl(url),
        ),
        url=HttpUrl(url),
        title=title,
        author=author,
        published_date=published_date,
        source_name=source_name,
        summary=summary,
    )


# =============================================================================
# HIGH-LEVEL FACTORY FUNCTIONS
# =============================================================================


class EvidenceFactory:
    """Factory for creating verified OSINT evidence objects.

    All data sources are public and require no authentication:
    - GitHub API: Public repos, commits, issues, PRs (60 req/hr)
    - Wayback Machine: Archived web pages
    - GH Archive: BigQuery (requires GCP project, free tier: 1TB/month)
    """

    def __init__(
        self,
        gharchive_credentials: str | None = None,
        gharchive_project: str | None = None,
    ):
        self._github_client: GitHubClient | None = None
        self._wayback_client: WaybackClient | None = None
        self._gharchive_client: GHArchiveClient | None = None
        self._gharchive_credentials = gharchive_credentials
        self._gharchive_project = gharchive_project

    @property
    def github(self) -> GitHubClient:
        if self._github_client is None:
            self._github_client = GitHubClient()
        return self._github_client

    @property
    def wayback(self) -> WaybackClient:
        if self._wayback_client is None:
            self._wayback_client = WaybackClient()
        return self._wayback_client

    @property
    def gharchive(self) -> GHArchiveClient:
        if self._gharchive_client is None:
            self._gharchive_client = GHArchiveClient(
                credentials_path=self._gharchive_credentials,
                project_id=self._gharchive_project,
            )
        return self._gharchive_client

    def commit(self, owner: str, repo: str, sha: str) -> CommitObservation:
        """Create verified CommitObservation."""
        query = CommitQuery(repo=RepositoryQuery(owner=owner, name=repo), sha=sha)
        return create_commit_observation(query, self.github)

    def issue(self, owner: str, repo: str, number: int) -> IssueObservation:
        """Create verified IssueObservation."""
        query = IssueQuery(repo=RepositoryQuery(owner=owner, name=repo), number=number)
        return create_issue_observation(query, self.github)

    def pull_request(self, owner: str, repo: str, number: int) -> IssueObservation:
        """Create verified PR observation (as IssueObservation)."""
        query = IssueQuery(repo=RepositoryQuery(owner=owner, name=repo), number=number, is_pull_request=True)
        return create_issue_observation(query, self.github)

    def file(self, owner: str, repo: str, path: str, ref: str = "HEAD") -> FileObservation:
        """Create verified FileObservation."""
        query = FileQuery(repo=RepositoryQuery(owner=owner, name=repo), path=path, ref=ref)
        return create_file_observation(query, self.github)

    def branch(self, owner: str, repo: str, branch_name: str) -> BranchObservation:
        """Create verified BranchObservation."""
        query = BranchQuery(repo=RepositoryQuery(owner=owner, name=repo), branch_name=branch_name)
        return create_branch_observation(query, self.github)

    def tag(self, owner: str, repo: str, tag_name: str) -> TagObservation:
        """Create verified TagObservation."""
        query = TagQuery(repo=RepositoryQuery(owner=owner, name=repo), tag_name=tag_name)
        return create_tag_observation(query, self.github)

    def release(self, owner: str, repo: str, tag_name: str) -> ReleaseObservation:
        """Create verified ReleaseObservation."""
        query = ReleaseQuery(repo=RepositoryQuery(owner=owner, name=repo), tag_name=tag_name)
        return create_release_observation(query, self.github)

    def forks(self, owner: str, repo: str) -> list[ForkObservation]:
        """Create verified ForkObservations."""
        query = ForkQuery(repo=RepositoryQuery(owner=owner, name=repo))
        return create_fork_observations(query, self.github)

    def wayback_snapshots(
        self,
        url: str,
        from_date: str | None = None,
        to_date: str | None = None,
    ) -> SnapshotObservation:
        """Create SnapshotObservation from Wayback Machine."""
        query = WaybackQuery(url=HttpUrl(url), from_date=from_date, to_date=to_date)
        return create_snapshot_observation(query, self.wayback)

    def events_from_gharchive(
        self,
        timestamp: str,
        repo: str | None = None,
        actor: str | None = None,
        event_type: str | None = None,
    ) -> list[AnyEvent]:
        """Query GH Archive and create Events.

        Args:
            timestamp: Specific time in YYYYMMDDHHMM format (e.g., "202507131207" for July 13, 2025 12:07 UTC)
            repo: Repository in "owner/name" format (required if no actor)
            actor: GitHub username (required if no repo)
            event_type: Filter by event type (e.g., "PushEvent")

        Raises:
            ValueError: If timestamp is not 12 digits or neither repo nor actor is specified
        """
        if len(timestamp) != 12 or not timestamp.isdigit():
            raise ValueError(
                f"timestamp must be YYYYMMDDHHMM format (12 digits), got: {timestamp}"
            )

        if not repo and not actor:
            raise ValueError(
                "Must specify at least 'repo' or 'actor' to avoid expensive full-table scans"
            )

        repo_query = None
        if repo:
            parts = repo.split("/", 1)
            if len(parts) == 2:
                repo_query = RepositoryQuery(owner=parts[0], name=parts[1])

        query = GHArchiveQuery(
            repo=repo_query,
            actor=actor,
            event_type=event_type,
            from_date=timestamp,
            to_date=timestamp,
        )

        rows = self.gharchive.query_events(
            repo=repo_query.full_name if repo_query else None,
            actor=actor,
            event_type=event_type,
            from_date=timestamp,
            to_date=timestamp,
        )

        events = []
        for row in rows:
            try:
                events.append(create_event_from_gharchive(row))
            except (KeyError, ValueError):
                continue

        return events

    def ioc(
        self,
        ioc_type: IOCType | str,
        value: str,
        source_url: str,
        extracted_from: str | None = None,
    ) -> IOC:
        """Create an IOC by verifying it exists in vendor report.

        Raises ValueError if IOC cannot be verified at source.
        """
        if isinstance(ioc_type, str):
            ioc_type = IOCType(ioc_type)
        return create_ioc(
            ioc_type=ioc_type,
            value=value,
            source_url=HttpUrl(source_url),
            extracted_from=extracted_from,
        )

    def article(
        self,
        url: str,
        title: str,
        author: str | None = None,
        published_date: datetime | None = None,
        source_name: str | None = None,
        summary: str | None = None,
    ) -> ArticleObservation:
        """Create an ArticleObservation for a blog post or security report."""
        return create_article_observation(
            url=url,
            title=title,
            author=author,
            published_date=published_date,
            source_name=source_name,
            summary=summary,
        )

    # GH Archive recovery methods - require exact timestamp

    def recover_issue(self, repo: str, issue_number: int, timestamp: str) -> IssueObservation:
        """Recover deleted issue content from GH Archive.

        Args:
            repo: Full repo name (owner/repo)
            issue_number: Issue number
            timestamp: ISO timestamp when event occurred (e.g. "2025-07-13T20:30:24Z")
        """
        return create_issue_observation_from_gharchive(repo, issue_number, timestamp, self.gharchive)

    def recover_pr(self, repo: str, pr_number: int, timestamp: str) -> IssueObservation:
        """Recover deleted PR content from GH Archive.

        Args:
            repo: Full repo name (owner/repo)
            pr_number: PR number
            timestamp: ISO timestamp when event occurred
        """
        return create_pr_observation_from_gharchive(repo, pr_number, timestamp, self.gharchive)

    def recover_commit(self, repo: str, sha: str, timestamp: str) -> CommitObservation:
        """Recover commit metadata from GH Archive.

        Args:
            repo: Full repo name (owner/repo)
            sha: Commit SHA (full or prefix)
            timestamp: ISO timestamp when push event occurred
        """
        return create_commit_observation_from_gharchive(repo, sha, timestamp, self.gharchive)

    def recover_force_push(self, repo: str, timestamp: str) -> CommitObservation:
        """Recover force-pushed commit from GH Archive.

        Args:
            repo: Full repo name (owner/repo)
            timestamp: ISO timestamp when force push occurred
        """
        return create_force_push_observation_from_gharchive(repo, timestamp, self.gharchive)
