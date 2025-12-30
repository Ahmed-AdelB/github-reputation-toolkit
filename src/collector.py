#!/usr/bin/env python3
"""
Metrics Collector - GitHub Profile & Package Statistics Tracker

Collects and tracks:
- GitHub profile metrics (repos, stars, forks, followers)
- Contribution metrics (PRs merged, issues closed, commits)
- PyPI package download statistics
- Daily snapshots for trend analysis

Author: Ahmed Adel Bakr Alderai
"""

import json
import logging
import os
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import httpx
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

load_dotenv()

console = Console()

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("logs/collector.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


# =============================================================================
# DATA MODELS
# =============================================================================


class MetricType(Enum):
    """Types of metrics collected."""

    PROFILE = "profile"
    CONTRIBUTION = "contribution"
    PYPI = "pypi"


@dataclass
class ProfileMetrics:
    """GitHub profile metrics snapshot."""

    username: str
    public_repos: int
    total_stars: int
    total_forks: int
    followers: int
    following: int
    public_gists: int
    created_at: datetime
    updated_at: datetime
    bio: str = ""
    company: str = ""
    location: str = ""
    hireable: bool = False
    snapshot_date: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "username": self.username,
            "public_repos": self.public_repos,
            "total_stars": self.total_stars,
            "total_forks": self.total_forks,
            "followers": self.followers,
            "following": self.following,
            "public_gists": self.public_gists,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "bio": self.bio,
            "company": self.company,
            "location": self.location,
            "hireable": self.hireable,
            "snapshot_date": self.snapshot_date.isoformat(),
        }


@dataclass
class ContributionMetrics:
    """GitHub contribution metrics snapshot."""

    username: str
    prs_opened: int
    prs_merged: int
    prs_closed: int
    issues_opened: int
    issues_closed: int
    commits_total: int
    reviews_given: int
    repositories_contributed_to: int
    snapshot_date: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "username": self.username,
            "prs_opened": self.prs_opened,
            "prs_merged": self.prs_merged,
            "prs_closed": self.prs_closed,
            "issues_opened": self.issues_opened,
            "issues_closed": self.issues_closed,
            "commits_total": self.commits_total,
            "reviews_given": self.reviews_given,
            "repositories_contributed_to": self.repositories_contributed_to,
            "snapshot_date": self.snapshot_date.isoformat(),
        }


@dataclass
class RepositoryMetrics:
    """Individual repository metrics."""

    owner: str
    name: str
    full_name: str
    stars: int
    forks: int
    watchers: int
    open_issues: int
    language: str
    created_at: datetime
    updated_at: datetime
    pushed_at: datetime
    is_fork: bool
    description: str = ""
    homepage: str = ""
    topics: list[str] = field(default_factory=list)
    snapshot_date: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "owner": self.owner,
            "name": self.name,
            "full_name": self.full_name,
            "stars": self.stars,
            "forks": self.forks,
            "watchers": self.watchers,
            "open_issues": self.open_issues,
            "language": self.language or "Unknown",
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "pushed_at": self.pushed_at.isoformat(),
            "is_fork": self.is_fork,
            "description": self.description,
            "homepage": self.homepage,
            "topics": json.dumps(self.topics),
            "snapshot_date": self.snapshot_date.isoformat(),
        }


@dataclass
class PyPIMetrics:
    """PyPI package download metrics."""

    package_name: str
    version: str
    downloads_last_day: int
    downloads_last_week: int
    downloads_last_month: int
    total_releases: int
    first_release_date: Optional[datetime]
    latest_release_date: Optional[datetime]
    requires_python: str = ""
    author: str = ""
    summary: str = ""
    snapshot_date: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "package_name": self.package_name,
            "version": self.version,
            "downloads_last_day": self.downloads_last_day,
            "downloads_last_week": self.downloads_last_week,
            "downloads_last_month": self.downloads_last_month,
            "total_releases": self.total_releases,
            "first_release_date": self.first_release_date.isoformat() if self.first_release_date else None,
            "latest_release_date": self.latest_release_date.isoformat() if self.latest_release_date else None,
            "requires_python": self.requires_python,
            "author": self.author,
            "summary": self.summary,
            "snapshot_date": self.snapshot_date.isoformat(),
        }


@dataclass
class WeeklySummary:
    """Weekly metrics summary for reporting."""

    week_start: datetime
    week_end: datetime
    profile_growth: dict[str, int]
    contribution_totals: dict[str, int]
    top_repositories: list[RepositoryMetrics]
    pypi_downloads: dict[str, int]
    highlights: list[str]


# =============================================================================
# RATE LIMITER
# =============================================================================


@dataclass
class RateLimiter:
    """Manages API rate limiting across multiple endpoints."""

    limits: dict[str, dict[str, Any]] = field(default_factory=dict)

    def update(self, api: str, remaining: int, reset_time: Optional[datetime]) -> None:
        """Update rate limit info for an API."""
        self.limits[api] = {
            "remaining": remaining,
            "reset_time": reset_time,
            "updated_at": datetime.now(),
        }

    def check(self, api: str, min_remaining: int = 10) -> bool:
        """Check if we can make more requests to an API."""
        if api not in self.limits:
            return True

        limit_info = self.limits[api]
        if limit_info["remaining"] < min_remaining:
            if limit_info["reset_time"]:
                wait_time = (limit_info["reset_time"] - datetime.now()).total_seconds()
                if wait_time > 0:
                    logger.warning(f"Rate limit low for {api}. {limit_info['remaining']} remaining.")
                    return False
        return True

    def wait_if_needed(self, api: str, min_remaining: int = 10) -> None:
        """Wait if rate limit is too low."""
        if api not in self.limits:
            return

        limit_info = self.limits[api]
        if limit_info["remaining"] < min_remaining and limit_info["reset_time"]:
            wait_time = (limit_info["reset_time"] - datetime.now()).total_seconds()
            if wait_time > 0:
                wait_time = min(wait_time + 5, 3600)  # Cap at 1 hour
                logger.info(f"Rate limited on {api}. Waiting {wait_time:.0f}s...")
                console.print(f"[yellow]Rate limited on {api}. Waiting {wait_time:.0f}s...[/yellow]")
                time.sleep(wait_time)


# =============================================================================
# MAIN COLLECTOR CLASS
# =============================================================================


@dataclass
class MetricsCollector:
    """Main metrics collector for GitHub and PyPI statistics."""

    github_token: str = field(default_factory=lambda: os.getenv("GITHUB_TOKEN", ""))
    github_username: str = field(default_factory=lambda: os.getenv("GITHUB_USERNAME", ""))
    pypi_packages: list[str] = field(default_factory=list)
    db_path: Path = field(default_factory=lambda: Path("data/metrics.db"))
    rate_limiter: RateLimiter = field(default_factory=RateLimiter)

    def __post_init__(self) -> None:
        """Initialize the collector."""
        # Ensure directories exist
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        Path("logs").mkdir(parents=True, exist_ok=True)
        Path("reports").mkdir(parents=True, exist_ok=True)

        # Initialize database
        self._init_db()

        # Initialize HTTP clients
        self.github_client = httpx.Client(
            base_url="https://api.github.com",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.github_token}" if self.github_token else "",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=30.0,
        )

        self.pypi_client = httpx.Client(
            base_url="https://pypistats.org/api",
            timeout=30.0,
        )

        self.pypi_json_client = httpx.Client(
            base_url="https://pypi.org/pypi",
            timeout=30.0,
        )

        logger.info(f"MetricsCollector initialized for user: {self.github_username}")

    def _init_db(self) -> None:
        """Initialize SQLite database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Profile metrics table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS profile_metrics (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                public_repos INTEGER,
                total_stars INTEGER,
                total_forks INTEGER,
                followers INTEGER,
                following INTEGER,
                public_gists INTEGER,
                bio TEXT,
                company TEXT,
                location TEXT,
                hireable INTEGER,
                created_at TEXT,
                updated_at TEXT,
                snapshot_date TEXT NOT NULL,
                UNIQUE(username, snapshot_date)
            )
        """)

        # Contribution metrics table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS contribution_metrics (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                prs_opened INTEGER,
                prs_merged INTEGER,
                prs_closed INTEGER,
                issues_opened INTEGER,
                issues_closed INTEGER,
                commits_total INTEGER,
                reviews_given INTEGER,
                repositories_contributed_to INTEGER,
                snapshot_date TEXT NOT NULL,
                UNIQUE(username, snapshot_date)
            )
        """)

        # Repository metrics table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS repository_metrics (
                id INTEGER PRIMARY KEY,
                owner TEXT NOT NULL,
                name TEXT NOT NULL,
                full_name TEXT NOT NULL,
                stars INTEGER,
                forks INTEGER,
                watchers INTEGER,
                open_issues INTEGER,
                language TEXT,
                description TEXT,
                homepage TEXT,
                topics TEXT,
                is_fork INTEGER,
                created_at TEXT,
                updated_at TEXT,
                pushed_at TEXT,
                snapshot_date TEXT NOT NULL,
                UNIQUE(full_name, snapshot_date)
            )
        """)

        # PyPI metrics table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pypi_metrics (
                id INTEGER PRIMARY KEY,
                package_name TEXT NOT NULL,
                version TEXT,
                downloads_last_day INTEGER,
                downloads_last_week INTEGER,
                downloads_last_month INTEGER,
                total_releases INTEGER,
                first_release_date TEXT,
                latest_release_date TEXT,
                requires_python TEXT,
                author TEXT,
                summary TEXT,
                snapshot_date TEXT NOT NULL,
                UNIQUE(package_name, snapshot_date)
            )
        """)

        # Collection log table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS collection_log (
                id INTEGER PRIMARY KEY,
                metric_type TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                error_message TEXT,
                collected_at TEXT NOT NULL
            )
        """)

        # Create indexes for efficient queries
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_profile_snapshot
            ON profile_metrics(username, snapshot_date)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_contribution_snapshot
            ON contribution_metrics(username, snapshot_date)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_repo_snapshot
            ON repository_metrics(full_name, snapshot_date)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_pypi_snapshot
            ON pypi_metrics(package_name, snapshot_date)
        """)

        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")

    def _update_github_rate_limit(self, response: httpx.Response) -> None:
        """Update rate limit info from GitHub response headers."""
        remaining = int(response.headers.get("x-ratelimit-remaining", 5000))
        reset_ts = response.headers.get("x-ratelimit-reset")
        reset_time = datetime.fromtimestamp(int(reset_ts)) if reset_ts else None
        self.rate_limiter.update("github", remaining, reset_time)

    def _log_collection(
        self, metric_type: MetricType, target: str, status: str, error: Optional[str] = None
    ) -> None:
        """Log a collection attempt."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO collection_log (metric_type, target, status, error_message, collected_at)
            VALUES (?, ?, ?, ?, ?)
        """,
            (metric_type.value, target, status, error, datetime.now().isoformat()),
        )
        conn.commit()
        conn.close()

    # =========================================================================
    # GITHUB PROFILE METRICS
    # =========================================================================

    def collect_profile_metrics(self, username: Optional[str] = None) -> Optional[ProfileMetrics]:
        """Collect GitHub profile metrics for a user."""
        username = username or self.github_username
        if not username:
            logger.error("No username provided for profile metrics collection")
            return None

        self.rate_limiter.wait_if_needed("github")

        try:
            # Get user profile
            response = self.github_client.get(f"/users/{username}")
            self._update_github_rate_limit(response)

            if response.status_code != 200:
                error_msg = f"Failed to fetch profile: {response.status_code}"
                logger.error(error_msg)
                self._log_collection(MetricType.PROFILE, username, "error", error_msg)
                return None

            user_data = response.json()

            # Get total stars and forks across all repos
            total_stars, total_forks = self._calculate_repo_totals(username)

            metrics = ProfileMetrics(
                username=username,
                public_repos=user_data.get("public_repos", 0),
                total_stars=total_stars,
                total_forks=total_forks,
                followers=user_data.get("followers", 0),
                following=user_data.get("following", 0),
                public_gists=user_data.get("public_gists", 0),
                created_at=datetime.fromisoformat(
                    user_data["created_at"].replace("Z", "+00:00")
                ),
                updated_at=datetime.fromisoformat(
                    user_data["updated_at"].replace("Z", "+00:00")
                ),
                bio=user_data.get("bio") or "",
                company=user_data.get("company") or "",
                location=user_data.get("location") or "",
                hireable=user_data.get("hireable") or False,
            )

            self._save_profile_metrics(metrics)
            self._log_collection(MetricType.PROFILE, username, "success")
            logger.info(f"Collected profile metrics for {username}")

            return metrics

        except Exception as e:
            error_msg = f"Exception collecting profile metrics: {e}"
            logger.exception(error_msg)
            self._log_collection(MetricType.PROFILE, username, "error", str(e))
            return None

    def _calculate_repo_totals(self, username: str) -> tuple[int, int]:
        """Calculate total stars and forks across all user repositories."""
        total_stars = 0
        total_forks = 0
        page = 1

        while True:
            self.rate_limiter.wait_if_needed("github")

            response = self.github_client.get(
                f"/users/{username}/repos",
                params={"per_page": 100, "page": page, "type": "owner"},
            )
            self._update_github_rate_limit(response)

            if response.status_code != 200:
                break

            repos = response.json()
            if not repos:
                break

            for repo in repos:
                if not repo.get("fork", False):  # Only count owned repos, not forks
                    total_stars += repo.get("stargazers_count", 0)
                    total_forks += repo.get("forks_count", 0)

            page += 1
            time.sleep(0.25)  # Be nice to the API

        return total_stars, total_forks

    def _save_profile_metrics(self, metrics: ProfileMetrics) -> None:
        """Save profile metrics to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        snapshot_date = metrics.snapshot_date.strftime("%Y-%m-%d")

        cursor.execute(
            """
            INSERT OR REPLACE INTO profile_metrics
            (username, public_repos, total_stars, total_forks, followers, following,
             public_gists, bio, company, location, hireable, created_at, updated_at, snapshot_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                metrics.username,
                metrics.public_repos,
                metrics.total_stars,
                metrics.total_forks,
                metrics.followers,
                metrics.following,
                metrics.public_gists,
                metrics.bio,
                metrics.company,
                metrics.location,
                1 if metrics.hireable else 0,
                metrics.created_at.isoformat(),
                metrics.updated_at.isoformat(),
                snapshot_date,
            ),
        )
        conn.commit()
        conn.close()

    # =========================================================================
    # GITHUB CONTRIBUTION METRICS
    # =========================================================================

    def collect_contribution_metrics(
        self, username: Optional[str] = None, days_back: int = 365
    ) -> Optional[ContributionMetrics]:
        """Collect GitHub contribution metrics for a user."""
        username = username or self.github_username
        if not username:
            logger.error("No username provided for contribution metrics collection")
            return None

        self.rate_limiter.wait_if_needed("github")

        try:
            since_date = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%d")

            # Count PRs opened
            prs_opened = self._count_search_results(
                f"author:{username} type:pr created:>={since_date}"
            )

            # Count PRs merged
            prs_merged = self._count_search_results(
                f"author:{username} type:pr is:merged created:>={since_date}"
            )

            # Count PRs closed (includes merged)
            prs_closed = self._count_search_results(
                f"author:{username} type:pr is:closed created:>={since_date}"
            )

            # Count issues opened
            issues_opened = self._count_search_results(
                f"author:{username} type:issue created:>={since_date}"
            )

            # Count issues closed by user
            issues_closed = self._count_search_results(
                f"author:{username} type:issue is:closed created:>={since_date}"
            )

            # Count reviews given
            reviews_given = self._count_search_results(
                f"reviewed-by:{username} type:pr created:>={since_date}"
            )

            # Count commits (approximate using push events or commit search)
            commits_total = self._count_commits(username, days_back)

            # Count unique repos contributed to
            repos_contributed = self._count_repos_contributed(username, days_back)

            metrics = ContributionMetrics(
                username=username,
                prs_opened=prs_opened,
                prs_merged=prs_merged,
                prs_closed=prs_closed,
                issues_opened=issues_opened,
                issues_closed=issues_closed,
                commits_total=commits_total,
                reviews_given=reviews_given,
                repositories_contributed_to=repos_contributed,
            )

            self._save_contribution_metrics(metrics)
            self._log_collection(MetricType.CONTRIBUTION, username, "success")
            logger.info(f"Collected contribution metrics for {username}")

            return metrics

        except Exception as e:
            error_msg = f"Exception collecting contribution metrics: {e}"
            logger.exception(error_msg)
            self._log_collection(MetricType.CONTRIBUTION, username, "error", str(e))
            return None

    def _count_search_results(self, query: str) -> int:
        """Count total results for a GitHub search query."""
        self.rate_limiter.wait_if_needed("github")

        try:
            response = self.github_client.get(
                "/search/issues", params={"q": query, "per_page": 1}
            )
            self._update_github_rate_limit(response)

            if response.status_code == 200:
                return response.json().get("total_count", 0)
            elif response.status_code == 403:
                logger.warning(f"Rate limited during search: {query}")
                time.sleep(60)  # Wait a minute on search rate limit
                return 0
            else:
                logger.warning(f"Search failed with status {response.status_code}: {query}")
                return 0

        except Exception as e:
            logger.error(f"Exception during search: {e}")
            return 0

    def _count_commits(self, username: str, days_back: int) -> int:
        """Count commits by user (approximate using events API)."""
        self.rate_limiter.wait_if_needed("github")
        total_commits = 0

        try:
            # Use events API to approximate commits
            response = self.github_client.get(
                f"/users/{username}/events/public", params={"per_page": 100}
            )
            self._update_github_rate_limit(response)

            if response.status_code == 200:
                cutoff_date = datetime.now() - timedelta(days=days_back)
                for event in response.json():
                    if event.get("type") == "PushEvent":
                        event_date = datetime.fromisoformat(
                            event["created_at"].replace("Z", "+00:00")
                        )
                        if event_date.replace(tzinfo=None) >= cutoff_date:
                            # Count commits in push
                            total_commits += len(event.get("payload", {}).get("commits", []))

        except Exception as e:
            logger.error(f"Exception counting commits: {e}")

        return total_commits

    def _count_repos_contributed(self, username: str, days_back: int) -> int:
        """Count unique repositories user has contributed to."""
        repos: set[str] = set()
        since_date = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%d")

        # Get repos from merged PRs
        self.rate_limiter.wait_if_needed("github")

        try:
            response = self.github_client.get(
                "/search/issues",
                params={
                    "q": f"author:{username} type:pr is:merged created:>={since_date}",
                    "per_page": 100,
                },
            )
            self._update_github_rate_limit(response)

            if response.status_code == 200:
                for item in response.json().get("items", []):
                    repo_url = item.get("repository_url", "")
                    if repo_url:
                        repos.add(repo_url.split("/")[-2] + "/" + repo_url.split("/")[-1])

        except Exception as e:
            logger.error(f"Exception counting repos contributed: {e}")

        return len(repos)

    def _save_contribution_metrics(self, metrics: ContributionMetrics) -> None:
        """Save contribution metrics to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        snapshot_date = metrics.snapshot_date.strftime("%Y-%m-%d")

        cursor.execute(
            """
            INSERT OR REPLACE INTO contribution_metrics
            (username, prs_opened, prs_merged, prs_closed, issues_opened, issues_closed,
             commits_total, reviews_given, repositories_contributed_to, snapshot_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                metrics.username,
                metrics.prs_opened,
                metrics.prs_merged,
                metrics.prs_closed,
                metrics.issues_opened,
                metrics.issues_closed,
                metrics.commits_total,
                metrics.reviews_given,
                metrics.repositories_contributed_to,
                snapshot_date,
            ),
        )
        conn.commit()
        conn.close()

    # =========================================================================
    # REPOSITORY METRICS
    # =========================================================================

    def collect_repository_metrics(
        self, username: Optional[str] = None
    ) -> list[RepositoryMetrics]:
        """Collect metrics for all repositories owned by user."""
        username = username or self.github_username
        if not username:
            logger.error("No username provided for repository metrics collection")
            return []

        repos: list[RepositoryMetrics] = []
        page = 1

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Collecting repository metrics...", total=None)

            while True:
                self.rate_limiter.wait_if_needed("github")

                try:
                    response = self.github_client.get(
                        f"/users/{username}/repos",
                        params={"per_page": 100, "page": page, "sort": "updated"},
                    )
                    self._update_github_rate_limit(response)

                    if response.status_code != 200:
                        break

                    repo_data = response.json()
                    if not repo_data:
                        break

                    for repo in repo_data:
                        metrics = RepositoryMetrics(
                            owner=repo["owner"]["login"],
                            name=repo["name"],
                            full_name=repo["full_name"],
                            stars=repo.get("stargazers_count", 0),
                            forks=repo.get("forks_count", 0),
                            watchers=repo.get("watchers_count", 0),
                            open_issues=repo.get("open_issues_count", 0),
                            language=repo.get("language") or "Unknown",
                            created_at=datetime.fromisoformat(
                                repo["created_at"].replace("Z", "+00:00")
                            ),
                            updated_at=datetime.fromisoformat(
                                repo["updated_at"].replace("Z", "+00:00")
                            ),
                            pushed_at=datetime.fromisoformat(
                                repo["pushed_at"].replace("Z", "+00:00")
                            )
                            if repo.get("pushed_at")
                            else datetime.now(),
                            is_fork=repo.get("fork", False),
                            description=repo.get("description") or "",
                            homepage=repo.get("homepage") or "",
                            topics=repo.get("topics", []),
                        )
                        repos.append(metrics)
                        self._save_repository_metrics(metrics)

                    progress.update(task, description=f"Collected {len(repos)} repositories...")
                    page += 1
                    time.sleep(0.25)

                except Exception as e:
                    logger.error(f"Exception collecting repo metrics: {e}")
                    break

        self._log_collection(MetricType.PROFILE, f"{username}/repos", "success")
        logger.info(f"Collected metrics for {len(repos)} repositories")

        return repos

    def _save_repository_metrics(self, metrics: RepositoryMetrics) -> None:
        """Save repository metrics to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        snapshot_date = metrics.snapshot_date.strftime("%Y-%m-%d")

        cursor.execute(
            """
            INSERT OR REPLACE INTO repository_metrics
            (owner, name, full_name, stars, forks, watchers, open_issues, language,
             description, homepage, topics, is_fork, created_at, updated_at, pushed_at, snapshot_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                metrics.owner,
                metrics.name,
                metrics.full_name,
                metrics.stars,
                metrics.forks,
                metrics.watchers,
                metrics.open_issues,
                metrics.language,
                metrics.description,
                metrics.homepage,
                json.dumps(metrics.topics),
                1 if metrics.is_fork else 0,
                metrics.created_at.isoformat(),
                metrics.updated_at.isoformat(),
                metrics.pushed_at.isoformat(),
                snapshot_date,
            ),
        )
        conn.commit()
        conn.close()

    # =========================================================================
    # PYPI METRICS
    # =========================================================================

    def collect_pypi_metrics(self, package_name: str) -> Optional[PyPIMetrics]:
        """Collect download statistics for a PyPI package."""
        try:
            # Get package info from PyPI JSON API
            info_response = self.pypi_json_client.get(f"/{package_name}/json")

            if info_response.status_code != 200:
                error_msg = f"Package {package_name} not found on PyPI"
                logger.warning(error_msg)
                self._log_collection(MetricType.PYPI, package_name, "error", error_msg)
                return None

            info_data = info_response.json()
            info = info_data.get("info", {})
            releases = info_data.get("releases", {})

            # Get download stats from pypistats.org
            downloads_day = self._get_pypi_downloads(package_name, "day")
            downloads_week = self._get_pypi_downloads(package_name, "week")
            downloads_month = self._get_pypi_downloads(package_name, "month")

            # Parse release dates
            release_dates = []
            for version, files in releases.items():
                if files:
                    upload_time = files[0].get("upload_time")
                    if upload_time:
                        release_dates.append(datetime.fromisoformat(upload_time))

            release_dates.sort()
            first_release = release_dates[0] if release_dates else None
            latest_release = release_dates[-1] if release_dates else None

            metrics = PyPIMetrics(
                package_name=package_name,
                version=info.get("version", ""),
                downloads_last_day=downloads_day,
                downloads_last_week=downloads_week,
                downloads_last_month=downloads_month,
                total_releases=len(releases),
                first_release_date=first_release,
                latest_release_date=latest_release,
                requires_python=info.get("requires_python") or "",
                author=info.get("author") or "",
                summary=info.get("summary") or "",
            )

            self._save_pypi_metrics(metrics)
            self._log_collection(MetricType.PYPI, package_name, "success")
            logger.info(f"Collected PyPI metrics for {package_name}")

            return metrics

        except Exception as e:
            error_msg = f"Exception collecting PyPI metrics: {e}"
            logger.exception(error_msg)
            self._log_collection(MetricType.PYPI, package_name, "error", str(e))
            return None

    def _get_pypi_downloads(self, package_name: str, period: str) -> int:
        """Get download count for a specific period from pypistats.org."""
        try:
            response = self.pypi_client.get(f"/packages/{package_name}/recent")

            if response.status_code == 200:
                data = response.json().get("data", {})
                if period == "day":
                    return data.get("last_day", 0)
                elif period == "week":
                    return data.get("last_week", 0)
                elif period == "month":
                    return data.get("last_month", 0)

            return 0

        except Exception as e:
            logger.error(f"Exception getting PyPI downloads: {e}")
            return 0

    def _save_pypi_metrics(self, metrics: PyPIMetrics) -> None:
        """Save PyPI metrics to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        snapshot_date = metrics.snapshot_date.strftime("%Y-%m-%d")

        cursor.execute(
            """
            INSERT OR REPLACE INTO pypi_metrics
            (package_name, version, downloads_last_day, downloads_last_week, downloads_last_month,
             total_releases, first_release_date, latest_release_date, requires_python,
             author, summary, snapshot_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                metrics.package_name,
                metrics.version,
                metrics.downloads_last_day,
                metrics.downloads_last_week,
                metrics.downloads_last_month,
                metrics.total_releases,
                metrics.first_release_date.isoformat() if metrics.first_release_date else None,
                metrics.latest_release_date.isoformat() if metrics.latest_release_date else None,
                metrics.requires_python,
                metrics.author,
                metrics.summary,
                snapshot_date,
            ),
        )
        conn.commit()
        conn.close()

    def collect_all_pypi_metrics(self) -> list[PyPIMetrics]:
        """Collect metrics for all configured PyPI packages."""
        results: list[PyPIMetrics] = []

        for package in self.pypi_packages:
            metrics = self.collect_pypi_metrics(package)
            if metrics:
                results.append(metrics)
            time.sleep(0.5)  # Be nice to PyPI API

        return results

    # =========================================================================
    # REPORTING
    # =========================================================================

    def generate_weekly_summary(self, weeks_back: int = 1) -> Optional[WeeklySummary]:
        """Generate a weekly summary report."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        week_end = datetime.now()
        week_start = week_end - timedelta(days=7 * weeks_back)
        prev_week_start = week_start - timedelta(days=7)

        try:
            # Get profile growth
            cursor.execute(
                """
                SELECT followers, total_stars, total_forks, public_repos
                FROM profile_metrics
                WHERE username = ? AND snapshot_date >= ? AND snapshot_date < ?
                ORDER BY snapshot_date DESC LIMIT 1
            """,
                (self.github_username, week_start.strftime("%Y-%m-%d"), week_end.strftime("%Y-%m-%d")),
            )
            current = cursor.fetchone()

            cursor.execute(
                """
                SELECT followers, total_stars, total_forks, public_repos
                FROM profile_metrics
                WHERE username = ? AND snapshot_date >= ? AND snapshot_date < ?
                ORDER BY snapshot_date DESC LIMIT 1
            """,
                (self.github_username, prev_week_start.strftime("%Y-%m-%d"), week_start.strftime("%Y-%m-%d")),
            )
            previous = cursor.fetchone()

            profile_growth = {}
            if current and previous:
                profile_growth = {
                    "followers": current[0] - previous[0],
                    "stars": current[1] - previous[1],
                    "forks": current[2] - previous[2],
                    "repos": current[3] - previous[3],
                }

            # Get contribution totals
            cursor.execute(
                """
                SELECT prs_merged, issues_closed, commits_total, reviews_given
                FROM contribution_metrics
                WHERE username = ? AND snapshot_date >= ?
                ORDER BY snapshot_date DESC LIMIT 1
            """,
                (self.github_username, week_start.strftime("%Y-%m-%d")),
            )
            contributions = cursor.fetchone()

            contribution_totals = {}
            if contributions:
                contribution_totals = {
                    "prs_merged": contributions[0],
                    "issues_closed": contributions[1],
                    "commits": contributions[2],
                    "reviews": contributions[3],
                }

            # Get top repositories
            cursor.execute(
                """
                SELECT full_name, stars, forks, language
                FROM repository_metrics
                WHERE owner = ? AND snapshot_date >= ?
                ORDER BY stars DESC LIMIT 5
            """,
                (self.github_username, week_start.strftime("%Y-%m-%d")),
            )
            top_repos_data = cursor.fetchall()

            # Get PyPI downloads
            cursor.execute(
                """
                SELECT package_name, downloads_last_week
                FROM pypi_metrics
                WHERE snapshot_date >= ?
                ORDER BY downloads_last_week DESC
            """,
                (week_start.strftime("%Y-%m-%d"),),
            )
            pypi_data = cursor.fetchall()
            pypi_downloads = {row[0]: row[1] for row in pypi_data}

            conn.close()

            # Generate highlights
            highlights = []
            if profile_growth.get("followers", 0) > 0:
                highlights.append(f"Gained {profile_growth['followers']} new followers")
            if profile_growth.get("stars", 0) > 0:
                highlights.append(f"Earned {profile_growth['stars']} new stars")
            if contribution_totals.get("prs_merged", 0) > 0:
                highlights.append(f"Merged {contribution_totals['prs_merged']} PRs")
            if sum(pypi_downloads.values()) > 0:
                highlights.append(f"PyPI packages downloaded {sum(pypi_downloads.values())} times")

            return WeeklySummary(
                week_start=week_start,
                week_end=week_end,
                profile_growth=profile_growth,
                contribution_totals=contribution_totals,
                top_repositories=[],  # Would need to convert from tuple data
                pypi_downloads=pypi_downloads,
                highlights=highlights,
            )

        except Exception as e:
            logger.exception(f"Exception generating weekly summary: {e}")
            conn.close()
            return None

    def generate_report(self, output_path: Optional[Path] = None) -> str:
        """Generate a comprehensive metrics report."""
        summary = self.generate_weekly_summary()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        report = f"""# GitHub Reputation Metrics Report
Generated: {timestamp}
Username: {self.github_username}

## Profile Summary

"""

        # Get latest profile metrics
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT public_repos, total_stars, total_forks, followers, following
            FROM profile_metrics
            WHERE username = ?
            ORDER BY snapshot_date DESC LIMIT 1
        """,
            (self.github_username,),
        )
        profile = cursor.fetchone()

        if profile:
            report += f"""| Metric | Value |
|--------|-------|
| Public Repos | {profile[0]} |
| Total Stars | {profile[1]} |
| Total Forks | {profile[2]} |
| Followers | {profile[3]} |
| Following | {profile[4]} |

"""

        # Contribution metrics
        cursor.execute(
            """
            SELECT prs_merged, prs_opened, issues_closed, commits_total, reviews_given, repositories_contributed_to
            FROM contribution_metrics
            WHERE username = ?
            ORDER BY snapshot_date DESC LIMIT 1
        """,
            (self.github_username,),
        )
        contributions = cursor.fetchone()

        if contributions:
            report += f"""## Contribution Metrics (Last 365 Days)

| Metric | Value |
|--------|-------|
| PRs Merged | {contributions[0]} |
| PRs Opened | {contributions[1]} |
| Issues Closed | {contributions[2]} |
| Commits | {contributions[3]} |
| Reviews Given | {contributions[4]} |
| Repos Contributed To | {contributions[5]} |

"""

        # Top repositories
        cursor.execute(
            """
            SELECT name, stars, forks, language
            FROM repository_metrics
            WHERE owner = ? AND is_fork = 0
            ORDER BY stars DESC LIMIT 10
        """,
            (self.github_username,),
        )
        repos = cursor.fetchall()

        if repos:
            report += """## Top Repositories

| Repository | Stars | Forks | Language |
|------------|-------|-------|----------|
"""
            for repo in repos:
                report += f"| {repo[0]} | {repo[1]} | {repo[2]} | {repo[3]} |\n"

            report += "\n"

        # PyPI packages
        cursor.execute(
            """
            SELECT package_name, version, downloads_last_month, downloads_last_week
            FROM pypi_metrics
            ORDER BY downloads_last_month DESC
        """
        )
        packages = cursor.fetchall()

        if packages:
            report += """## PyPI Packages

| Package | Version | Monthly Downloads | Weekly Downloads |
|---------|---------|-------------------|------------------|
"""
            for pkg in packages:
                report += f"| {pkg[0]} | {pkg[1]} | {pkg[2]:,} | {pkg[3]:,} |\n"

            report += "\n"

        conn.close()

        # Weekly highlights
        if summary and summary.highlights:
            report += """## Weekly Highlights

"""
            for highlight in summary.highlights:
                report += f"- {highlight}\n"

        report += f"""
---
*Generated by GitHub Reputation Toolkit - {self.github_username}*
"""

        # Save report if path provided
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(report)
            logger.info(f"Report saved to {output_path}")

        return report

    def display_metrics(self) -> None:
        """Display current metrics in a formatted table."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Profile table
        cursor.execute(
            """
            SELECT public_repos, total_stars, total_forks, followers
            FROM profile_metrics
            WHERE username = ?
            ORDER BY snapshot_date DESC LIMIT 1
        """,
            (self.github_username,),
        )
        profile = cursor.fetchone()

        if profile:
            profile_table = Table(title="Profile Metrics", show_header=True, header_style="bold cyan")
            profile_table.add_column("Metric", style="white")
            profile_table.add_column("Value", style="green", justify="right")
            profile_table.add_row("Public Repos", str(profile[0]))
            profile_table.add_row("Total Stars", str(profile[1]))
            profile_table.add_row("Total Forks", str(profile[2]))
            profile_table.add_row("Followers", str(profile[3]))
            console.print(profile_table)
            console.print()

        # Contribution table
        cursor.execute(
            """
            SELECT prs_merged, issues_closed, commits_total, reviews_given
            FROM contribution_metrics
            WHERE username = ?
            ORDER BY snapshot_date DESC LIMIT 1
        """,
            (self.github_username,),
        )
        contributions = cursor.fetchone()

        if contributions:
            contrib_table = Table(
                title="Contribution Metrics (Last 365 Days)",
                show_header=True,
                header_style="bold magenta",
            )
            contrib_table.add_column("Metric", style="white")
            contrib_table.add_column("Value", style="yellow", justify="right")
            contrib_table.add_row("PRs Merged", str(contributions[0]))
            contrib_table.add_row("Issues Closed", str(contributions[1]))
            contrib_table.add_row("Commits", str(contributions[2]))
            contrib_table.add_row("Reviews Given", str(contributions[3]))
            console.print(contrib_table)
            console.print()

        # Top repos table
        cursor.execute(
            """
            SELECT name, stars, forks, language
            FROM repository_metrics
            WHERE owner = ? AND is_fork = 0
            ORDER BY stars DESC LIMIT 5
        """,
            (self.github_username,),
        )
        repos = cursor.fetchall()

        if repos:
            repos_table = Table(
                title="Top Repositories by Stars",
                show_header=True,
                header_style="bold blue",
            )
            repos_table.add_column("Repository", style="white")
            repos_table.add_column("Stars", style="yellow", justify="right")
            repos_table.add_column("Forks", style="cyan", justify="right")
            repos_table.add_column("Language", style="green")
            for repo in repos:
                repos_table.add_row(repo[0], str(repo[1]), str(repo[2]), repo[3] or "Unknown")
            console.print(repos_table)
            console.print()

        # PyPI packages table
        cursor.execute(
            """
            SELECT package_name, downloads_last_month, downloads_last_week
            FROM pypi_metrics
            ORDER BY downloads_last_month DESC LIMIT 5
        """
        )
        packages = cursor.fetchall()

        if packages:
            pypi_table = Table(
                title="PyPI Package Downloads",
                show_header=True,
                header_style="bold red",
            )
            pypi_table.add_column("Package", style="white")
            pypi_table.add_column("Monthly", style="green", justify="right")
            pypi_table.add_column("Weekly", style="cyan", justify="right")
            for pkg in packages:
                pypi_table.add_row(pkg[0], f"{pkg[1]:,}", f"{pkg[2]:,}")
            console.print(pypi_table)

        conn.close()

    # =========================================================================
    # MAIN COLLECTION WORKFLOW
    # =========================================================================

    def collect_all(self) -> dict[str, Any]:
        """Run full metrics collection."""
        console.print(
            Panel.fit(
                f"[bold green]Starting Metrics Collection[/bold green]\n"
                f"Username: {self.github_username}\n"
                f"PyPI Packages: {len(self.pypi_packages)}",
                title="Metrics Collector",
            )
        )

        results: dict[str, Any] = {
            "profile": None,
            "contributions": None,
            "repositories": [],
            "pypi": [],
        }

        # Collect profile metrics
        console.print("\n[bold cyan]Collecting profile metrics...[/bold cyan]")
        results["profile"] = self.collect_profile_metrics()

        # Collect contribution metrics
        console.print("\n[bold cyan]Collecting contribution metrics...[/bold cyan]")
        results["contributions"] = self.collect_contribution_metrics()

        # Collect repository metrics
        console.print("\n[bold cyan]Collecting repository metrics...[/bold cyan]")
        results["repositories"] = self.collect_repository_metrics()

        # Collect PyPI metrics
        if self.pypi_packages:
            console.print("\n[bold cyan]Collecting PyPI metrics...[/bold cyan]")
            results["pypi"] = self.collect_all_pypi_metrics()

        # Display summary
        console.print("\n")
        self.display_metrics()

        # Generate report
        report_path = Path(f"reports/metrics_{datetime.now().strftime('%Y%m%d')}.md")
        self.generate_report(report_path)
        console.print(f"\n[green]Report saved to {report_path}[/green]")

        return results

    def run_scheduled(self, interval_hours: int = 24) -> None:
        """Run metrics collection on a schedule."""
        console.print(
            f"[bold green]Starting scheduled collection (every {interval_hours} hours)...[/bold green]"
        )

        collection_count = 0
        while True:
            collection_count += 1
            console.print(
                f"\n[bold cyan]===== Collection #{collection_count} - "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} =====[/bold cyan]"
            )

            try:
                self.collect_all()
            except Exception as e:
                logger.exception(f"Collection failed: {e}")
                console.print(f"[red]Collection failed: {e}[/red]")

            console.print(f"\n[yellow]Next collection in {interval_hours} hours...[/yellow]")
            time.sleep(interval_hours * 3600)

    def close(self) -> None:
        """Close HTTP clients."""
        self.github_client.close()
        self.pypi_client.close()
        self.pypi_json_client.close()


# =============================================================================
# CLI ENTRY POINT
# =============================================================================


def main() -> None:
    """Main entry point for the metrics collector CLI."""
    import typer

    app = typer.Typer(
        help="GitHub Reputation Metrics Collector - Track your GitHub and PyPI statistics"
    )

    @app.command()
    def collect(
        username: Optional[str] = typer.Option(
            None, "--username", "-u", help="GitHub username (defaults to GITHUB_USERNAME env var)"
        ),
        packages: Optional[str] = typer.Option(
            None, "--packages", "-p", help="Comma-separated PyPI package names to track"
        ),
        continuous: bool = typer.Option(
            False, "--continuous", "-c", help="Run in continuous mode (daily collection)"
        ),
        interval: int = typer.Option(
            24, "--interval", "-i", help="Hours between collections in continuous mode"
        ),
    ) -> None:
        """Collect GitHub and PyPI metrics."""
        pypi_packages = packages.split(",") if packages else []

        collector = MetricsCollector(
            github_username=username or os.getenv("GITHUB_USERNAME", ""),
            pypi_packages=pypi_packages,
        )

        try:
            if continuous:
                collector.run_scheduled(interval)
            else:
                collector.collect_all()
        finally:
            collector.close()

    @app.command()
    def report(
        username: Optional[str] = typer.Option(
            None, "--username", "-u", help="GitHub username"
        ),
        output: Optional[str] = typer.Option(
            None, "--output", "-o", help="Output file path for the report"
        ),
    ) -> None:
        """Generate a metrics report from stored data."""
        collector = MetricsCollector(
            github_username=username or os.getenv("GITHUB_USERNAME", ""),
        )

        try:
            output_path = Path(output) if output else None
            report_content = collector.generate_report(output_path)

            if not output:
                console.print(report_content)
            else:
                console.print(f"[green]Report saved to {output}[/green]")
        finally:
            collector.close()

    @app.command()
    def show(
        username: Optional[str] = typer.Option(
            None, "--username", "-u", help="GitHub username"
        ),
    ) -> None:
        """Display current metrics from database."""
        collector = MetricsCollector(
            github_username=username or os.getenv("GITHUB_USERNAME", ""),
        )

        try:
            collector.display_metrics()
        finally:
            collector.close()

    @app.command()
    def profile(
        username: Optional[str] = typer.Option(
            None, "--username", "-u", help="GitHub username"
        ),
    ) -> None:
        """Collect only profile metrics."""
        collector = MetricsCollector(
            github_username=username or os.getenv("GITHUB_USERNAME", ""),
        )

        try:
            metrics = collector.collect_profile_metrics()
            if metrics:
                console.print(f"[green]Profile metrics collected for {metrics.username}[/green]")
                console.print(f"  Repos: {metrics.public_repos}")
                console.print(f"  Stars: {metrics.total_stars}")
                console.print(f"  Forks: {metrics.total_forks}")
                console.print(f"  Followers: {metrics.followers}")
        finally:
            collector.close()

    @app.command()
    def contributions(
        username: Optional[str] = typer.Option(
            None, "--username", "-u", help="GitHub username"
        ),
        days: int = typer.Option(365, "--days", "-d", help="Days to look back"),
    ) -> None:
        """Collect only contribution metrics."""
        collector = MetricsCollector(
            github_username=username or os.getenv("GITHUB_USERNAME", ""),
        )

        try:
            metrics = collector.collect_contribution_metrics(days_back=days)
            if metrics:
                console.print(
                    f"[green]Contribution metrics collected for {metrics.username}[/green]"
                )
                console.print(f"  PRs Merged: {metrics.prs_merged}")
                console.print(f"  PRs Opened: {metrics.prs_opened}")
                console.print(f"  Issues Closed: {metrics.issues_closed}")
                console.print(f"  Commits: {metrics.commits_total}")
                console.print(f"  Reviews: {metrics.reviews_given}")
        finally:
            collector.close()

    @app.command()
    def pypi(
        packages: str = typer.Argument(..., help="Comma-separated PyPI package names"),
    ) -> None:
        """Collect PyPI package download statistics."""
        package_list = [p.strip() for p in packages.split(",")]

        collector = MetricsCollector(pypi_packages=package_list)

        try:
            for package in package_list:
                console.print(f"\n[cyan]Collecting metrics for {package}...[/cyan]")
                metrics = collector.collect_pypi_metrics(package)
                if metrics:
                    console.print(f"[green]  Version: {metrics.version}[/green]")
                    console.print(f"  Monthly downloads: {metrics.downloads_last_month:,}")
                    console.print(f"  Weekly downloads: {metrics.downloads_last_week:,}")
                    console.print(f"  Daily downloads: {metrics.downloads_last_day:,}")
        finally:
            collector.close()

    @app.command()
    def weekly(
        username: Optional[str] = typer.Option(
            None, "--username", "-u", help="GitHub username"
        ),
        weeks: int = typer.Option(1, "--weeks", "-w", help="Weeks back to summarize"),
    ) -> None:
        """Generate a weekly summary report."""
        collector = MetricsCollector(
            github_username=username or os.getenv("GITHUB_USERNAME", ""),
        )

        try:
            summary = collector.generate_weekly_summary(weeks_back=weeks)
            if summary:
                console.print(
                    Panel.fit(
                        f"[bold]Weekly Summary[/bold]\n"
                        f"Period: {summary.week_start.strftime('%Y-%m-%d')} to "
                        f"{summary.week_end.strftime('%Y-%m-%d')}",
                        title="Weekly Report",
                    )
                )

                if summary.profile_growth:
                    console.print("\n[bold cyan]Profile Growth:[/bold cyan]")
                    for metric, value in summary.profile_growth.items():
                        sign = "+" if value > 0 else ""
                        color = "green" if value > 0 else "red" if value < 0 else "white"
                        console.print(f"  {metric}: [{color}]{sign}{value}[/{color}]")

                if summary.contribution_totals:
                    console.print("\n[bold magenta]Contributions:[/bold magenta]")
                    for metric, value in summary.contribution_totals.items():
                        console.print(f"  {metric}: {value}")

                if summary.highlights:
                    console.print("\n[bold yellow]Highlights:[/bold yellow]")
                    for highlight in summary.highlights:
                        console.print(f"  - {highlight}")
        finally:
            collector.close()

    app()


if __name__ == "__main__":
    main()
