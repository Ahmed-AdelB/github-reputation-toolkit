#!/usr/bin/env python3
"""
Issue Radar - Automated GitHub Issue Finder for Reputation Building

Targets:
- AI/ML repositories (LangChain, Transformers, FastAPI, PyTorch, etc.)
- Security repositories (OWASP, Bandit, Safety, Trivy, etc.)
- Compliance repositories (OPA, Checkov, tfsec, etc.)

Author: Ahmed Adel Bakr Alderai
"""

import json
import os
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import httpx
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

load_dotenv()

console = Console()

# =============================================================================
# TARGET REPOSITORIES CONFIGURATION
# =============================================================================

AI_ML_REPOS: list[str] = [
    # LLM & AI Frameworks
    "langchain-ai/langchain",
    "huggingface/transformers",
    "openai/openai-python",
    "anthropics/anthropic-sdk-python",
    "run-llama/llama_index",
    "microsoft/autogen",
    "crewAIInc/crewAI",
    "stanfordnlp/dspy",
    "vllm-project/vllm",
    "ggerganov/llama.cpp",
    # ML/DL Frameworks
    "pytorch/pytorch",
    "keras-team/keras",
    "scikit-learn/scikit-learn",
    "Lightning-AI/pytorch-lightning",
    "jax-ml/jax",
    # API & Web Frameworks
    "tiangolo/fastapi",
    "encode/starlette",
    "encode/httpx",
    "pydantic/pydantic",
    "pallets/flask",
    # MLOps & Tools
    "mlflow/mlflow",
    "wandb/wandb",
    "bentoml/BentoML",
    "ray-project/ray",
    "apache/airflow",
]

SECURITY_REPOS: list[str] = [
    # OWASP Projects
    "OWASP/CheatSheetSeries",
    "OWASP/wstg",
    "OWASP/ASVS",
    "OWASP/owasp-mastg",
    "OWASP/wrongsecrets",
    # Security Scanners
    "PyCQA/bandit",
    "pyupio/safety",
    "aquasecurity/trivy",
    "anchore/grype",
    "anchore/syft",
    "returntocorp/semgrep",
    "snyk/cli",
    # Secret Detection
    "trufflesecurity/trufflehog",
    "gitleaks/gitleaks",
    "Yelp/detect-secrets",
    # Vulnerability Databases
    "github/advisory-database",
    "pypa/advisory-database",
    # Security Tools
    "sqlmapproject/sqlmap",
    "swisskyrepo/PayloadsAllTheThings",
    "danielmiessler/SecLists",
]

COMPLIANCE_REPOS: list[str] = [
    # Policy as Code
    "open-policy-agent/opa",
    "open-policy-agent/gatekeeper",
    "open-policy-agent/conftest",
    # Infrastructure Security
    "bridgecrewio/checkov",
    "aquasecurity/tfsec",
    "tenable/terrascan",
    "stelligent/cfn_nag",
    "prowler-cloud/prowler",
    # Kubernetes Security
    "aquasecurity/kube-bench",
    "aquasecurity/kube-hunter",
    "stackrox/kube-linter",
    "FairwindsOps/polaris",
    # Cloud Security
    "cloud-custodian/cloud-custodian",
    "nccgroup/ScoutSuite",
    "toniblyx/my-arsenal-of-aws-security-tools",
]

# Issue labels to search for
ISSUE_LABELS: list[str] = [
    "good first issue",
    "help wanted",
    "bug",
    "documentation",
    "enhancement",
    "security",
    "vulnerability",
    "hacktoberfest",
    "beginner-friendly",
    "easy",
    "low-hanging-fruit",
    "needs-triage",
    "contributions welcome",
]


@dataclass
class Issue:
    """Represents a GitHub issue."""

    repo: str
    number: int
    title: str
    url: str
    labels: list[str]
    created_at: datetime
    updated_at: datetime
    comments: int
    state: str
    author: str
    body: str = ""
    score: float = 0.0
    category: str = "unknown"


@dataclass
class IssueRadar:
    """Main issue radar class for finding contribution opportunities."""

    github_token: str = field(default_factory=lambda: os.getenv("GITHUB_TOKEN", ""))
    db_path: Path = field(default_factory=lambda: Path("data/issues.db"))
    rate_limit_remaining: int = 5000
    rate_limit_reset: Optional[datetime] = None

    def __post_init__(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self.client = httpx.Client(
            base_url="https://api.github.com",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.github_token}" if self.github_token else "",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=30.0,
        )

    def _init_db(self) -> None:
        """Initialize SQLite database for caching issues."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS issues (
                id INTEGER PRIMARY KEY,
                repo TEXT NOT NULL,
                number INTEGER NOT NULL,
                title TEXT NOT NULL,
                url TEXT NOT NULL,
                labels TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                comments INTEGER DEFAULT 0,
                state TEXT DEFAULT 'open',
                author TEXT,
                body TEXT,
                score REAL DEFAULT 0.0,
                category TEXT DEFAULT 'unknown',
                discovered_at TEXT NOT NULL,
                UNIQUE(repo, number)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_log (
                id INTEGER PRIMARY KEY,
                repo TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                issues_found INTEGER DEFAULT 0,
                status TEXT DEFAULT 'success'
            )
        """)
        conn.commit()
        conn.close()

    def _check_rate_limit(self) -> None:
        """Check and handle GitHub API rate limits."""
        if self.rate_limit_remaining < 10:
            if self.rate_limit_reset:
                wait_time = (self.rate_limit_reset - datetime.now()).total_seconds()
                if wait_time > 0:
                    console.print(f"[yellow]Rate limit low. Waiting {wait_time:.0f}s...[/yellow]")
                    time.sleep(min(wait_time + 5, 3600))

    def _update_rate_limit(self, response: httpx.Response) -> None:
        """Update rate limit info from response headers."""
        self.rate_limit_remaining = int(response.headers.get("x-ratelimit-remaining", 5000))
        reset_ts = response.headers.get("x-ratelimit-reset")
        if reset_ts:
            self.rate_limit_reset = datetime.fromtimestamp(int(reset_ts))

    def search_issues(
        self,
        repo: str,
        labels: Optional[list[str]] = None,
        state: str = "open",
        since_days: int = 90,
    ) -> list[Issue]:
        """Search for issues in a repository."""
        self._check_rate_limit()

        issues: list[Issue] = []
        since_date = datetime.now() - timedelta(days=since_days)

        # Build search query
        query_parts = [
            f"repo:{repo}",
            f"is:issue",
            f"state:{state}",
            f"updated:>={since_date.strftime('%Y-%m-%d')}",
        ]

        if labels:
            for label in labels[:3]:  # Limit to avoid query length issues
                query_parts.append(f'label:"{label}"')

        query = " ".join(query_parts)

        try:
            response = self.client.get(
                "/search/issues",
                params={"q": query, "sort": "updated", "order": "desc", "per_page": 30},
            )
            self._update_rate_limit(response)

            if response.status_code == 200:
                data = response.json()
                for item in data.get("items", []):
                    issue = Issue(
                        repo=repo,
                        number=item["number"],
                        title=item["title"],
                        url=item["html_url"],
                        labels=[l["name"] for l in item.get("labels", [])],
                        created_at=datetime.fromisoformat(item["created_at"].replace("Z", "+00:00")),
                        updated_at=datetime.fromisoformat(item["updated_at"].replace("Z", "+00:00")),
                        comments=item.get("comments", 0),
                        state=item["state"],
                        author=item["user"]["login"] if item.get("user") else "unknown",
                        body=item.get("body", "")[:500] if item.get("body") else "",
                    )
                    issues.append(issue)
            elif response.status_code == 403:
                console.print(f"[red]Rate limited on {repo}[/red]")
            else:
                console.print(f"[yellow]Error {response.status_code} for {repo}[/yellow]")

        except Exception as e:
            console.print(f"[red]Exception searching {repo}: {e}[/red]")

        return issues

    def get_repo_issues(self, repo: str, state: str = "open") -> list[Issue]:
        """Get issues directly from repo endpoint (no search API limits)."""
        self._check_rate_limit()

        issues: list[Issue] = []

        try:
            response = self.client.get(
                f"/repos/{repo}/issues",
                params={"state": state, "sort": "updated", "direction": "desc", "per_page": 50},
            )
            self._update_rate_limit(response)

            if response.status_code == 200:
                for item in response.json():
                    # Skip pull requests (they show up in issues endpoint)
                    if "pull_request" in item:
                        continue

                    issue = Issue(
                        repo=repo,
                        number=item["number"],
                        title=item["title"],
                        url=item["html_url"],
                        labels=[l["name"] for l in item.get("labels", [])],
                        created_at=datetime.fromisoformat(item["created_at"].replace("Z", "+00:00")),
                        updated_at=datetime.fromisoformat(item["updated_at"].replace("Z", "+00:00")),
                        comments=item.get("comments", 0),
                        state=item["state"],
                        author=item["user"]["login"] if item.get("user") else "unknown",
                        body=item.get("body", "")[:500] if item.get("body") else "",
                    )
                    issues.append(issue)

        except Exception as e:
            console.print(f"[red]Exception getting issues from {repo}: {e}[/red]")

        return issues

    def score_issue(self, issue: Issue) -> float:
        """Score an issue based on contribution potential."""
        score = 0.0

        # Label scoring
        high_value_labels = {"good first issue", "help wanted", "beginner-friendly", "easy"}
        medium_value_labels = {"bug", "documentation", "enhancement"}
        security_labels = {"security", "vulnerability", "cve"}

        issue_labels_lower = {l.lower() for l in issue.labels}

        if issue_labels_lower & high_value_labels:
            score += 30
        if issue_labels_lower & medium_value_labels:
            score += 15
        if issue_labels_lower & security_labels:
            score += 25  # Security issues are high value for CVE hunting

        # Recency scoring (newer = better)
        days_old = (datetime.now(issue.updated_at.tzinfo) - issue.updated_at).days
        if days_old < 7:
            score += 20
        elif days_old < 30:
            score += 10
        elif days_old < 90:
            score += 5

        # Comment scoring (low comments = less competition)
        if issue.comments == 0:
            score += 15
        elif issue.comments < 3:
            score += 10
        elif issue.comments < 10:
            score += 5

        # Body length scoring (detailed issues are easier to work on)
        if len(issue.body) > 200:
            score += 10
        elif len(issue.body) > 50:
            score += 5

        return score

    def categorize_repo(self, repo: str) -> str:
        """Categorize a repository."""
        if repo in AI_ML_REPOS:
            return "AI/ML"
        elif repo in SECURITY_REPOS:
            return "Security"
        elif repo in COMPLIANCE_REPOS:
            return "Compliance"
        return "Other"

    def save_issues(self, issues: list[Issue]) -> int:
        """Save issues to database, return count of new issues."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        new_count = 0

        for issue in issues:
            try:
                cursor.execute("""
                    INSERT OR REPLACE INTO issues
                    (repo, number, title, url, labels, created_at, updated_at,
                     comments, state, author, body, score, category, discovered_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    issue.repo,
                    issue.number,
                    issue.title,
                    issue.url,
                    json.dumps(issue.labels),
                    issue.created_at.isoformat(),
                    issue.updated_at.isoformat(),
                    issue.comments,
                    issue.state,
                    issue.author,
                    issue.body,
                    issue.score,
                    issue.category,
                    datetime.now().isoformat(),
                ))
                new_count += cursor.rowcount
            except Exception as e:
                console.print(f"[red]Error saving issue {issue.repo}#{issue.number}: {e}[/red]")

        conn.commit()
        conn.close()
        return new_count

    def log_scan(self, repo: str, issues_found: int, status: str = "success") -> None:
        """Log a repository scan."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_log (repo, scanned_at, issues_found, status)
            VALUES (?, ?, ?, ?)
        """, (repo, datetime.now().isoformat(), issues_found, status))
        conn.commit()
        conn.close()

    def scan_all_repos(self, categories: Optional[list[str]] = None) -> dict[str, list[Issue]]:
        """Scan all configured repositories for issues."""
        all_repos: list[str] = []

        if categories is None or "ai_ml" in categories:
            all_repos.extend(AI_ML_REPOS)
        if categories is None or "security" in categories:
            all_repos.extend(SECURITY_REPOS)
        if categories is None or "compliance" in categories:
            all_repos.extend(COMPLIANCE_REPOS)

        results: dict[str, list[Issue]] = {}

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning repositories...", total=len(all_repos))

            for repo in all_repos:
                progress.update(task, description=f"Scanning {repo}...")

                # Get issues using direct endpoint (more reliable)
                issues = self.get_repo_issues(repo)

                # Score and categorize each issue
                for issue in issues:
                    issue.score = self.score_issue(issue)
                    issue.category = self.categorize_repo(repo)

                # Filter to high-value issues only
                high_value_issues = [i for i in issues if i.score >= 20]

                if high_value_issues:
                    results[repo] = high_value_issues
                    self.save_issues(high_value_issues)

                self.log_scan(repo, len(high_value_issues))
                progress.advance(task)

                # Small delay to be nice to GitHub API
                time.sleep(0.5)

        return results

    def get_top_issues(self, limit: int = 50) -> list[Issue]:
        """Get top scored issues from database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT repo, number, title, url, labels, created_at, updated_at,
                   comments, state, author, body, score, category
            FROM issues
            WHERE state = 'open'
            ORDER BY score DESC
            LIMIT ?
        """, (limit,))

        issues = []
        for row in cursor.fetchall():
            issues.append(Issue(
                repo=row[0],
                number=row[1],
                title=row[2],
                url=row[3],
                labels=json.loads(row[4]),
                created_at=datetime.fromisoformat(row[5]),
                updated_at=datetime.fromisoformat(row[6]),
                comments=row[7],
                state=row[8],
                author=row[9],
                body=row[10],
                score=row[11],
                category=row[12],
            ))

        conn.close()
        return issues

    def display_results(self, issues: list[Issue]) -> None:
        """Display issues in a formatted table."""
        table = Table(title="Top Contribution Opportunities", show_lines=True)
        table.add_column("Score", style="cyan", width=6)
        table.add_column("Category", style="magenta", width=10)
        table.add_column("Repository", style="green", width=30)
        table.add_column("Issue", style="white", width=50)
        table.add_column("Labels", style="yellow", width=20)
        table.add_column("Comments", style="blue", width=8)

        for issue in issues[:30]:
            labels_str = ", ".join(issue.labels[:3])
            if len(issue.labels) > 3:
                labels_str += "..."

            table.add_row(
                f"{issue.score:.0f}",
                issue.category,
                issue.repo,
                f"#{issue.number}: {issue.title[:45]}...",
                labels_str,
                str(issue.comments),
            )

        console.print(table)

    def generate_report(self, issues: list[Issue], output_path: Path) -> None:
        """Generate a markdown report of top issues."""
        output_path.parent.mkdir(parents=True, exist_ok=True)

        report = f"""# Issue Radar Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary
- Total issues found: {len(issues)}
- AI/ML issues: {len([i for i in issues if i.category == 'AI/ML'])}
- Security issues: {len([i for i in issues if i.category == 'Security'])}
- Compliance issues: {len([i for i in issues if i.category == 'Compliance'])}

## Top 30 Contribution Opportunities

| Score | Category | Repository | Issue | Labels |
|-------|----------|------------|-------|--------|
"""
        for issue in issues[:30]:
            labels = ", ".join(issue.labels[:2])
            report += f"| {issue.score:.0f} | {issue.category} | {issue.repo} | [#{issue.number}]({issue.url}): {issue.title[:40]}... | {labels} |\n"

        report += """

## Next Steps
1. Review issues above and pick 3-5 to work on
2. Check issue comments for any existing work
3. Comment on the issue before starting work
4. Submit quality PRs with tests and documentation

---
*Generated by Issue Radar - Ahmed Adel Bakr Alderai*
"""

        output_path.write_text(report)
        console.print(f"[green]Report saved to {output_path}[/green]")

    def run_continuous(self, interval_hours: int = 4) -> None:
        """Run issue radar continuously for 24-hour mode."""
        console.print("[bold green]Starting 24-hour continuous issue hunting mode...[/bold green]")

        scan_count = 0
        while True:
            scan_count += 1
            console.print(f"\n[bold cyan]===== Scan #{scan_count} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} =====[/bold cyan]")

            # Scan all repos
            results = self.scan_all_repos()

            # Get and display top issues
            top_issues = self.get_top_issues(50)
            self.display_results(top_issues)

            # Generate report
            report_path = Path(f"reports/issue_radar_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
            self.generate_report(top_issues, report_path)

            # Stats
            total_issues = sum(len(issues) for issues in results.values())
            console.print(f"\n[green]Scan complete: {total_issues} high-value issues found across {len(results)} repos[/green]")
            console.print(f"[yellow]Next scan in {interval_hours} hours...[/yellow]")

            # Sleep until next scan
            time.sleep(interval_hours * 3600)


def main() -> None:
    """Main entry point."""
    import typer

    app = typer.Typer(help="Issue Radar - Find GitHub contribution opportunities")

    @app.command()
    def scan(
        categories: Optional[str] = typer.Option(None, help="Categories: ai_ml,security,compliance"),
        continuous: bool = typer.Option(False, help="Run in 24-hour continuous mode"),
        interval: int = typer.Option(4, help="Hours between scans in continuous mode"),
    ) -> None:
        """Scan repositories for contribution opportunities."""
        radar = IssueRadar()

        cats = categories.split(",") if categories else None

        if continuous:
            radar.run_continuous(interval)
        else:
            results = radar.scan_all_repos(cats)
            top_issues = radar.get_top_issues(50)
            radar.display_results(top_issues)

            report_path = Path(f"reports/issue_radar_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
            radar.generate_report(top_issues, report_path)

    @app.command()
    def report(
        limit: int = typer.Option(30, help="Number of issues to show"),
    ) -> None:
        """Show top issues from database."""
        radar = IssueRadar()
        top_issues = radar.get_top_issues(limit)
        radar.display_results(top_issues)

    app()


if __name__ == "__main__":
    main()
