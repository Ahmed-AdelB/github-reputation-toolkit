"""Tests for issue radar module."""

import pytest
from pathlib import Path
from src.issue_radar import Issue, IssueRadar, AI_ML_REPOS, SECURITY_REPOS
from datetime import datetime, timezone


class TestIssue:
    """Tests for Issue dataclass."""

    def test_issue_creation(self):
        """Test creating an Issue instance."""
        issue = Issue(
            repo="test/repo",
            number=123,
            title="Test issue",
            url="https://github.com/test/repo/issues/123",
            labels=["bug", "help wanted"],
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            comments=5,
            state="open",
            author="testuser",
        )
        assert issue.repo == "test/repo"
        assert issue.number == 123
        assert "bug" in issue.labels


class TestIssueRadar:
    """Tests for IssueRadar class."""

    def test_repo_lists_not_empty(self):
        """Ensure repo lists are populated."""
        assert len(AI_ML_REPOS) > 10
        assert len(SECURITY_REPOS) > 10

    def test_score_issue(self):
        """Test issue scoring logic."""
        radar = IssueRadar(github_token="")

        # High-value issue
        high_value = Issue(
            repo="test/repo",
            number=1,
            title="Good first issue",
            url="https://github.com/test/repo/issues/1",
            labels=["good first issue", "help wanted"],
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            comments=0,
            state="open",
            author="test",
            body="Detailed description " * 50,
        )
        score = radar.score_issue(high_value)
        assert score >= 50  # Should have high score

        # Low-value issue
        low_value = Issue(
            repo="test/repo",
            number=2,
            title="Random issue",
            url="https://github.com/test/repo/issues/2",
            labels=[],
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            comments=100,
            state="open",
            author="test",
        )
        low_score = radar.score_issue(low_value)
        assert low_score < score

    def test_categorize_repo(self):
        """Test repository categorization."""
        radar = IssueRadar(github_token="")

        assert radar.categorize_repo("langchain-ai/langchain") == "AI/ML"
        assert radar.categorize_repo("PyCQA/bandit") == "Security"
        assert radar.categorize_repo("bridgecrewio/checkov") == "Compliance"
        assert radar.categorize_repo("unknown/repo") == "Other"


class TestDatabase:
    """Tests for database operations."""

    def test_init_db(self, tmp_path):
        """Test database initialization."""
        db_path = tmp_path / "test.db"
        radar = IssueRadar(github_token="", db_path=db_path)

        assert db_path.exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
