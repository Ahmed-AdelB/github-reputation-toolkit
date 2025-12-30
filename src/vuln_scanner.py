#!/usr/bin/env python3
"""
Vulnerability Scanner - Find security issues in AI/ML and Security projects

Targets CVE hunting and security vulnerability discovery for reputation building.

Author: Ahmed Adel Bakr Alderai
"""

import json
import os
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import httpx
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

load_dotenv()

console = Console()


@dataclass
class SecurityFinding:
    """Represents a potential security finding."""

    repo: str
    file_path: str
    line_number: int
    finding_type: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    cwe_id: Optional[str] = None
    evidence: str = ""
    confidence: str = "medium"  # high, medium, low


@dataclass
class VulnScanner:
    """Scans repositories for potential security vulnerabilities."""

    github_token: str = field(default_factory=lambda: os.getenv("GITHUB_TOKEN", ""))
    db_path: Path = field(default_factory=lambda: Path("data/vulns.db"))

    # Common vulnerability patterns in Python code
    VULN_PATTERNS: dict = field(default_factory=lambda: {
        "sql_injection": {
            "patterns": [
                r'execute\s*\(\s*["\'].*%.*["\']',
                r'execute\s*\(\s*f["\']',
                r'\.format\s*\(.*\).*execute',
                r'cursor\.execute\s*\(\s*["\'].*\+',
            ],
            "cwe": "CWE-89",
            "severity": "critical",
            "title": "Potential SQL Injection",
        },
        "command_injection": {
            "patterns": [
                r'os\.system\s*\(',
                r'subprocess\.call\s*\([^,\]]*shell\s*=\s*True',
                r'subprocess\.run\s*\([^,\]]*shell\s*=\s*True',
                r'eval\s*\(',
                r'exec\s*\(',
            ],
            "cwe": "CWE-78",
            "severity": "critical",
            "title": "Potential Command Injection",
        },
        "path_traversal": {
            "patterns": [
                r'open\s*\([^)]*\+[^)]*\)',
                r'\.\./',
                r'os\.path\.join\s*\([^)]*request\.',
            ],
            "cwe": "CWE-22",
            "severity": "high",
            "title": "Potential Path Traversal",
        },
        "hardcoded_secrets": {
            "patterns": [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'api_key\s*=\s*["\'][^"\']+["\']',
                r'secret\s*=\s*["\'][^"\']+["\']',
                r'token\s*=\s*["\'][a-zA-Z0-9]{20,}["\']',
                r'AWS_SECRET_ACCESS_KEY\s*=\s*["\']',
            ],
            "cwe": "CWE-798",
            "severity": "high",
            "title": "Hardcoded Credentials",
        },
        "insecure_deserialization": {
            "patterns": [
                r'pickle\.load\s*\(',
                r'pickle\.loads\s*\(',
                r'yaml\.load\s*\([^)]*\)',  # without Loader
                r'marshal\.loads?\s*\(',
            ],
            "cwe": "CWE-502",
            "severity": "high",
            "title": "Insecure Deserialization",
        },
        "ssrf": {
            "patterns": [
                r'requests\.(get|post|put|delete)\s*\([^)]*request\.',
                r'urllib\.request\.urlopen\s*\([^)]*\+',
                r'httpx\.(get|post)\s*\([^)]*request\.',
            ],
            "cwe": "CWE-918",
            "severity": "high",
            "title": "Potential SSRF",
        },
        "xxe": {
            "patterns": [
                r'etree\.parse\s*\(',
                r'xml\.etree\.ElementTree\.parse',
                r'xml\.dom\.minidom\.parse',
            ],
            "cwe": "CWE-611",
            "severity": "medium",
            "title": "Potential XXE",
        },
        "weak_crypto": {
            "patterns": [
                r'hashlib\.md5\s*\(',
                r'hashlib\.sha1\s*\(',
                r'DES\s*\.',
                r'RC4\s*\.',
            ],
            "cwe": "CWE-327",
            "severity": "medium",
            "title": "Weak Cryptographic Algorithm",
        },
        "insecure_random": {
            "patterns": [
                r'random\.random\s*\(',
                r'random\.randint\s*\(',
                r'random\.choice\s*\(',
            ],
            "cwe": "CWE-330",
            "severity": "low",
            "title": "Insecure Random Number Generation",
        },
        "debug_enabled": {
            "patterns": [
                r'DEBUG\s*=\s*True',
                r'app\.run\s*\([^)]*debug\s*=\s*True',
                r'FLASK_DEBUG\s*=\s*["\']?1',
            ],
            "cwe": "CWE-489",
            "severity": "medium",
            "title": "Debug Mode Enabled",
        },
    })

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
        """Initialize SQLite database for storing findings."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY,
                repo TEXT NOT NULL,
                file_path TEXT NOT NULL,
                line_number INTEGER NOT NULL,
                finding_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                cwe_id TEXT,
                evidence TEXT,
                confidence TEXT DEFAULT 'medium',
                discovered_at TEXT NOT NULL,
                status TEXT DEFAULT 'new',
                UNIQUE(repo, file_path, line_number, finding_type)
            )
        """)
        conn.commit()
        conn.close()

    def scan_file_content(self, repo: str, file_path: str, content: str) -> list[SecurityFinding]:
        """Scan file content for security vulnerabilities."""
        findings: list[SecurityFinding] = []
        lines = content.split('\n')

        for vuln_type, config in self.VULN_PATTERNS.items():
            for pattern in config["patterns"]:
                compiled = re.compile(pattern, re.IGNORECASE)
                for line_num, line in enumerate(lines, 1):
                    if compiled.search(line):
                        # Skip if in comment or docstring
                        stripped = line.strip()
                        if stripped.startswith('#') or stripped.startswith('"""') or stripped.startswith("'''"):
                            continue

                        findings.append(SecurityFinding(
                            repo=repo,
                            file_path=file_path,
                            line_number=line_num,
                            finding_type=vuln_type,
                            severity=config["severity"],
                            title=config["title"],
                            description=f"Pattern matched: {pattern}",
                            cwe_id=config.get("cwe"),
                            evidence=line.strip()[:200],
                            confidence="medium" if len(config["patterns"]) > 1 else "high",
                        ))

        return findings

    def get_repo_files(self, repo: str, path: str = "", extensions: list[str] = None) -> list[dict]:
        """Get list of files in a repository."""
        if extensions is None:
            extensions = [".py", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg"]

        files: list[dict] = []
        try:
            resp = self.client.get(f"/repos/{repo}/contents/{path}")
            if resp.status_code == 200:
                for item in resp.json():
                    if item["type"] == "file":
                        if any(item["name"].endswith(ext) for ext in extensions):
                            files.append(item)
                    elif item["type"] == "dir" and not item["name"].startswith('.'):
                        # Recursively get files from subdirectories (limited depth)
                        if path.count('/') < 3:
                            files.extend(self.get_repo_files(repo, item["path"], extensions))
        except Exception as e:
            console.print(f"[red]Error listing files in {repo}/{path}: {e}[/red]")

        return files

    def scan_repo(self, repo: str) -> list[SecurityFinding]:
        """Scan a repository for security vulnerabilities."""
        console.print(f"[cyan]Scanning {repo}...[/cyan]")
        all_findings: list[SecurityFinding] = []

        # Get Python files
        files = self.get_repo_files(repo, extensions=[".py"])

        for file_info in files[:50]:  # Limit to 50 files per repo
            try:
                resp = self.client.get(file_info["download_url"].replace("https://api.github.com", ""))
                if resp.status_code == 200:
                    # Fetch raw content
                    raw_resp = httpx.get(file_info["download_url"], timeout=30)
                    if raw_resp.status_code == 200:
                        findings = self.scan_file_content(repo, file_info["path"], raw_resp.text)
                        all_findings.extend(findings)
            except Exception as e:
                console.print(f"[yellow]Error scanning {file_info['path']}: {e}[/yellow]")

        return all_findings

    def save_findings(self, findings: list[SecurityFinding]) -> int:
        """Save findings to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        new_count = 0

        for finding in findings:
            try:
                cursor.execute("""
                    INSERT OR IGNORE INTO findings
                    (repo, file_path, line_number, finding_type, severity,
                     title, description, cwe_id, evidence, confidence, discovered_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    finding.repo,
                    finding.file_path,
                    finding.line_number,
                    finding.finding_type,
                    finding.severity,
                    finding.title,
                    finding.description,
                    finding.cwe_id,
                    finding.evidence,
                    finding.confidence,
                    datetime.now().isoformat(),
                ))
                new_count += cursor.rowcount
            except Exception as e:
                console.print(f"[red]Error saving finding: {e}[/red]")

        conn.commit()
        conn.close()
        return new_count

    def display_findings(self, findings: list[SecurityFinding]) -> None:
        """Display findings in a table."""
        table = Table(title="Security Findings", show_lines=True)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Type", width=20)
        table.add_column("Repository", width=25)
        table.add_column("File:Line", width=30)
        table.add_column("Evidence", width=40)

        severity_colors = {
            "critical": "red",
            "high": "orange1",
            "medium": "yellow",
            "low": "green",
            "info": "blue",
        }

        for finding in findings[:30]:
            color = severity_colors.get(finding.severity, "white")
            table.add_row(
                f"[{color}]{finding.severity.upper()}[/{color}]",
                finding.finding_type,
                finding.repo,
                f"{finding.file_path}:{finding.line_number}",
                finding.evidence[:35] + "..." if len(finding.evidence) > 35 else finding.evidence,
            )

        console.print(table)

    def generate_report(self, findings: list[SecurityFinding], output_path: Path) -> None:
        """Generate a markdown report of findings."""
        output_path.parent.mkdir(parents=True, exist_ok=True)

        critical = [f for f in findings if f.severity == "critical"]
        high = [f for f in findings if f.severity == "high"]
        medium = [f for f in findings if f.severity == "medium"]
        low = [f for f in findings if f.severity == "low"]

        report = f"""# Security Scan Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary
- **Total Findings**: {len(findings)}
- **Critical**: {len(critical)}
- **High**: {len(high)}
- **Medium**: {len(medium)}
- **Low**: {len(low)}

## Critical Findings

"""
        for f in critical[:10]:
            report += f"""### {f.title} in {f.repo}
- **File**: `{f.file_path}:{f.line_number}`
- **CWE**: {f.cwe_id or 'N/A'}
- **Evidence**: `{f.evidence}`

"""

        report += """## High Severity Findings

"""
        for f in high[:10]:
            report += f"""### {f.title} in {f.repo}
- **File**: `{f.file_path}:{f.line_number}`
- **CWE**: {f.cwe_id or 'N/A'}
- **Evidence**: `{f.evidence}`

"""

        report += """
---
*Generated by Vulnerability Scanner - Ahmed Adel Bakr Alderai*
"""

        output_path.write_text(report)
        console.print(f"[green]Report saved to {output_path}[/green]")


def main() -> None:
    """Main entry point."""
    import typer

    app = typer.Typer(help="Vulnerability Scanner - Find security issues in repositories")

    @app.command()
    def scan(
        repos: str = typer.Argument(..., help="Comma-separated list of repos (owner/name)"),
    ) -> None:
        """Scan repositories for security vulnerabilities."""
        scanner = VulnScanner()
        repo_list = [r.strip() for r in repos.split(",")]

        all_findings: list[SecurityFinding] = []
        for repo in repo_list:
            findings = scanner.scan_repo(repo)
            all_findings.extend(findings)
            console.print(f"[green]Found {len(findings)} potential issues in {repo}[/green]")

        scanner.save_findings(all_findings)
        scanner.display_findings(all_findings)

        report_path = Path(f"reports/vuln_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
        scanner.generate_report(all_findings, report_path)

    @app.command()
    def report() -> None:
        """Show findings from database."""
        scanner = VulnScanner()
        conn = sqlite3.connect(scanner.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT repo, file_path, line_number, finding_type, severity, title, evidence
            FROM findings
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END
            LIMIT 50
        """)

        findings = [SecurityFinding(
            repo=row[0],
            file_path=row[1],
            line_number=row[2],
            finding_type=row[3],
            severity=row[4],
            title=row[5],
            description="",
            evidence=row[6] or "",
        ) for row in cursor.fetchall()]

        conn.close()
        scanner.display_findings(findings)

    app()


if __name__ == "__main__":
    main()
