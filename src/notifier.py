#!/usr/bin/env python3
"""
Notifier - Send weekly digest notifications via Discord/Email

Author: Ahmed Adel Bakr Alderai
"""

import json
import os
import smtplib
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

import httpx
from dotenv import load_dotenv
from rich.console import Console

load_dotenv()

console = Console()


@dataclass
class DigestData:
    """Data for weekly digest."""

    total_issues: int = 0
    high_value_issues: int = 0
    new_issues_this_week: int = 0
    top_repos: list[tuple[str, int]] = field(default_factory=list)
    top_issues: list[dict] = field(default_factory=list)
    security_findings: int = 0
    critical_vulns: int = 0


@dataclass
class Notifier:
    """Send notifications via Discord webhook or Email."""

    discord_webhook_url: str = field(
        default_factory=lambda: os.getenv("DISCORD_WEBHOOK_URL", "")
    )
    smtp_server: str = field(default_factory=lambda: os.getenv("SMTP_SERVER", ""))
    smtp_port: int = field(default_factory=lambda: int(os.getenv("SMTP_PORT", "587")))
    smtp_user: str = field(default_factory=lambda: os.getenv("SMTP_USER", ""))
    smtp_password: str = field(default_factory=lambda: os.getenv("SMTP_PASSWORD", ""))
    email_to: str = field(default_factory=lambda: os.getenv("EMAIL_TO", ""))
    issues_db: Path = field(default_factory=lambda: Path("data/issues.db"))
    vulns_db: Path = field(default_factory=lambda: Path("data/vulns.db"))

    def gather_digest_data(self) -> DigestData:
        """Gather data for the weekly digest."""
        data = DigestData()

        # Load issues data
        if self.issues_db.exists():
            conn = sqlite3.connect(self.issues_db)
            cursor = conn.cursor()

            # Total issues
            cursor.execute("SELECT COUNT(*) FROM issues WHERE state = 'open'")
            data.total_issues = cursor.fetchone()[0]

            # High value issues (score >= 25)
            cursor.execute("SELECT COUNT(*) FROM issues WHERE state = 'open' AND score >= 25")
            data.high_value_issues = cursor.fetchone()[0]

            # New issues this week
            week_ago = (datetime.now() - timedelta(days=7)).isoformat()
            cursor.execute(
                "SELECT COUNT(*) FROM issues WHERE discovered_at > ?",
                (week_ago,)
            )
            data.new_issues_this_week = cursor.fetchone()[0]

            # Top repos
            cursor.execute("""
                SELECT repo, COUNT(*) as count
                FROM issues WHERE state = 'open'
                GROUP BY repo ORDER BY count DESC LIMIT 5
            """)
            data.top_repos = cursor.fetchall()

            # Top issues
            cursor.execute("""
                SELECT repo, number, title, score, category
                FROM issues WHERE state = 'open'
                ORDER BY score DESC LIMIT 10
            """)
            for row in cursor.fetchall():
                data.top_issues.append({
                    "repo": row[0],
                    "number": row[1],
                    "title": row[2],
                    "score": row[3],
                    "category": row[4],
                })

            conn.close()

        # Load vulnerability data
        if self.vulns_db.exists():
            conn = sqlite3.connect(self.vulns_db)
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM findings")
            data.security_findings = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM findings WHERE severity = 'critical'")
            data.critical_vulns = cursor.fetchone()[0]

            conn.close()

        return data

    def format_discord_message(self, data: DigestData) -> dict:
        """Format digest data for Discord webhook."""
        top_issues_text = ""
        for issue in data.top_issues[:5]:
            top_issues_text += f"• [{issue['score']}] {issue['repo']} #{issue['number']}: {issue['title'][:40]}...\n"

        top_repos_text = ""
        for repo, count in data.top_repos:
            top_repos_text += f"• {repo}: {count} issues\n"

        return {
            "embeds": [
                {
                    "title": "📊 Weekly GitHub Reputation Digest",
                    "description": f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                    "color": 0x00D9FF,
                    "fields": [
                        {
                            "name": "📈 Issue Statistics",
                            "value": f"**Total Open Issues:** {data.total_issues}\n"
                                    f"**High-Value (25+):** {data.high_value_issues}\n"
                                    f"**New This Week:** {data.new_issues_this_week}",
                            "inline": True,
                        },
                        {
                            "name": "🔒 Security",
                            "value": f"**Total Findings:** {data.security_findings}\n"
                                    f"**Critical Vulns:** {data.critical_vulns}",
                            "inline": True,
                        },
                        {
                            "name": "🏆 Top Repositories",
                            "value": top_repos_text or "No data",
                            "inline": False,
                        },
                        {
                            "name": "🎯 Top Contribution Opportunities",
                            "value": top_issues_text or "No issues found",
                            "inline": False,
                        },
                    ],
                    "footer": {
                        "text": "GitHub Reputation Toolkit - Ahmed Adel Bakr Alderai"
                    },
                }
            ]
        }

    def format_email_html(self, data: DigestData) -> str:
        """Format digest data for email."""
        top_issues_html = ""
        for issue in data.top_issues[:10]:
            url = f"https://github.com/{issue['repo']}/issues/{issue['number']}"
            top_issues_html += f"""
            <tr>
                <td>{issue['score']}</td>
                <td>{issue['category']}</td>
                <td>{issue['repo']}</td>
                <td><a href="{url}">#{issue['number']}: {issue['title'][:50]}...</a></td>
            </tr>
            """

        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }}
                h1 {{ color: #00D9FF; }}
                .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
                .stat-box {{ background: #f0f0f0; padding: 15px; border-radius: 8px; text-align: center; }}
                .stat-value {{ font-size: 24px; font-weight: bold; color: #333; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
                th {{ background: #00D9FF; color: white; }}
            </style>
        </head>
        <body>
            <h1>📊 Weekly GitHub Reputation Digest</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>

            <div class="stats">
                <div class="stat-box">
                    <div class="stat-value">{data.total_issues}</div>
                    <div>Total Issues</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{data.high_value_issues}</div>
                    <div>High-Value</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{data.new_issues_this_week}</div>
                    <div>New This Week</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{data.critical_vulns}</div>
                    <div>Critical Vulns</div>
                </div>
            </div>

            <h2>🎯 Top Contribution Opportunities</h2>
            <table>
                <tr>
                    <th>Score</th>
                    <th>Category</th>
                    <th>Repository</th>
                    <th>Issue</th>
                </tr>
                {top_issues_html}
            </table>

            <hr>
            <p><em>Generated by GitHub Reputation Toolkit - Ahmed Adel Bakr Alderai</em></p>
        </body>
        </html>
        """

    def send_discord(self, data: DigestData) -> bool:
        """Send digest via Discord webhook."""
        if not self.discord_webhook_url:
            console.print("[yellow]Discord webhook URL not configured[/yellow]")
            return False

        try:
            payload = self.format_discord_message(data)
            response = httpx.post(
                self.discord_webhook_url,
                json=payload,
                timeout=30,
            )
            if response.status_code in (200, 204):
                console.print("[green]Discord notification sent successfully[/green]")
                return True
            else:
                console.print(f"[red]Discord error: {response.status_code}[/red]")
                return False
        except Exception as e:
            console.print(f"[red]Discord error: {e}[/red]")
            return False

    def send_email(self, data: DigestData) -> bool:
        """Send digest via email."""
        if not all([self.smtp_server, self.smtp_user, self.email_to]):
            console.print("[yellow]Email configuration incomplete[/yellow]")
            return False

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"📊 Weekly GitHub Reputation Digest - {datetime.now().strftime('%Y-%m-%d')}"
            msg["From"] = self.smtp_user
            msg["To"] = self.email_to

            html_content = self.format_email_html(data)
            msg.attach(MIMEText(html_content, "html"))

            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.sendmail(self.smtp_user, self.email_to, msg.as_string())

            console.print("[green]Email sent successfully[/green]")
            return True
        except Exception as e:
            console.print(f"[red]Email error: {e}[/red]")
            return False

    def send_digest(self) -> None:
        """Send weekly digest via all configured channels."""
        console.print("[cyan]Gathering digest data...[/cyan]")
        data = self.gather_digest_data()

        console.print(f"[green]Found {data.total_issues} total issues, {data.high_value_issues} high-value[/green]")

        if self.discord_webhook_url:
            self.send_discord(data)

        if self.smtp_server:
            self.send_email(data)


def main() -> None:
    """Main entry point."""
    import typer

    app = typer.Typer(help="Notifier - Send weekly digest notifications")

    @app.command()
    def send(
        discord: bool = typer.Option(True, help="Send via Discord"),
        email: bool = typer.Option(False, help="Send via Email"),
    ) -> None:
        """Send weekly digest notification."""
        notifier = Notifier()
        data = notifier.gather_digest_data()

        if discord and notifier.discord_webhook_url:
            notifier.send_discord(data)
        if email:
            notifier.send_email(data)

    @app.command()
    def preview() -> None:
        """Preview digest data without sending."""
        notifier = Notifier()
        data = notifier.gather_digest_data()

        console.print("\n[bold]Weekly Digest Preview[/bold]\n")
        console.print(f"Total Issues: {data.total_issues}")
        console.print(f"High-Value Issues: {data.high_value_issues}")
        console.print(f"New This Week: {data.new_issues_this_week}")
        console.print(f"Security Findings: {data.security_findings}")
        console.print(f"Critical Vulns: {data.critical_vulns}")

        console.print("\n[bold]Top Issues:[/bold]")
        for issue in data.top_issues[:5]:
            console.print(f"  [{issue['score']}] {issue['repo']} #{issue['number']}: {issue['title'][:50]}...")

    app()


if __name__ == "__main__":
    main()
