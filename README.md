# 🚀 GitHub Reputation Toolkit

[![CI](https://github.com/Ahmed-AdelB/github-reputation-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/Ahmed-AdelB/github-reputation-toolkit/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

Automated tools for building GitHub reputation through strategic open source contributions. Focuses on **AI/ML**, **Security**, and **Compliance** projects.

## Features

- **🔍 Issue Radar** - Automated discovery of contribution opportunities across 60+ repositories
- **🔒 Vulnerability Scanner** - Find security issues for CVE hunting
- **📊 Metrics Collector** - Track GitHub profile and contribution statistics
- **📈 Analytics Dashboard** - Visualize progress with Streamlit
- **📬 Notifier** - Weekly digest via Discord/Email
- **⚡ CI/CD Templates** - Ready-to-use GitHub Actions workflows

## Quick Start

```bash
# Clone the repository
git clone https://github.com/Ahmed-AdelB/github-reputation-toolkit.git
cd github-reputation-toolkit

# Install dependencies
pip install -e .

# Set up GitHub token
export GITHUB_TOKEN="your_token_here"

# Run issue radar
python -m src.issue_radar scan

# Run vulnerability scanner
python -m src.vuln_scanner scan "owner/repo"

# Start dashboard
streamlit run src/dashboard.py
```

## Target Repositories

### AI/ML (25 repos)
- LangChain, Transformers, OpenAI SDK, Anthropic SDK
- PyTorch, Keras, scikit-learn, JAX
- FastAPI, Pydantic, httpx
- MLflow, Ray, Airflow

### Security (20 repos)
- OWASP projects (CheatSheets, WSTG, ASVS)
- Bandit, Safety, Trivy, Semgrep
- TruffleHog, Gitleaks, detect-secrets

### Compliance (15 repos)
- OPA, Gatekeeper, Conftest
- Checkov, tfsec, Terrascan
- kube-bench, kube-hunter, Polaris

## Tools

### Issue Radar

Scans repositories for high-value contribution opportunities:

```bash
# Single scan
python -m src.issue_radar scan

# Filter by category
python -m src.issue_radar scan --categories "ai_ml,security"

# 24-hour continuous mode
python -m src.issue_radar scan --continuous --interval 4
```

### Vulnerability Scanner

Finds potential security vulnerabilities for CVE hunting:

```bash
# Scan specific repos
python -m src.vuln_scanner scan "langchain-ai/langchain,tiangolo/fastapi"

# View findings
python -m src.vuln_scanner report
```

### Metrics Collector

Track your GitHub profile and contribution metrics:

```bash
# Collect all metrics
python -m src.collector collect

# Weekly summary
python -m src.collector weekly
```

### Notifier

Send weekly digest notifications:

```bash
# Configure in .env
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
SMTP_SERVER=smtp.gmail.com
EMAIL_TO=your@email.com

# Send digest
python -m src.notifier send
```

## Configuration

Create a `.env` file:

```bash
# GitHub
GITHUB_TOKEN=ghp_xxxxx
GITHUB_USERNAME=Ahmed-AdelB

# Notifications
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your@gmail.com
SMTP_PASSWORD=app_password
EMAIL_TO=your@email.com
```

## Dashboard

Run the Streamlit dashboard for visual analytics:

```bash
streamlit run src/dashboard.py
```

Features:
- Issue distribution by category
- Score distribution histogram
- Security findings overview
- Progress towards 6-month goals

## CI/CD Integration

The toolkit includes GitHub Actions workflows:

- **ci.yml** - Lint, type check, test, security scan
- **release.yml** - Build, publish to PyPI, announce

## 6-Month Goals

| Metric | Target |
|--------|--------|
| Issues Submitted | 200+ |
| PRs Merged | 50+ |
| Projects Contributed | 30+ |
| GitHub Followers | 500+ |
| CVEs Discovered | 3+ |

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Run pre-commit hooks: `pre-commit run --all-files`
4. Submit a PR

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

**Ahmed Adel Bakr Alderai**

- GitHub: [@Ahmed-AdelB](https://github.com/Ahmed-AdelB)
- Email: ah.adel.bakr@gmail.com

---

*Built with Python, powered by open source contribution.*
