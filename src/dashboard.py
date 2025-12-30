#!/usr/bin/env python3
"""
Analytics Dashboard - Visualize GitHub contribution metrics

Built with Streamlit for easy deployment.

Author: Ahmed Adel Bakr Alderai
"""

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

try:
    import streamlit as st
    import plotly.express as px
    import plotly.graph_objects as go
    import pandas as pd
    STREAMLIT_AVAILABLE = True
except ImportError:
    STREAMLIT_AVAILABLE = False
    print("Streamlit not installed. Run: pip install streamlit plotly pandas")


def load_issues_data(db_path: Path) -> pd.DataFrame:
    """Load issues from the database."""
    if not db_path.exists():
        return pd.DataFrame()

    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("""
        SELECT repo, number, title, labels, created_at, updated_at,
               comments, state, score, category, discovered_at
        FROM issues
        WHERE state = 'open'
        ORDER BY score DESC
    """, conn)
    conn.close()

    if not df.empty:
        df['created_at'] = pd.to_datetime(df['created_at'])
        df['updated_at'] = pd.to_datetime(df['updated_at'])
        df['discovered_at'] = pd.to_datetime(df['discovered_at'])

    return df


def load_vuln_data(db_path: Path) -> pd.DataFrame:
    """Load vulnerability findings from database."""
    if not db_path.exists():
        return pd.DataFrame()

    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("""
        SELECT repo, file_path, finding_type, severity, title,
               cwe_id, confidence, discovered_at, status
        FROM findings
        ORDER BY discovered_at DESC
    """, conn)
    conn.close()

    if not df.empty:
        df['discovered_at'] = pd.to_datetime(df['discovered_at'])

    return df


def main():
    """Main dashboard application."""
    if not STREAMLIT_AVAILABLE:
        print("Please install streamlit: pip install streamlit plotly pandas")
        return

    st.set_page_config(
        page_title="GitHub Reputation Toolkit",
        page_icon="🚀",
        layout="wide",
    )

    st.title("🚀 GitHub Reputation Toolkit Dashboard")
    st.markdown("*Tracking contribution opportunities and security findings*")

    # Sidebar
    st.sidebar.header("Navigation")
    page = st.sidebar.selectbox(
        "Select Page",
        ["Overview", "Issue Radar", "Security Findings", "Metrics"]
    )

    # Load data
    issues_db = Path("data/issues.db")
    vulns_db = Path("data/vulns.db")

    issues_df = load_issues_data(issues_db)
    vulns_df = load_vuln_data(vulns_db)

    if page == "Overview":
        render_overview(issues_df, vulns_df)
    elif page == "Issue Radar":
        render_issues(issues_df)
    elif page == "Security Findings":
        render_vulns(vulns_df)
    elif page == "Metrics":
        render_metrics(issues_df, vulns_df)


def render_overview(issues_df: pd.DataFrame, vulns_df: pd.DataFrame):
    """Render overview page."""
    st.header("📊 Overview")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Issues Found", len(issues_df))
    with col2:
        high_score = len(issues_df[issues_df['score'] >= 25]) if not issues_df.empty else 0
        st.metric("High-Value Issues", high_score)
    with col3:
        st.metric("Security Findings", len(vulns_df))
    with col4:
        critical = len(vulns_df[vulns_df['severity'] == 'critical']) if not vulns_df.empty else 0
        st.metric("Critical Vulns", critical, delta_color="inverse")

    st.subheader("📈 Issues by Category")
    if not issues_df.empty:
        category_counts = issues_df['category'].value_counts()
        fig = px.pie(
            values=category_counts.values,
            names=category_counts.index,
            title="Issue Distribution by Category"
        )
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("🔥 Top 10 Contribution Opportunities")
    if not issues_df.empty:
        top_issues = issues_df.head(10)[['score', 'category', 'repo', 'number', 'title']]
        st.dataframe(top_issues, use_container_width=True)


def render_issues(issues_df: pd.DataFrame):
    """Render issues page."""
    st.header("🔍 Issue Radar")

    if issues_df.empty:
        st.warning("No issues found. Run the issue radar scanner first.")
        return

    # Filters
    col1, col2, col3 = st.columns(3)
    with col1:
        categories = ["All"] + list(issues_df['category'].unique())
        category_filter = st.selectbox("Category", categories)
    with col2:
        min_score = st.slider("Minimum Score", 0, 100, 20)
    with col3:
        sort_by = st.selectbox("Sort By", ["score", "updated_at", "comments"])

    # Apply filters
    filtered = issues_df.copy()
    if category_filter != "All":
        filtered = filtered[filtered['category'] == category_filter]
    filtered = filtered[filtered['score'] >= min_score]
    filtered = filtered.sort_values(sort_by, ascending=False)

    st.write(f"Showing {len(filtered)} issues")

    # Display issues
    for _, issue in filtered.head(20).iterrows():
        with st.expander(f"[{issue['score']:.0f}] {issue['repo']} #{issue['number']}: {issue['title'][:60]}..."):
            st.write(f"**Category:** {issue['category']}")
            st.write(f"**Labels:** {issue['labels']}")
            st.write(f"**Comments:** {issue['comments']}")
            st.write(f"**Last Updated:** {issue['updated_at']}")

    # Score distribution chart
    st.subheader("Score Distribution")
    fig = px.histogram(
        issues_df,
        x="score",
        nbins=20,
        title="Issue Score Distribution"
    )
    st.plotly_chart(fig, use_container_width=True)


def render_vulns(vulns_df: pd.DataFrame):
    """Render security findings page."""
    st.header("🔒 Security Findings")

    if vulns_df.empty:
        st.warning("No security findings. Run the vulnerability scanner first.")
        return

    # Summary
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        critical = len(vulns_df[vulns_df['severity'] == 'critical'])
        st.metric("Critical", critical)
    with col2:
        high = len(vulns_df[vulns_df['severity'] == 'high'])
        st.metric("High", high)
    with col3:
        medium = len(vulns_df[vulns_df['severity'] == 'medium'])
        st.metric("Medium", medium)
    with col4:
        low = len(vulns_df[vulns_df['severity'] == 'low'])
        st.metric("Low", low)

    # Severity filter
    severity_filter = st.multiselect(
        "Filter by Severity",
        ["critical", "high", "medium", "low"],
        default=["critical", "high"]
    )

    filtered = vulns_df[vulns_df['severity'].isin(severity_filter)]

    # Findings by type
    st.subheader("Findings by Type")
    type_counts = filtered['finding_type'].value_counts()
    fig = px.bar(
        x=type_counts.index,
        y=type_counts.values,
        title="Security Findings by Type"
    )
    st.plotly_chart(fig, use_container_width=True)

    # Findings table
    st.subheader("Detailed Findings")
    st.dataframe(
        filtered[['severity', 'finding_type', 'repo', 'file_path', 'title']].head(50),
        use_container_width=True
    )


def render_metrics(issues_df: pd.DataFrame, vulns_df: pd.DataFrame):
    """Render metrics page."""
    st.header("📈 Contribution Metrics")

    # Issues over time
    if not issues_df.empty:
        st.subheader("Issues Discovered Over Time")
        issues_df['date'] = issues_df['discovered_at'].dt.date
        daily_counts = issues_df.groupby('date').size().reset_index(name='count')
        fig = px.line(daily_counts, x='date', y='count', title="Daily Issue Discovery")
        st.plotly_chart(fig, use_container_width=True)

        # Top repos
        st.subheader("Top Repositories by Issue Count")
        repo_counts = issues_df['repo'].value_counts().head(10)
        fig = px.bar(
            x=repo_counts.values,
            y=repo_counts.index,
            orientation='h',
            title="Issues by Repository"
        )
        st.plotly_chart(fig, use_container_width=True)

    # Goals progress
    st.subheader("🎯 6-Month Goals Progress")
    goals = {
        "Issues Submitted": {"current": len(issues_df), "target": 200},
        "PRs Merged": {"current": 0, "target": 50},
        "Projects Contributed": {"current": issues_df['repo'].nunique() if not issues_df.empty else 0, "target": 30},
        "CVEs Discovered": {"current": len(vulns_df[vulns_df['severity'] == 'critical']) if not vulns_df.empty else 0, "target": 3},
    }

    for goal, values in goals.items():
        progress = min(values["current"] / values["target"], 1.0)
        st.write(f"**{goal}**: {values['current']} / {values['target']}")
        st.progress(progress)


if __name__ == "__main__":
    main()
