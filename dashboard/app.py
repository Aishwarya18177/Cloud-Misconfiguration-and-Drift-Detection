import html
import json
import os
import sqlite3
import sys

from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st


# ============================================================
# Project configuration
# ============================================================

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

SUBSCRIPTION_ID = os.getenv(
    "AZURE_SUBSCRIPTION_ID",
    "3295c2de-964f-43f0-8429-6ef55498e26d"
)

RESOURCE_GROUP = os.getenv(
    "AZURE_RESOURCE_GROUP",
    "driftstore"
)

STORAGE_ACCOUNT = os.getenv(
    "AZURE_STORAGE_ACCOUNT",
    "clouddriftlab2026"
)

BASELINE = ROOT / "collector" / "intended_state.json"
DATABASE = ROOT / "database" / "drift_detection.db"


# ============================================================
# Page setup
# ============================================================

st.set_page_config(
    page_title="DriftGuard | Azure Security",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# Dashboard styling
# ============================================================

CSS = """
<style>
:root {
    color-scheme: dark;
    --ink: #e8eef8;
    --muted: #93a6bc;
    --line: #24364d;
    --cyan: #58e0db;
}

.stApp {
    background: #090f1a;
    color: var(--ink);
}

[data-testid="stHeader"] {
    background: #090f1a;
}

/* Keeps the top label below Streamlit's header. */
[data-testid="stMainBlockContainer"] {
    max-width: 1500px;
    padding-top: 5rem !important;
    padding-bottom: 3rem;
}

[data-testid="stSidebar"] {
    background: #0e1726;
    border-right: 1px solid var(--line);
}

[data-testid="stSidebar"] * {
    color: var(--ink);
}

h1, h2, h3, p, label {
    color: var(--ink);
}

h1 {
    font-size: 2rem !important;
    letter-spacing: -1px;
    font-weight: 700 !important;
}

h3 {
    font-size: 1.15rem !important;
}

[data-testid="stCaptionContainer"] p {
    color: var(--muted) !important;
}

[data-testid="stMarkdownContainer"] a {
    color: var(--cyan);
}

.brand {
    display: flex;
    align-items: center;
    gap: 12px;
    margin: 8px 0 32px;
}

.logo {
    border: 1px solid #2a737d;
    background: #10343d;
    color: #65ede2;
    border-radius: 12px;
    padding: 10px;
    font: 700 21px monospace;
}

.brand-name {
    font-size: 21px;
    font-weight: 750;
    letter-spacing: 2px;
}

.brand-sub {
    color: var(--muted);
    font-size: 10px;
    letter-spacing: 2px;
    margin-top: 3px;
}

.eyebrow {
    color: var(--cyan);
    font: 600 11px monospace;
    letter-spacing: 2px;
    text-transform: uppercase;
    margin: 5px 0 12px;
}

.subtle {
    color: var(--muted);
    font-size: 14px;
    line-height: 1.6;
}

.side-label {
    color: #71869f;
    font: 600 10px monospace;
    letter-spacing: 1.8px;
    margin: 28px 0 10px;
}

.side-item {
    border: 1px solid #254352;
    border-radius: 9px;
    padding: 12px;
    background: #122837;
    font-size: 13px;
    color: #79e5df;
}

.side-meta {
    font-size: 12px;
    color: var(--muted);
    line-height: 1.6;
    margin: 14px 0;
    overflow-wrap: anywhere;
}

.side-meta strong {
    display: block;
    color: #d6e3f2;
    font-size: 13px;
    font-weight: 500;
}

.side-note {
    border-top: 1px solid var(--line);
    padding-top: 20px;
    margin-top: 30px;
    color: #93a6bc;
    font-size: 12px;
    line-height: 1.7;
}

.hero {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 22px;
    border: 1px solid #31404d;
    border-radius: 16px;
    background:
        radial-gradient(
            ellipse at 100% 0%,
            #15343d 0%,
            transparent 65%
        ),
        #111d2e;
    padding: 26px 28px;
    margin: 14px 0 20px;
}

.hero h2 {
    font-size: 25px;
    margin: 12px 0 8px;
    letter-spacing: -0.5px;
    line-height: 1.3;
}

.hero p {
    max-width: 640px;
    color: #a4b6c9;
    line-height: 1.7;
    font-size: 14px;
    margin: 0;
}

.pill {
    display: inline-block;
    padding: 5px 10px;
    border-radius: 5px;
    font: 600 10px monospace;
    letter-spacing: 1px;
    border: 1px solid;
}

.medium {
    color: #ffd184;
    background: #392e20;
    border-color: #695235;
}

.high, .critical {
    color: #ff9ea7;
    background: #3b222e;
    border-color: #743848;
}

.low, .info {
    color: #8ecbff;
    background: #152c45;
    border-color: #315c7d;
}

.good {
    color: #80e4b6;
    background: #13372e;
    border-color: #2c6650;
}

.ring {
    flex-shrink: 0;
    width: 112px;
    height: 112px;
    border-radius: 50%;
    display: grid;
    place-items: center;
}

.ring-inner {
    background: #101d2b;
    width: 94px;
    height: 94px;
    border-radius: 50%;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
}

.ring strong {
    font: 700 25px monospace;
    color: #e7f6fb;
}

.ring small {
    font: 10px monospace;
    color: #9fb5c5;
    margin-top: 5px;
}

.stat {
    background: #111c2c;
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 18px 20px;
    margin-bottom: 14px;
    min-height: 118px;
}

.stat-label {
    color: #9db0c8;
    font-size: 12px;
}

.stat-value {
    font: 650 30px monospace;
    color: #edf5ff;
    margin: 8px 0 5px;
}

.stat-foot {
    font-size: 11px;
    color: #7f95ae;
}

.finding {
    background: #111c2c;
    border: 1px solid var(--line);
    border-left: 3px solid #d7a24c;
    border-radius: 12px;
    padding: 23px;
    margin: 10px 0 16px;
}

.finding.high, .finding.critical {
    border-left-color: #ff798c;
}

.finding-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 15px;
}

.finding h3 {
    margin: 14px 0 5px;
    color: #edf4fd;
    font-size: 19px !important;
}

.finding code {
    font-size: 11px;
    color: #8fa6bf;
    background: transparent;
    overflow-wrap: anywhere;
}

.finding p {
    font-size: 13px;
    color: #a5b7cd;
    line-height: 1.7;
    margin: 10px 0;
}

.values {
    display: flex;
    gap: 45px;
    border-top: 1px solid #27374a;
    border-bottom: 1px solid #27374a;
    padding: 14px 0;
    margin: 16px 0;
    flex-wrap: wrap;
}

.values span {
    display: block;
    color: #8298b2;
    font-size: 11px;
    margin-bottom: 5px;
}

.values strong {
    font: 500 13px monospace;
    color: #e6eef9;
}

.recommend {
    color: #bce9e5 !important;
    background: #102c32;
    border: 1px solid #20454d;
    border-radius: 8px;
    padding: 12px 14px;
}

.panel {
    background: #101b2a;
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 20px;
    margin: 10px 0 16px;
}

.panel h3 {
    margin: 0 0 12px;
    font-size: 14px !important;
}

.resource {
    font: 12px monospace;
    color: #b8cede;
    overflow-wrap: anywhere;
}

.rule {
    display: flex;
    justify-content: space-between;
    gap: 14px;
    border-bottom: 1px solid #233147;
    padding: 12px 0;
    font-size: 12px;
    color: #b5c6da;
}

.rule:last-child {
    border: 0;
    padding-bottom: 0;
}

.rule b {
    font-size: 11px;
    white-space: nowrap;
}

.footer {
    border-top: 1px solid #203047;
    padding-top: 18px;
    margin-top: 30px;
    color: #71869f;
    font: 10px monospace;
    letter-spacing: 0.6px;
}

.config-wrap {
    overflow-x: auto;
    border: 1px solid var(--line);
    border-radius: 12px;
    margin: 12px 0 22px;
}

.config {
    width: 100%;
    border-collapse: collapse;
    background: #111c2c;
    font-size: 13px;
}

.config th {
    background: #162437;
    text-align: left;
    color: #98aec6;
    font: 11px monospace;
    padding: 15px;
    white-space: nowrap;
}

.config td {
    padding: 17px 15px;
    border-top: 1px solid #233249;
    color: #d6e3f1;
}

.config code {
    background: transparent;
    font-size: 12px;
    color: #b5cde7;
}

[data-baseweb="tab-list"] {
    gap: 28px;
    border-bottom: 1px solid #25354b;
    margin-top: 10px;
}

[data-baseweb="tab"] {
    color: #96abc4 !important;
    padding: 10px 0 14px;
    background: transparent !important;
}

[data-baseweb="tab"][aria-selected="true"] {
    color: #6de0da !important;
}

[data-baseweb="tab-highlight"] {
    background: #58dcd5 !important;
}

[data-testid="stButton"] button,
[data-testid="stDownloadButton"] button {
    background: #14383e;
    color: #a1f5e9;
    border: 1px solid #2b6268;
    border-radius: 8px;
}

[data-testid="stButton"] button:hover,
[data-testid="stDownloadButton"] button:hover {
    background: #1b4b50;
    border-color: #68ddd4;
    color: white;
}

[data-testid="stWidgetLabel"] p {
    color: #a7bad0 !important;
    font-size: 12px;
}

[data-baseweb="select"] > div,
[data-baseweb="input"] {
    background: #142034 !important;
    color: #e8eef8 !important;
    border-color: #31445e !important;
}

[data-baseweb="select"] input,
[data-baseweb="input"] input {
    color: #e8eef8 !important;
}

[data-testid="stAlert"] {
    background: #142438;
    border: 1px solid #304861;
    color: #dce9f6;
}

@media (max-width: 700px) {
    .hero {
        padding: 20px;
        align-items: flex-start;
    }

    .hero h2 {
        font-size: 21px;
    }

    .ring {
        display: none;
    }

    h1 {
        font-size: 1.7rem !important;
    }

    .finding-top {
        flex-wrap: wrap;
    }

    .stat {
        padding: 14px;
    }

    .values {
        gap: 20px;
    }
}
</style>
"""

st.markdown(CSS, unsafe_allow_html=True)


# ============================================================
# Display helpers
# ============================================================

def esc(value):
    return html.escape(str(value))


def markup(value):
    st.markdown(value, unsafe_allow_html=True)


def stat(column, label, value, foot):
    with column:
        markup(
            '<div class="stat">'
            f'<div class="stat-label">{esc(label)}</div>'
            f'<div class="stat-value">{esc(value)}</div>'
            f'<div class="stat-foot">{esc(foot)}</div>'
            '</div>'
        )


# ============================================================
# Collect current Azure configuration
# ============================================================

def collect_snapshot():
    from azure.identity import AzureCliCredential
    from azure.mgmt.storage import StorageManagementClient
    from collector.security_rules import check_security_rules

    with BASELINE.open(encoding="utf-8") as handle:
        intended = json.load(handle)

    if not isinstance(intended, dict) or not intended:
        raise ValueError(
            "The intended configuration must be "
            "a nonempty JSON object."
        )

    credential = AzureCliCredential()

    try:
        client = StorageManagementClient(
            credential,
            SUBSCRIPTION_ID
        )

        try:
            account = client.storage_accounts.get_properties(
                RESOURCE_GROUP,
                STORAGE_ACCOUNT
            )

            raw = account.as_dict()
            properties = raw.get("properties", raw)

            fields = {
                "allowBlobPublicAccess":
                    "allow_blob_public_access",

                "publicNetworkAccess":
                    "public_network_access",

                "minimumTlsVersion":
                    "minimum_tls_version",

                "allowSharedKeyAccess":
                    "allow_shared_key_access",

                "supportsHttpsTrafficOnly":
                    "enable_https_traffic_only"
            }

            actual = {}

            for key, attribute in fields.items():
                value = properties.get(
                    key,
                    properties.get(
                        attribute,
                        getattr(account, attribute, None)
                    )
                )

                actual[key] = getattr(value, "value", value)

        finally:
            client.close()

    finally:
        credential.close()

    missing = [
        key
        for key, value in actual.items()
        if value is None
    ]

    if missing:
        raise ValueError(
            "Azure returned unknown values for: "
            + ", ".join(missing)
        )

    unsupported = set(intended) - set(actual)

    if unsupported:
        raise ValueError(
            "The baseline includes unsupported settings: "
            + ", ".join(sorted(unsupported))
        )

    findings = check_security_rules(
        actual,
        intended
    )

    return {
        "intended": intended,
        "actual": actual,
        "findings": findings,
        "checked_at": datetime.now(timezone.utc).isoformat()
    }


# ============================================================
# Read SQLite records
# ============================================================

def read_records(query):
    if not DATABASE.exists():
        return (
            None,
            "No database found. Run the comparator first."
        )

    connection = None

    try:
        connection = sqlite3.connect(
            DATABASE.as_uri() + "?mode=ro",
            uri=True
        )

        data = pd.read_sql_query(
            query,
            connection,
            params=(STORAGE_ACCOUNT,)
        )

        return data, None

    except Exception as error:
        return None, str(error)

    finally:
        if connection is not None:
            connection.close()


def read_history():
    return read_records(
        """
        SELECT *
        FROM findings
        WHERE resource_name = ?
        ORDER BY id DESC
        """
    )


def read_scan_history():
    return read_records(
        """
        SELECT
            id,
            started_at,
            finished_at,
            status,
            result,
            drift_count,
            finding_count,
            error_message
        FROM scans
        WHERE resource_name = ?
        ORDER BY id DESC
        """
    )


# ============================================================
# Sidebar
# ============================================================

with st.sidebar:
    markup(
        '<div class="brand">'
        '<div class="logo">DG</div>'
        '<div>'
        '<div class="brand-name">DRIFTGUARD</div>'
        '<div class="brand-sub">CLOUD SECURITY CONSOLE</div>'
        '</div>'
        '</div>'
    )

    markup(
        '<div class="side-label">WORKSPACE</div>'
        '<div class="side-item">'
        '◈ &nbsp; Azure storage monitor'
        '</div>'
    )

    markup(
        '<div class="side-label">MONITORED RESOURCE</div>'
        '<div class="side-meta">'
        'Storage account'
        f'<strong>{esc(STORAGE_ACCOUNT)}</strong>'
        '</div>'
        '<div class="side-meta">'
        'Resource group'
        f'<strong>{esc(RESOURCE_GROUP)}</strong>'
        '</div>'
        '<div class="side-meta">'
        'Provider'
        '<strong>Microsoft Azure</strong>'
        '</div>'
    )

    refresh = st.button(
        "↻  Refresh Azure",
        width="stretch"
    )

    st.button(
        "↻  Refresh saved history",
        width="stretch",
        help="Reload database records without requesting Azure again."
    )

    markup(
        '<div class="side-note">'
        'Manual refresh<br>'
        'Azure is checked on first load and when you select '
        'Refresh Azure. Filters reuse that snapshot.<br><br>'
        'Run the comparator to save findings and scan records.'
        '</div>'
    )


# ============================================================
# Collect or refresh the Azure snapshot
# ============================================================

first_load = (
    "dg_snapshot" not in st.session_state
    and "dg_error" not in st.session_state
)

if refresh or first_load:
    # Clear old results so a failed refresh cannot look healthy.
    st.session_state.pop("dg_snapshot", None)

    try:
        with st.spinner("Reading Azure configuration…"):
            st.session_state.dg_snapshot = collect_snapshot()

        st.session_state.pop("dg_error", None)

    except Exception as error:
        st.session_state.dg_error = str(error)


# ============================================================
# Page heading
# ============================================================

markup(
    '<div class="eyebrow">'
    'AZURE POSTURE / STORAGE MONITOR'
    '</div>'
)

st.title("Cloud security overview")

st.caption(
    "Configuration drift, security policy checks and "
    "scan history in one workspace."
)

snapshot = st.session_state.get("dg_snapshot")


# ============================================================
# Current assessment summary
# ============================================================

if snapshot is None:
    st.error(
        "Current assessment unavailable — Azure could not be checked."
    )

    st.info(
        "Check your Azure CLI session, resource permissions "
        "and intended_state.json, then select Refresh Azure. "
        "Saved finding history and scan history remain available below."
    )

    with st.expander("Azure error details"):
        st.code(
            st.session_state.get(
                "dg_error",
                "No Azure snapshot is available."
            )
        )

else:
    actual = snapshot["actual"]
    intended = snapshot["intended"]
    findings = snapshot["findings"]

    checked = datetime.fromisoformat(
        snapshot["checked_at"]
    ).strftime("%d %b %Y · %H:%M:%S UTC")

    drifts = [
        key
        for key in intended
        if intended[key] != actual[key]
    ]

    matched = len(intended) - len(drifts)
    ratio = round(matched / len(intended) * 100)

    high_count = sum(
        finding["severity"].upper() in {"HIGH", "CRITICAL"}
        for finding in findings
    )

    if findings and drifts:
        heading = "Drift + security misconfiguration"

        explanation = (
            "The Azure configuration differs from your baseline "
            "and has security policy findings. Review both below."
        )

    elif findings:
        heading = "Security misconfiguration"

        explanation = (
            "Your configuration matches the intended baseline. "
            "Separate security policy checks still require attention."
        )

    elif drifts:
        heading = "Configuration drift detected"

        explanation = (
            "Some settings differ from your intended baseline. "
            "No issues were found by the configured security rules."
        )

    else:
        heading = "All configured checks passed"

        explanation = (
            "The snapshot matches your baseline and has no findings "
            "from the configured security rules."
        )

    if high_count:
        tone = "high"
    elif findings or drifts:
        tone = "medium"
    else:
        tone = "good"

    badge = (
        "REVIEW REQUIRED"
        if findings or drifts
        else "COMPLIANT"
    )

    markup(
        '<div class="hero">'
        '<div>'
        f'<span class="pill {tone}">{badge}</span>'
        f'<h2>{heading}</h2>'
        f'<p>{explanation}</p>'
        '</div>'
        '<div class="ring" '
        f'style="background:conic-gradient(#58dcd5 {ratio}%,'
        '#28394c 0)">'
        '<div class="ring-inner">'
        f'<strong>{matched}/{len(intended)}</strong>'
        '<small>BASELINE MATCH</small>'
        '</div>'
        '</div>'
        '</div>'
    )

    st.caption(
        f"Last successful Azure check: {checked} "
        "· Snapshot, not continuous monitoring"
    )

    columns = st.columns(4)

    stat(
        columns[0],
        "Settings monitored",
        len(intended),
        "Intended configuration"
    )

    stat(
        columns[1],
        "Configuration drifts",
        len(drifts),
        "Compared with baseline"
    )

    stat(
        columns[2],
        "Security findings",
        len(findings),
        "Current snapshot"
    )

    stat(
        columns[3],
        "High / critical",
        high_count,
        "Current security findings"
    )


# ============================================================
# Dashboard tabs
# ============================================================

overview, configuration, history_tab, scan_tab = st.tabs(
    [
        "Security overview",
        "Configuration",
        "Finding history",
        "Scan history"
    ]
)


# ============================================================
# Security overview tab
# ============================================================

with overview:
    if snapshot is None:
        st.info(
            "Refresh Azure successfully to view current security findings."
        )

    else:
        left, right = st.columns(
            [1.9, 1],
            gap="large"
        )

        with left:
            st.subheader("Current findings")

            available = sorted(
                {
                    finding["severity"].upper()
                    for finding in findings
                }
            )

            severity = st.selectbox(
                "Severity",
                ["All severities"] + available,
                key="current_severity_filter"
            )

            visible = [
                finding
                for finding in findings
                if severity == "All severities"
                or finding["severity"].upper() == severity
            ]

            if not visible:
                st.success(
                    "No security findings match this view."
                )

            for finding in visible:
                severity_name = str(
                    finding["severity"]
                ).upper()

                known_severities = {
                    "CRITICAL",
                    "HIGH",
                    "MEDIUM",
                    "LOW",
                    "INFO"
                }

                if severity_name in known_severities:
                    severity_class = severity_name.lower()
                else:
                    severity_class = "info"

                markup(
                    f'<div class="finding {severity_class}">'
                    '<div class="finding-top">'
                    f'<span class="pill {severity_class}">'
                    f'{esc(severity_name)}'
                    '</span>'
                    f'<code>{esc(finding["setting"])}</code>'
                    '</div>'
                    f'<h3>{esc(finding["title"])}</h3>'
                    f'<p>{esc(finding["reason"])}</p>'
                    '<div class="values">'
                    '<div>'
                    '<span>SECURITY POLICY EXPECTS</span>'
                    f'<strong>{esc(finding["expected"])}</strong>'
                    '</div>'
                    '<div>'
                    '<span>OBSERVED VALUE</span>'
                    f'<strong>{esc(finding["actual"])}</strong>'
                    '</div>'
                    '</div>'
                    '<p class="recommend">'
                    '<b>Recommended action</b><br>'
                    f'{esc(finding["recommendation"])}'
                    '</p>'
                    '</div>'
                )

        with right:
            st.subheader("Assessment context")

            markup(
                '<div class="panel">'
                '<h3>Monitored resource</h3>'
                '<div class="resource">'
                f'{esc(STORAGE_ACCOUNT)}'
                '</div>'
                '<p class="subtle">'
                'Azure Storage account<br>'
                'Configuration and policy assessment'
                '</p>'
                '</div>'
            )

            setting_labels = [
                (
                    "allowBlobPublicAccess",
                    "Anonymous blob access"
                ),
                (
                    "publicNetworkAccess",
                    "Public network access"
                ),
                (
                    "minimumTlsVersion",
                    "Minimum TLS"
                ),
                (
                    "allowSharedKeyAccess",
                    "Shared key access"
                ),
                (
                    "supportsHttpsTrafficOnly",
                    "Secure transfer"
                )
            ]

            comparison_html = ""

            for key, label in setting_labels:
                if key not in intended:
                    continue

                is_drift = key in drifts

                colour = (
                    "#ffd184"
                    if is_drift
                    else "#80e4b6"
                )

                result = (
                    "DRIFT"
                    if is_drift
                    else "MATCH"
                )

                comparison_html += (
                    '<div class="rule">'
                    f'<span>{esc(label)}</span>'
                    f'<b style="color:{colour}">{result}</b>'
                    '</div>'
                )

            markup(
                '<div class="panel">'
                '<h3>Baseline comparison</h3>'
                + comparison_html
                + '</div>'
            )

            st.caption(
                "Baseline match is not a security score. "
                "An intended value can still violate a "
                "separate security policy."
            )


# ============================================================
# Configuration tab
# ============================================================

with configuration:
    if snapshot is None:
        st.info(
            "Refresh Azure successfully to view its current configuration."
        )

    else:
        st.subheader("Intended vs. observed")

        st.caption(
            "These values belong to the same Azure snapshot "
            "as the current security findings."
        )

        rows = []

        for key, value in intended.items():
            rows.append(
                {
                    "Setting": key,
                    "Intended": str(value),
                    "Observed": str(actual[key]),
                    "Drift": "Yes" if key in drifts else "No"
                }
            )

        table_rows = ""

        for row in rows:
            is_drift = row["Drift"] == "Yes"

            pill_class = (
                "medium"
                if is_drift
                else "good"
            )

            result = (
                "DRIFT"
                if is_drift
                else "MATCH"
            )

            table_rows += (
                '<tr>'
                f'<td><code>{esc(row["Setting"])}</code></td>'
                f'<td>{esc(row["Intended"])}</td>'
                f'<td>{esc(row["Observed"])}</td>'
                '<td>'
                f'<span class="pill {pill_class}">{result}</span>'
                '</td>'
                '</tr>'
            )

        markup(
            '<div class="config-wrap">'
            '<table class="config">'
            '<thead>'
            '<tr>'
            '<th>SETTING</th>'
            '<th>INTENDED</th>'
            '<th>OBSERVED</th>'
            '<th>BASELINE</th>'
            '</tr>'
            '</thead>'
            '<tbody>'
            + table_rows
            + '</tbody></table></div>'
        )

        st.download_button(
            label="Download configuration CSV",
            data=pd.DataFrame(rows).to_csv(index=False),
            file_name="azure-configuration.csv",
            mime="text/csv",
            key="download_configuration"
        )

        assessment = {
            "resource": STORAGE_ACCOUNT,
            **snapshot
        }

        st.download_button(
            label="Download assessment JSON",
            data=json.dumps(assessment, indent=2),
            file_name="azure-assessment.json",
            mime="application/json",
            key="download_assessment"
        )


# ============================================================
# Finding history tab
# ============================================================

with history_tab:
    st.subheader("Saved finding history")

    st.caption(
        "Saved by the comparator. Azure refresh does not update "
        "these records. Finding timestamps are recorded events, "
        "not the time of the last successful scan."
    )

    history, history_error = read_history()

    if history_error:
        st.error(
            f"Unable to read finding history: {history_error}"
        )

    else:
        opened = history[
            history["status"] == "OPEN"
        ]

        resolved = history[
            history["status"] == "RESOLVED"
        ]

        history_columns = st.columns(3)

        stat(
            history_columns[0],
            "Total records",
            len(history),
            "This storage account"
        )

        stat(
            history_columns[1],
            "Open records",
            len(opened),
            "Saved status"
        )

        stat(
            history_columns[2],
            "Resolved records",
            len(resolved),
            "Retained for review"
        )

        if snapshot is not None:
            current_settings = {
                finding["setting"]
                for finding in findings
            }

            saved_settings = set(opened["setting"])

            if current_settings != saved_settings:
                st.warning(
                    "Saved open findings differ from the current "
                    "snapshot. Run the comparator to synchronize "
                    "history, then refresh the dashboard."
                )

        filter_a, filter_b = st.columns(2)

        with filter_a:
            status = st.selectbox(
                "Saved status",
                [
                    "All statuses",
                    "OPEN",
                    "RESOLVED"
                ],
                key="finding_status_filter"
            )

        with filter_b:
            search = st.text_input(
                "Find a setting or title",
                placeholder="e.g. publicNetworkAccess",
                key="finding_search"
            )

        filtered = history.copy()

        if status != "All statuses":
            filtered = filtered[
                filtered["status"] == status
            ]

        if search:
            setting_matches = (
                filtered["setting"]
                .fillna("")
                .str.contains(
                    search,
                    case=False,
                    regex=False
                )
            )

            title_matches = (
                filtered["title"]
                .fillna("")
                .str.contains(
                    search,
                    case=False,
                    regex=False
                )
            )

            filtered = filtered[
                setting_matches | title_matches
            ]

        if filtered.empty:
            st.info(
                "No saved findings match these filters."
            )

        else:
            display_columns = [
                "id",
                "timestamp",
                "severity",
                "status",
                "setting",
                "title",
                "expected_value",
                "actual_value"
            ]

            st.dataframe(
                filtered[display_columns],
                width="stretch",
                hide_index=True
            )

            st.download_button(
                label="Export filtered findings",
                data=filtered.to_csv(index=False),
                file_name="finding-history.csv",
                mime="text/csv",
                key="download_finding_history"
            )

    with st.expander("Update saved findings"):
        st.write(
            "Run this from your project folder, then select "
            "Refresh saved history in the sidebar:"
        )

        st.code(
            "python -m collector.comparator",
            language="powershell"
        )


# ============================================================
# Scan history tab
# ============================================================

with scan_tab:
    st.subheader("Scan history")

    st.caption(
        "Each comparator run creates a separate scan record. "
        "SUCCESS means the scan completed, even if it found "
        "security issues. Refresh Azure does not create a scan."
    )

    scan_data, scan_error = read_scan_history()

    if scan_error:
        st.error(
            f"Unable to read scan history: {scan_error}"
        )

        st.info(
            "Make sure the scans table exists and you have "
            "run the updated comparator."
        )

    elif scan_data.empty:
        st.info(
            "No scans recorded yet. Run "
            "python -m collector.comparator."
        )

    else:
        successful_scans = int(
            (scan_data["status"] == "SUCCESS").sum()
        )

        failed_scans = int(
            (scan_data["status"] == "FAILED").sum()
        )

        running_scans = int(
            (scan_data["status"] == "RUNNING").sum()
        )

        scan_columns = st.columns(4)

        stat(
            scan_columns[0],
            "Total scans",
            len(scan_data),
            "Recorded comparator runs"
        )

        stat(
            scan_columns[1],
            "Successful scans",
            successful_scans,
            "Assessment completed"
        )

        stat(
            scan_columns[2],
            "Failed scans",
            failed_scans,
            "Assessment did not complete"
        )

        stat(
            scan_columns[3],
            "Running / unfinished",
            running_scans,
            "No completion recorded"
        )

        latest_scan = scan_data.iloc[0]
        latest_result = latest_scan["result"]

        if pd.isna(latest_result):
            latest_result = "No completed assessment"

        latest_status = str(latest_scan["status"])

        if latest_status == "SUCCESS":
            latest_class = "good"
        elif latest_status == "FAILED":
            latest_class = "high"
        else:
            latest_class = "medium"

        markup(
            '<div class="panel">'
            '<h3>Latest recorded scan</h3>'
            f'<span class="pill {latest_class}">'
            f'{esc(latest_status)}'
            '</span>'
            '<p class="subtle">'
            f'Scan #{esc(latest_scan["id"])}'
            '<br>'
            f'Assessment: {esc(latest_result)}'
            '<br>'
            f'Started: {esc(latest_scan["started_at"])}'
            '</p>'
            '</div>'
        )

        latest_error = latest_scan["error_message"]

        if pd.notna(latest_error) and str(latest_error).strip():
            with st.expander("Latest scan error"):
                st.code(str(latest_error))

        selected_scan_status = st.selectbox(
            "Filter scan status",
            [
                "All scans",
                "SUCCESS",
                "FAILED",
                "RUNNING"
            ],
            key="scan_status_filter"
        )

        filtered_scans = scan_data.copy()

        if selected_scan_status != "All scans":
            filtered_scans = filtered_scans[
                filtered_scans["status"]
                == selected_scan_status
            ].copy()

        # Missing counts remain empty, rather than becoming zero.
        for column in ["drift_count", "finding_count"]:
            filtered_scans[column] = pd.to_numeric(
                filtered_scans[column],
                errors="coerce"
            ).astype("Int64")

        if filtered_scans.empty:
            st.info(
                "No scans match the selected status."
            )

        else:
            st.dataframe(
                filtered_scans,
                width="stretch",
                hide_index=True
            )

            st.download_button(
                label="Export scan history",
                data=filtered_scans.to_csv(index=False),
                file_name="scan-history.csv",
                mime="text/csv",
                key="download_scan_history"
            )

        st.caption(
            "Empty counts mean no completed assessment "
            "was recorded. RUNNING may also indicate a "
            "scan interrupted before completion."
        )

    with st.expander("Record another scan"):
        st.write(
            "Run this in your project terminal, then select "
            "Refresh saved history in the sidebar:"
        )

        st.code(
            "python -m collector.comparator",
            language="powershell"
        )


# ============================================================
# Footer
# ============================================================

markup(
    '<div class="footer">'
    'DRIFTGUARD / AZURE STORAGE SECURITY'
    ' &nbsp; · &nbsp; READ-ONLY AZURE COLLECTION'
    ' &nbsp; · &nbsp; MANUAL REFRESH'
    '</div>'
)