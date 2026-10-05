import json
import os
import sqlite3
import pandas as pd
import plotly.express as px
import requests
import streamlit as st

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "data", "telemetry.db")
API_URL = "http://127.0.0.1:8000/api/v1/ingest"

st.set_page_config(
    page_title="Rate Shield Security Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def fetch_data():
    if not os.path.exists(DB_PATH):
        return pd.DataFrame(), pd.DataFrame()

    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    try:
        telemetry_df = pd.read_sql_query(
            """
            SELECT id, client_ip, endpoint, http_method, status_code, response_time_ms, timestamp 
            FROM request_telemetry 
            ORDER BY id DESC LIMIT 100
            """,
            conn,
        )

        audits_df = pd.read_sql_query(
            """
            SELECT id, telemetry_id, payload_sample, threat_score, flagged_categories, 
                   remediation_action, inspection_time_ms, raw_llm_output, analyzed_at 
            FROM security_audits 
            ORDER BY id DESC LIMIT 100
            """,
            conn,
        )
    except Exception as e:
        st.sidebar.error(f"Database Read Error: {e}")
        telemetry_df, audits_df = pd.DataFrame(), pd.DataFrame()
    finally:
        conn.close()

    return telemetry_df, audits_df


st.sidebar.title("🛡️ Rate Shield Control")

st.sidebar.subheader("Single Payload Injector")
sample_user_id = st.sidebar.text_input("User ID", value="sec_admin")
sample_query = st.sidebar.text_area(
    "Test Payload / Query",
    value="SELECT * FROM users WHERE '1'='1'",
    height=100,
)

if st.sidebar.button("Send Payload to API", use_container_width=True, key="btn_single_payload"):
    payload = {"user_id": sample_user_id, "query": sample_query}
    try:
        res = requests.post(API_URL, json=payload, timeout=10.0)
        if res.status_code == 200:
            st.sidebar.success("Payload ingested! Audit queued.")
        else:
            st.sidebar.error(f"API Error: {res.status_code}")
    except Exception as e:
        st.sidebar.error(f"Failed to connect to API: {e}")

st.sidebar.divider()

st.sidebar.subheader("Traffic Simulator")
if st.sidebar.button("Inject Attack Batch (5 Requests)", use_container_width=True, key="btn_attack_batch"):
    simulated_payloads = [
        {"user_id": "usr_safe", "query": "SELECT id, name FROM products WHERE category = 'books'"},
        {"user_id": "usr_warn1", "query": "SELECT * FROM users WHERE name = 'John' OR '1'='1'"},
        {"user_id": "usr_warn2", "query": "UPDATE profiles SET status = 'active' WHERE id = 42 -- update user"},
        {"user_id": "attacker1", "query": "UNION SELECT null, username, password FROM admin_users--"},
        {"user_id": "attacker2", "query": "DROP TABLE request_telemetry; --"}
    ]

    success_count = 0
    for p in simulated_payloads:
        try:
            res = requests.post(API_URL, json=p, timeout=10.0)
            if res.status_code == 200:
                success_count += 1
        except Exception:
            pass

    st.sidebar.info(f"Dispatched {success_count}/5 simulated requests.")

st.sidebar.divider()

st.sidebar.subheader("Dashboard Filters")
st.sidebar.slider(
    "Filter Minimum Threat Score",
    min_value=0,
    max_value=100,
    value=0,
    step=5,
    key="filter_min_score"
)

st.sidebar.multiselect(
    "Filter Remediation Actions",
    options=["BLOCK", "SANITIZE", "ALLOW"],
    default=["BLOCK", "SANITIZE", "ALLOW"],
    key="filter_actions"
)

st.sidebar.divider()
st.sidebar.caption("System Mode: WAL Enabled | Engine: Local Ollama (llama3)")

st.title("Rate Shield Security & Telemetry Console")


@st.fragment(run_every=2)
def render_live_metrics():
    min_score = st.session_state.get("filter_min_score", 0)
    selected_actions = st.session_state.get("filter_actions", ["BLOCK", "SANITIZE", "ALLOW"])

    telemetry_df, audits_df = fetch_data()

    filtered_audits = audits_df.copy()
    if not filtered_audits.empty:
        filtered_audits["remediation_action"] = (
            filtered_audits["remediation_action"]
            .astype(str)
            .str.strip()
            .str.upper()
        )

        if selected_actions:
            filtered_audits = filtered_audits[
                (filtered_audits["threat_score"] >= min_score) &
                (filtered_audits["remediation_action"].isin(selected_actions))
                ]
        else:
            filtered_audits = filtered_audits.iloc[0:0]

    c1, c2, c3, c4 = st.columns(4)

    total_requests = len(telemetry_df)
    high_threats = (
        len(audits_df[audits_df["threat_score"] >= 50])
        if not audits_df.empty
        else 0
    )
    avg_latency = (
        f"{telemetry_df['response_time_ms'].mean():.2f} ms"
        if not telemetry_df.empty
        else "0.00 ms"
    )
    avg_inspection = (
        f"{audits_df['inspection_time_ms'].mean():.2f} ms"
        if not audits_df.empty
        else "0.00 ms"
    )

    c1.metric("Total API Requests", total_requests)
    c2.metric("Flagged Threats (Score ≥50)", high_threats)
    c3.metric("API Response Time", avg_latency)
    c4.metric("Ollama Inspection Latency", avg_inspection)

    st.divider()

    col1, col2, col3 = st.columns(3)

    with col1:
        st.subheader("API Latency Distribution")
        if not telemetry_df.empty:
            fig_latency = px.histogram(
                telemetry_df,
                x="response_time_ms",
                nbins=15,
                color="http_method",
                labels={"response_time_ms": "Response Time (ms)"},
            )
            fig_latency.update_layout(margin=dict(l=10, r=10, t=20, b=10))
            st.plotly_chart(fig_latency, use_container_width=True)
        else:
            st.info("No telemetry latency records yet.")

    with col2:
        st.subheader("Threat Score Spectrum")
        if not filtered_audits.empty:
            color_map = {
                "BLOCK": "#8b5cf6",
                "SANITIZE": "#0d9488",
                "ALLOW": "#10b981",
            }

            fig_threats = px.scatter(
                filtered_audits,
                x="id",
                y="threat_score",
                color="remediation_action",
                color_discrete_map=color_map,
                size="inspection_time_ms",
                hover_data=["payload_sample"],
                labels={
                    "threat_score": "Threat Score",
                    "id": "Audit ID",
                    "remediation_action": "Action",
                },
            )
            fig_threats.update_layout(margin=dict(l=10, r=10, t=20, b=10))
            st.plotly_chart(fig_threats, use_container_width=True)
        else:
            st.info("No audit scores matching filters.")

    with col3:
        st.subheader("Threat Category Breakdown")
        if not filtered_audits.empty and "flagged_categories" in filtered_audits.columns:
            CATEGORY_MAP = {
                "sql injection": "SQLi",
                "sql_injection": "SQLi",
                "sqlinjection": "SQLi",
                "sqli": "SQLi",
                "sql": "SQLi",
                "xss_attack": "XSS",
                "cross_site_scripting": "XSS",
                "xss": "XSS",
                "command_injection": "Command Injection",
                "command injection": "Command Injection",
                "cmdi": "Command Injection",
                "none": "None",
            }

            def parse_categories(val):
                try:
                    res = json.loads(val)
                    if not isinstance(res, list):
                        res = [str(res)]
                except Exception:
                    res = ["none"]

                normalized = []
                for c in res:
                    key = str(c).lower().strip()
                    normalized.append(CATEGORY_MAP.get(key, key.upper()))
                return normalized

            categories_series = filtered_audits["flagged_categories"].apply(parse_categories)
            exploded_cats = categories_series.explode()

            exploded_cats = exploded_cats[exploded_cats != "None"]

            if not exploded_cats.empty:
                cat_counts = exploded_cats.value_counts().reset_index()
                cat_counts.columns = ["Category", "Count"]

                fig_cats = px.pie(
                    cat_counts,
                    names="Category",
                    values="Count",
                    hole=0.4,
                    color_discrete_sequence=px.colors.qualitative.Set2,
                )
                fig_cats.update_layout(margin=dict(l=10, r=10, t=20, b=10))
                st.plotly_chart(fig_cats, use_container_width=True)
            else:
                st.info("No active threat vectors detected in selected logs.")
        else:
            st.info("No category data available.")

    st.divider()

    t1, t2 = st.tabs(["🔒 Ollama Security Audits", "📊 API Network Telemetry"])

    with t1:
        st.subheader("Recent Payload Threat Audits")
        if not filtered_audits.empty:
            for idx, row in filtered_audits.iterrows():
                score = row["threat_score"]
                action = row["remediation_action"]

                badge = (
                    "🔴 BLOCK"
                    if action == "BLOCK"
                    else "🟡 SANITIZE" if action == "SANITIZE" else "🟢 ALLOW"
                )

                with st.expander(
                        f"Audit #{row['id']} | Threat Score: {score} | Action: {badge}"
                ):
                    st.json(
                        {
                            "telemetry_id": row["telemetry_id"],
                            "payload_sample": row["payload_sample"],
                            "threat_score": row["threat_score"],
                            "remediation_action": row["remediation_action"],
                            "flagged_categories": row["flagged_categories"],
                            "inspection_time_ms": row["inspection_time_ms"],
                            "raw_ollama_json": row["raw_llm_output"],
                        }
                    )
        else:
            st.info("No audit logs matching the current filters.")

    with t2:
        st.subheader("Raw Telemetry Stream")
        if not telemetry_df.empty:
            st.dataframe(telemetry_df, use_container_width=True)
        else:
            st.info("No network requests recorded.")


render_live_metrics()