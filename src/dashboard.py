import json
from pathlib import Path
from collections import Counter
from datetime import datetime
import streamlit as st

ALERTS_PATH = Path("reports/alerts_enriched.json")

# ---------------- CONFIG ----------------
st.set_page_config(page_title="AI SOC Copilot", layout="wide")

# ---------------- STYLES ----------------
st.markdown("""
<style>
.block-container { padding-top: 1.5rem; }

/* HEADER FIX */
.header {
    text-align: center;
    font-size: 34px;
    font-weight: 700;
    margin-top: 10px;
    margin-bottom: 6px;
    line-height: 1.3;
}

.subheader {
    text-align: center;
    color: #9ca3af;
    margin-bottom: 24px;
}

/* KPI */
.kpi {
    text-align:center;
    padding:14px;
    border-radius:10px;
    background:#0f172a;
    border:1px solid #1f2937;
}

/* FILTER BAR */
.filter-bar {
    padding:12px;
    border-radius:10px;
    background:#0f172a;
    border:1px solid #1f2937;
}

/* CARDS */
.card {
    border-radius:14px;
    padding:18px;
    border:1px solid #1f2937;
    background:#0b1220;
    margin-bottom:14px;
}

/* AI BOXES */
.ai-box { padding:10px; border-radius:8px; margin-bottom:8px; }
.ai-what { background:#1e3a5f; }
.ai-why { background:#3f3f1a; }

</style>
""", unsafe_allow_html=True)

# ---------------- DATA ----------------
def load_alerts():
    if not ALERTS_PATH.exists():
        return []
    return json.loads(ALERTS_PATH.read_text())


def save_alerts(alerts):
    ALERTS_PATH.write_text(json.dumps(alerts, indent=2))


# ---------------- HELPERS ----------------
def severity_rank(sev):
    return {"critical":4,"high":3,"medium":2,"low":1}.get(str(sev).lower(),0)


def parse_ts(ts):
    try:
        return datetime.fromisoformat(str(ts).replace("Z","+00:00"))
    except:
        return datetime.min


def severity_badge(sev):
    return {
        "critical":"🔴 Critical",
        "high":"🟠 High",
        "medium":"🟡 Medium",
        "low":"🟢 Low"
    }.get(str(sev).lower(), sev)


def compute_kpis(alerts):
    sev = Counter(str(a.get("severity","")).lower() for a in alerts)
    return {
        "total": len(alerts),
        "open": sum(1 for a in alerts if a.get("status","open")=="open"),
        "triaged": sum(1 for a in alerts if a.get("status")=="triaged"),
        "closed": sum(1 for a in alerts if a.get("status")=="closed"),
        "tp": sum(1 for a in alerts if str(a.get("analyst_label","")).lower()=="true positive"),
        "critical": sev.get("critical",0),
        "high": sev.get("high",0),
        "medium": sev.get("medium",0),
        "low": sev.get("low",0),
    }


# ---------------- FILTERS ----------------
def apply_filters(alerts, search):

    st.markdown("<div class='filter-bar'>", unsafe_allow_html=True)

    col1,col2,col3,col4 = st.columns(4)

    with col1:
        sev = st.selectbox("Severity", ["all","critical","high","medium","low"])

    with col2:
        det = st.selectbox("Detection", ["all"] + sorted({a.get("detection_type","") for a in alerts}))

    with col3:
        status = st.selectbox("Status", ["all","open","triaged","closed"])

    with col4:
        label = st.selectbox("Label", ["all","Needs Review","True Positive","Benign"])

    st.markdown("</div>", unsafe_allow_html=True)

    out = []
    for a in alerts:
        if search and search.lower() not in json.dumps(a).lower():
            continue
        if sev != "all" and str(a.get("severity","")).lower() != sev:
            continue
        if det != "all" and a.get("detection_type") != det:
            continue
        if status != "all" and str(a.get("status","")).lower() != status:
            continue
        if label != "all" and a.get("analyst_label") != label:
            continue
        out.append(a)

    return out


# ---------------- ALERT CARD ----------------
def render_alert(alerts, original_index, alert):

    st.markdown(f"### {alert.get('detection_type')}")
    st.caption(f"{alert.get('alert_id')} • {alert.get('mitre_technique')}")

    st.write(f"**Severity:** {severity_badge(alert.get('severity'))}")
    st.write(f"Rule: {alert.get('rule_confidence')} | AI: {alert.get('ai_confidence')}")

    # ---------- AI ----------
    ai = alert.get("ai_summary", {})
    if ai:
        st.markdown("### 🤖 AI Analysis")

        st.markdown(f"<div class='ai-box ai-what'>{ai.get('what_happened')}</div>", unsafe_allow_html=True)
        st.markdown(f"<div class='ai-box ai-why'>{ai.get('why_it_matters')}</div>", unsafe_allow_html=True)

        st.markdown("### ⚡ Actions")
        for a in ai.get("top_3_actions", []):
            st.markdown(f"- {a}")

    # ---------- TIMELINE ----------
    timeline = alert.get("investigation_timeline", [])
    if timeline:
        with st.expander("🕒 Timeline"):
            for t in timeline:
                st.write(t)

    # ---------- DETAILS ----------
    with st.expander("Details"):
        st.json(alert)

    # ---------- TRIAGE ----------
    st.markdown("### 🧑‍💻 Triage")

    col1,col2 = st.columns(2)

    status_options = ["open","triaged","closed"]
    current_status = str(alert.get("status","open")).lower()
    if current_status not in status_options:
        current_status = "open"

    new_status = col1.selectbox(
        "Status",
        status_options,
        index=status_options.index(current_status),
        key=f"s_{original_index}"
    )

    label_options = ["Needs Review","True Positive","Benign"]
    current_label = alert.get("analyst_label","Needs Review")

    if current_label not in label_options:
        current_label = "Needs Review"

    new_label = col2.selectbox(
        "Label",
        label_options,
        index=label_options.index(current_label),
        key=f"l_{original_index}"
    )

    note = st.text_area(
        "Analyst Note",
        value=alert.get("analyst_note",""),
        key=f"n_{original_index}"
    )

    if st.button("Save Triage Update", key=f"b_{original_index}"):
        alerts[original_index]["status"] = new_status
        alerts[original_index]["analyst_label"] = new_label
        alerts[original_index]["analyst_note"] = note

        save_alerts(alerts)
        st.success("Updated")
        st.rerun()


# ---------------- MAIN ----------------
def main():

    st.markdown("<div class='header'>🛡️ AI SOC Copilot</div>", unsafe_allow_html=True)
    st.markdown("<div class='subheader'>Security Operations Dashboard</div>", unsafe_allow_html=True)

    alerts = load_alerts()
    if not alerts:
        st.info("Run pipeline first")
        return

    k = compute_kpis(alerts)

    row1 = st.columns(5)
    row1[0].markdown(f"<div class='kpi'><b>Alerts</b><br>{k['total']}</div>", unsafe_allow_html=True)
    row1[1].markdown(f"<div class='kpi'><b>Open</b><br>{k['open']}</div>", unsafe_allow_html=True)
    row1[2].markdown(f"<div class='kpi'><b>Triaged</b><br>{k['triaged']}</div>", unsafe_allow_html=True)
    row1[3].markdown(f"<div class='kpi'><b>Closed</b><br>{k['closed']}</div>", unsafe_allow_html=True)
    row1[4].markdown(f"<div class='kpi'><b>True Positive</b><br>{k['tp']}</div>", unsafe_allow_html=True)

    row2 = st.columns(4)
    row2[0].markdown(f"<div class='kpi'><b>Critical</b><br>{k['critical']}</div>", unsafe_allow_html=True)
    row2[1].markdown(f"<div class='kpi'><b>High</b><br>{k['high']}</div>", unsafe_allow_html=True)
    row2[2].markdown(f"<div class='kpi'><b>Medium</b><br>{k['medium']}</div>", unsafe_allow_html=True)
    row2[3].markdown(f"<div class='kpi'><b>Low</b><br>{k['low']}</div>", unsafe_allow_html=True)

    st.divider()

    search = st.text_input("🔎 Search alerts")

    filtered = apply_filters(alerts, search)

    st.write(f"Showing {len(filtered)} / {len(alerts)} alerts")

    st.divider()

    sorted_alerts = sorted(
        filtered,
        key=lambda a: (severity_rank(a.get("severity")), parse_ts(a.get("timestamp"))),
        reverse=True
    )

    id_map = {a.get("alert_id"):i for i,a in enumerate(alerts)}

    for alert in sorted_alerts:
        original_index = id_map.get(alert.get("alert_id"))
        if original_index is None:
            continue

        render_alert(alerts, original_index, alerts[original_index])


if __name__ == "__main__":
    main()