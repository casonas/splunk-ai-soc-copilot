import json
from pathlib import Path
from collections import Counter
from datetime import datetime
import streamlit as st

ALERTS_PATH = Path("reports/alerts_enriched.json")


def load_alerts():
    if not ALERTS_PATH.exists():
        return []
    try:
        return json.loads(ALERTS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []


def save_alerts(alerts):
    ALERTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    ALERTS_PATH.write_text(json.dumps(alerts, indent=2), encoding="utf-8")


def severity_rank(sev: str) -> int:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return order.get(str(sev).lower(), 0)


def parse_ts(ts: str):
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except Exception:
        return datetime.min


def severity_badge(sev: str) -> str:
    s = str(sev).lower()
    if s == "critical":
        return "🔴 Critical"
    if s == "high":
        return "🟠 High"
    if s == "medium":
        return "🟡 Medium"
    if s == "low":
        return "🟢 Low"
    return f"⚪️ {sev}"


def compute_kpis(alerts):
    total = len(alerts)
    open_count = sum(1 for a in alerts if str(a.get("status", "open")).lower() == "open")
    triaged_count = sum(1 for a in alerts if str(a.get("status", "")).lower() == "triaged")
    closed_count = sum(1 for a in alerts if str(a.get("status", "")).lower() == "closed")
    tp_count = sum(1 for a in alerts if str(a.get("analyst_label", "")).lower() == "true positive")
    sev_counts = Counter(str(a.get("severity", "unknown")).lower() for a in alerts)

    return {
        "total": total,
        "open": open_count,
        "triaged": triaged_count,
        "closed": closed_count,
        "tp": tp_count,
        "critical": sev_counts.get("critical", 0),
        "high": sev_counts.get("high", 0),
        "medium": sev_counts.get("medium", 0),
        "low": sev_counts.get("low", 0),
    }


def apply_filters(alerts):
    all_sev = sorted({str(a.get("severity", "unknown")).lower() for a in alerts})
    all_det = sorted({str(a.get("detection_type", "unknown")) for a in alerts})
    all_status = sorted({str(a.get("status", "open")).lower() for a in alerts})
    all_labels = sorted({str(a.get("analyst_label", "Needs Review")) for a in alerts})

    st.markdown("### Filters")
    f1, f2, f3, f4 = st.columns(4)

    with f1:
        sev_filter = st.multiselect("Severity", options=all_sev, default=all_sev, key="filter_sev")

    with f2:
        det_filter = st.multiselect("Detection Type", options=all_det, default=all_det, key="filter_det")

    with f3:
        status_filter = st.multiselect("Status", options=all_status, default=all_status, key="filter_status")

    with f4:
        label_filter = st.multiselect("Analyst Label", options=all_labels, default=all_labels, key="filter_label")

    filtered = []
    for a in alerts:
        sev = str(a.get("severity", "unknown")).lower()
        det = str(a.get("detection_type", "unknown"))
        status = str(a.get("status", "open")).lower()
        label = str(a.get("analyst_label", "Needs Review"))

        if sev not in sev_filter:
            continue
        if det not in det_filter:
            continue
        if status not in status_filter:
            continue
        if label not in label_filter:
            continue

        filtered.append(a)

    return filtered


def render_kpis(alerts):
    k = compute_kpis(alerts)

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Alerts", k["total"])
    c2.metric("Open", k["open"])
    c3.metric("Triaged", k["triaged"])
    c4.metric("Closed", k["closed"])
    c5.metric("True Positive", k["tp"])

    s1, s2, s3, s4 = st.columns(4)
    s1.metric("Critical", k["critical"])
    s2.metric("High", k["high"])
    s3.metric("Medium", k["medium"])
    s4.metric("Low", k["low"])


def render_alert_card(alerts, i, alert):
    with st.container(border=True):
        st.markdown(f"### {alert.get('detection_type', 'Unknown Detection')}")
        st.write(f"**Alert ID:** {alert.get('alert_id', 'N/A')}")
        st.write(f"**Severity:** {severity_badge(alert.get('severity', 'unknown'))}")
        st.write(f"**MITRE:** {alert.get('mitre_technique', 'N/A')}")
        st.write(f"**Rule Confidence:** {alert.get('rule_confidence', 0.0)}")
        st.write(f"**AI Confidence:** {alert.get('ai_confidence', 0.0)}")

        with st.expander("Entities"):
            st.json(alert.get("entities", {}))

        with st.expander("Evidence"):
            st.json(alert.get("evidence", {}))

        ai = alert.get("ai_summary", {})
        if ai:
            st.markdown("**AI Summary**")
            st.write(f"- **What happened:** {ai.get('what_happened', '')}")
            st.write(f"- **Why it matters:** {ai.get('why_it_matters', '')}")

            actions = ai.get("top_3_actions", [])
            for a in actions:
                st.write(f"- {a}")

        timeline = alert.get("investigation_timeline", [])
        if timeline:
            with st.expander("Investigation Timeline"):
                for item in timeline:
                    st.write(f"- {item}")

        col1, col2 = st.columns(2)

        with col1:
            status_options = ["open", "triaged", "closed"]
            current_status = str(alert.get("status", "open")).lower()
            if current_status not in status_options:
                current_status = "open"

            new_status = st.selectbox("Status", status_options, index=status_options.index(current_status), key=f"status_{i}")

        with col2:
            label_options = ["Needs Review", "True Positive", "Benign"]
            current_label = str(alert.get("analyst_label", "Needs Review"))
            if current_label not in label_options:
                current_label = "Needs Review"

            new_label = st.selectbox("Analyst Label", label_options, index=label_options.index(current_label), key=f"label_{i}")

        note_key = f"note_{i}"
        current_note = alert.get("analyst_note", "")
        new_note = st.text_area("Analyst Note", value=current_note, key=note_key, height=90)

        if st.button("Save Triage Update", key=f"save_{i}"):
            alerts[i]["status"] = new_status
            alerts[i]["analyst_label"] = new_label
            alerts[i]["analyst_note"] = new_note
            save_alerts(alerts)
            st.success(f"Updated {alert.get('alert_id', 'alert')}")
            st.rerun()


def main():
    st.set_page_config(page_title="AI SOC Copilot Dashboard", layout="centered")
    st.title("AI SOC Copilot Dashboard")
    st.subheader("SOC Alert Triage")

    alerts = load_alerts()
    if not alerts:
        st.info("No enriched alerts found yet. Run: python src/run_pipeline.py")
        return

    render_kpis(alerts)
    st.divider()

    filtered = apply_filters(alerts)
    st.write(f"Showing **{len(filtered)}** of **{len(alerts)}** alerts")
    st.divider()

    sorted_alerts = sorted(
        filtered,
        key=lambda a: (severity_rank(a.get("severity", "")), parse_ts(a.get("timestamp", ""))),
        reverse=True,
    )

    id_to_index = {a.get("alert_id"): idx for idx, a in enumerate(alerts)}

    for alert in sorted_alerts:
        orig_index = id_to_index.get(alert.get("alert_id"))
        if orig_index is None:
            continue
        render_alert_card(alerts, orig_index, alerts[orig_index])


if __name__ == "__main__":
    main()