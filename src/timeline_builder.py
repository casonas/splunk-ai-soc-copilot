from typing import Dict, Any, List


def _fmt(v: Any, fallback: str = "unknown") -> str:
    if v is None:
        return fallback
    s = str(v).strip()
    return s if s else fallback


def build_timeline(alert: Dict[str, Any]) -> List[str]:
    timeline: List[str] = []

    ts = _fmt(alert.get("timestamp"))
    detection = _fmt(alert.get("detection_type"))
    severity = _fmt(alert.get("severity")).upper()
    entities = alert.get("entities", {})
    evidence = alert.get("evidence", {})
    ai = alert.get("ai_summary", {})

    # 1) Initial detection event
    timeline.append(f"{ts} - Alert triggered: {detection} ({severity})")

    # 2) Key entity/evidence line by detection type
    if "Brute" in detection:
        src_ip = _fmt(entities.get("source_ip"))
        acct = _fmt(entities.get("account_name"))
        fails = _fmt(evidence.get("failed_attempts"))
        timeline.append(
            f"{ts} - Repeated failed logins observed from {src_ip} targeting account {acct} (failed_attempts={fails})"
        )

    elif "PowerShell" in detection:
        host = _fmt(entities.get("host"))
        acct = _fmt(entities.get("account_name"))
        cmd = _fmt(evidence.get("process_command_line"), fallback="[redacted/none]")
        timeline.append(
            f"{ts} - Suspicious PowerShell execution on host {host} by account {acct}; command context: {cmd}"
        )

    elif "Lateral" in detection:
        src_ip = _fmt(entities.get("source_ip"))
        acct = _fmt(entities.get("account_name"))
        host_count = _fmt(evidence.get("host_count"))
        timeline.append(
            f"{ts} - Network logon spread detected from {src_ip} using account {acct} across host_count={host_count}"
        )

    # 3) AI interpretation line
    what = _fmt(ai.get("what_happened"), fallback="")
    why = _fmt(ai.get("why_it_matters"), fallback="")
    if what and what != "unknown":
        timeline.append(f"{ts} - AI summary: {what}")
    if why and why != "unknown":
        timeline.append(f"{ts} - Risk context: {why}")

    # 4) Recommended actions lines
    actions = ai.get("top_3_actions", [])
    if not isinstance(actions, list) or len(actions) == 0:
        actions = alert.get("recommended_actions", [])

    for idx, action in enumerate(actions[:3], start=1):
        timeline.append(f"{ts} - Recommended action {idx}: {action}")

    return timeline