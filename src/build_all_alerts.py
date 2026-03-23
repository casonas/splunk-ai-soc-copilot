import csv
import json
from pathlib import Path
from typing import List, Dict, Any

from build_alerts import build_bruteforce_alerts
from build_powershell_alerts import build_powershell_alerts
from build_lateral_alerts import build_lateral_alerts
from save_alerts import save_alerts_to_json


def load_csv_rows(path: str) -> List[Dict[str, Any]]:
    file_path = Path(path)
    if not file_path.exists():
        return []

    with file_path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        return list(reader)


def main() -> None:
    bruteforce_csv = "data/raw/splunk_bruteforce.csv"
    powershell_csv = "data/raw/splunk_powershell.csv"
    lateral_csv = "data/raw/splunk_lateral.csv"

    bf_rows = load_csv_rows(bruteforce_csv)
    ps_rows = load_csv_rows(powershell_csv)
    lat_rows = load_csv_rows(lateral_csv)

    bf_alerts = build_bruteforce_alerts(bf_rows)
    ps_alerts = build_powershell_alerts(ps_rows)
    lat_alerts = build_lateral_alerts(lat_rows)

    all_alerts = bf_alerts + ps_alerts + lat_alerts

    out_path = save_alerts_to_json(all_alerts, "reports/alerts.json")

    print(f"Brute-force rows: {len(bf_rows)} -> alerts: {len(bf_alerts)}")
    print(f"PowerShell rows: {len(ps_rows)} -> alerts: {len(ps_alerts)}")
    print(f"Lateral rows: {len(lat_rows)} -> alerts: {len(lat_alerts)}")
    print(f"Total alerts: {len(all_alerts)}")
    print(f"Saved alerts file: {out_path}")

    preview = [a.to_dict() for a in all_alerts[:2]]
    print(json.dumps(preview, indent=2))


if __name__ == "__main__":
    main()