import json
from pathlib import Path
from typing import List
from alert_schema import Alert

def save_alerts_to_json(alerts: List[Alert], output_path:str = "reports/alerts.json") -> str:

    """
    Save a list of Alert objects to a JSON file.
    Returns the output of file path
    """
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    payload = [alert.to_dict() for alert in alerts]

    with out_file.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    return str(out_file)
