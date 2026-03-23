from build_alerts import build_bruteforce_alerts
from save_alerts import save_alerts_to_json

sample_rows = [
{
"Account_Name": "-",
"Source_Network_Address": "10.0.1.100",
"count": "3162",
"hosts": "mercury"
},
{
"Account_Name": "Administrator",
"Source_Network_Address": "10.0.1.220",
"count": "109",
"hosts": "mercury"
}
]

alerts = build_bruteforce_alerts(sample_rows)

for a in alerts:
    print(a.to_dict())

saved_path = save_alerts_to_json(alerts, "reports/alerts.json")
print(f"\nSaved alerts to: {saved_path}")
