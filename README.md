<<<<<<< HEAD
# Splunk AI SOC Copilot

An end-to-end SOC triage prototype that integrates **Splunk detections** with **structured AI analysis** to accelerate analyst workflows.

This project ingests security detections from Splunk, normalizes alert data, enriches each alert with AI-generated incident context, supports human triage decisions in a dashboard, exports ticket JSON payloads, and generates a detailed PDF report.

---

## Why this project exists

SOC teams often deal with high alert volume and context gaps.  
This project demonstrates a practical approach:

- **Rules (Splunk) = detection truth**
- **AI = structured explanation + triage guidance**
- **Analyst = final decision authority**

---

## What this proves

- Practical SIEM workflow design (not just isolated scripts)
- Security detection engineering with MITRE mapping
- AI-assisted triage with confidence separation (`rule_confidence` vs `ai_confidence`)
- Human-in-the-loop SOC operations (status, labels, notes)
- Portfolio-ready engineering and documentation discipline

---

## Core features

### 1) Multi-detection pipeline
- **Brute-force Login Failures** — MITRE `T1110`
- **Suspicious PowerShell Execution** — MITRE `T1059.001`
- **Possible Lateral Movement** — MITRE `T1021`

### 2) Standardized alert schema
Each alert includes:
- `alert_id`, `timestamp`
- `detection_type`, `severity`, `mitre_technique`
- `entities`, `evidence`
- `rule_confidence`, `ai_confidence`
- `status`, `analyst_label`, `analyst_note`
- `recommended_actions`

### 3) Structured AI enrichment (local Ollama)
AI returns strict JSON:
- `what_happened`
- `why_it_matters`
- `top_3_actions`
- `mitre_mapping`
- `confidence`

### 4) SOC dashboard (Streamlit)
- KPI cards (alerts, open/triaged/closed, true positives, severity distribution)
- Filter controls (severity, detection type, status, label)
- Alert triage workflow
- Investigation timeline view
- Persistent analyst updates

### 5) Ticket export
Generates per-alert ticket payloads:
- `reports/tickets/*.ticket.json`

### 6) PDF reporting
Creates a professional technical report:
- `reports/AI_SOC_Copilot_Report.pdf`

---

## Architecture

Splunk (BOTS telemetry)  
→ Detection Queries  
→ Python Alert Builders  
→ `reports/alerts.json`  
→ AI Enrichment (Ollama)  
→ `reports/alerts_enriched.json`  
→ Dashboard + Ticket Export + PDF Report

---

## Dataset attribution

This project uses the **Splunk Boss of the SOC (BOTS) Dataset Version 2**.

- Repository: https://github.com/splunk/botsv2
- Dataset used for SOC simulation/detection testing
- License: see upstream repository/license details

**Citation:**  
Splunk. *Boss of the SOC (BOTS) Dataset Version 2*. GitHub repository, https://github.com/splunk/botsv2

---

## Tech stack

- Splunk Enterprise (local lab)
- Splunk BOTS v2 dataset
- Python 3.x
- Streamlit
- Ollama (`llama3.1:8b`)
- ReportLab

---

## Project structure

```text
src/
  alert_schema.py
  build_alerts.py
  build_powershell_alerts.py
  build_lateral_alerts.py
  build_all_alerts.py
  splunk_client.py
  detections.py
  run_pipeline.py
  ai_formatter.py
  timeline_builder.py
  ticket_exporter.py
  dashboard.py
  generate_report_pdf.py

data/raw/
  splunk_bruteforce.csv
  splunk_powershell.csv
  splunk_lateral.csv

reports/
  alerts.json
  alerts_enriched.json
  tickets/
  AI_SOC_Copilot_Report.pdf
=======
# splunk-ai-soc-copilot
Splunk + AI SOC triage pipeline with alert enrichment, analyst workflow, and ticket/PDF reporting.
>>>>>>> 50b7778caf459f7d3e76857d95e18f2a6d62091e
