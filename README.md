# Ransomware Risk Assessment Tool (NIST CSF 2.0) - v2

An interactive tool that lets an organisation answer a security questionnaire, optionally upload a
vulnerability scan, and instantly get a **personalised ransomware risk register** mapped to the
**NIST Cybersecurity Framework 2.0**, with a prioritised list of what to fix first.

> **v1** (static register with hard-coded scores) is tagged `v1.0`. **v2** (this version) calculates scores
> from the organisation's own answers and live threat intelligence.

## Features
- **22 ransomware risks** mapped to NIST CSF 2.0 (Govern, Identify, Protect, Detect, Respond, Recover)
- **25-question control questionnaire** (Yes / Partial / No) that *calculates* residual risk
- **Threat intelligence:** checks a vulnerability scan against CISA's Known Exploited Vulnerabilities (KEV)
  catalog and raises likelihood when attackers are actively exploiting a flaw you have
- **"What to fix first" engine:** re-scores the register as if each missing control were in place and ranks them
- **Streamlit dashboard** with heat maps, filters, what-if answers and downloads (Excel, CSV, Markdown report)
- **Command-line mode** for automation
- **Data-driven:** risks, controls and thresholds live in CSV/YAML files - no code changes needed
- Input validation, 14 automated tests, CI workflow, Dockerfile

## How scoring works
1. Each risk starts with a base **likelihood** and **impact** (1-5) from `data/risks.csv`.
2. If a scan shows a KEV-listed flaw, likelihood of "KEV-sensitive" risks is raised (+1 internet-facing, +0.5 internal).
3. Each control linked to the risk (`data/control_map.csv`) reduces likelihood and/or impact:
   `L = L x (1 - likelihood_effect x answer_value)`, with Yes = 1, Partial = 0.5, No = 0.
4. Score = Likelihood x Impact (1-25). Low <= 5, Medium <= 12, High <= 19, Critical above (editable in `config.yaml`).

## Project structure
```
data/        risks.csv, controls.csv, control_map.csv, config.yaml, sample inputs, kev_sample.json
src/         loader.py (read+validate)  scoring.py (the maths)  threat_intel.py (CISA KEV)
             charts.py  export.py
app.py       Streamlit dashboard
run_assessment.py   command-line runner
tests/       automated tests
```

## Quick start
```bash
git clone https://github.com/Shubhrang-Sinha/ransomware-risk-assessment
cd ransomware-risk-assessment
python -m venv venv && source venv/bin/activate     # Windows: venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py             # dashboard at http://localhost:8501
python run_assessment.py         # or: command-line mode, writes ./output
python -m pytest                 # run the tests
```

## Using your own data
| File | Columns | Purpose |
|---|---|---|
| answers.csv | `control_id, answer` | Yes / Partial / No per control (template downloadable in the app) |
| scan.csv | `host, internet_facing, cve, severity` | Vulnerability scanner export |
| data/risks.csv | see file | Add or edit risks, base scores, CSF mapping |
| data/control_map.csv | `control_id, risk_id, likelihood_effect, impact_effect` | Which control reduces which risk, and by how much |

```bash
python run_assessment.py --answers my_answers.csv --vulns my_scan.csv --org "Acme Ltd" --out results
```

## Deployment
**Streamlit Community Cloud (free):** push to GitHub -> share.streamlit.io -> New app -> choose the repo,
branch `main`, main file `app.py` -> Deploy.
**Docker:** `docker build -t risk-tool . && docker run -p 8501:8501 risk-tool`

## Limitations
- Control effect sizes and base scores are expert estimates; calibrate them to your environment and industry.
- Answers are self-reported and not verified; the scan check only uses CVE IDs and an internet-facing flag.
- No financial-loss modelling and no history tracking yet.
- The offline KEV file is only a small sample; the live CISA feed is used when reachable.

## Roadmap
FAIR-style loss quantification (Monte Carlo) - SQLite history and trend charts - MITRE ATT&CK / CIS Controls
mapping - EPSS scores - PDF reports - authentication and multi-organisation support.

## References
NIST CSF 2.0 (2024) - NIST IR 8374 (Ransomware profile) - CISA #StopRansomware Guide - CISA KEV Catalog.
