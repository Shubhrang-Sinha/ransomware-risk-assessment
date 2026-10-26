# Enterprise Ransomware Risk Assessment (NIST CSF 2.0)

A Python tool that generates a **corporate risk register for ransomware**, mapped to the
**NIST Cybersecurity Framework 2.0** (Govern, Identify, Protect, Detect, Respond, Recover).

## What it does
- Defines 22 ransomware risks with threat scenarios, assets, existing controls and treatments
- Maps each risk to a CSF Function, Category and Subcategory (e.g. `PR.DS-11`)
- Scores inherent and residual risk using Likelihood x Impact (1-5 each, max 25)
- Rates risks: Low (1-5), Medium (6-12), High (13-19), Critical (20-25)
- Exports `risk_register.csv`, a colour-coded `risk_register.xlsx`, and three charts

## Project structure
```
.
├── risk_register.py     # main script
├── requirements.txt     # dependencies
├── README.md
└── output/              # generated files (csv, xlsx, png)
```

## Setup and run
```bash
git clone https://github.com/<your-username>/ransomware-risk-assessment.git
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python risk_register.py          # optional: --out my_folder
```

## Key results
| Metric | Value |
|---|---|
| Risks assessed | 22 |
| Inherent: Critical / High / Medium | 7 / 9 / 6 |
| Residual: Medium / Low | 21 / 1 |
| Average score | 15.7 -> 7.5 after treatment |

Highest-risk CSF function: **Protect** (avg inherent 19.0).

## Customising
Edit the `RISKS` list in `risk_register.py` to add or change risks, or adjust the
`rating()` thresholds to match your organisation's risk appetite.

## Disclaimer
Scores are illustrative, based on a hypothetical mid-size enterprise. Calibrate them
with real assessment data before using in production.

## References
NIST CSF 2.0 (2024), CISA #StopRansomware Guide, NIST IR 8374 (Ransomware Risk Management profile).
