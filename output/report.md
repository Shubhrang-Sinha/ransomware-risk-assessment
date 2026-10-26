# Ransomware Risk Assessment - Demo Company
_Generated 26 October 2026_

## 1. Executive summary
- 22 ransomware risks assessed against NIST CSF 2.0.
- Controls: 1 fully in place, 10 partial, 14 not in place (of 25).
- Without controls: 17 risks are Critical/High. With current controls: 12.
- Average risk score moves from 16.1 to 13.6 (scale 1-25).

## 2. Threat intelligence (CISA KEV)
- Source: CISA live feed.
- 10 scanned findings; 5 are known to be actively exploited (3 on internet-facing hosts, 2 internal).

## 3. Highest remaining risks
| ID | Risk | CSF | Score | Rating |
|---|---|---|---|---|
| R06 | Excessive privileges / domain admin compromise | PR.AA-05 | 20.0 | Critical |
| R08 | Backups not immutable or offline | PR.DS-11 | 20.0 | Critical |
| R03 | Unpatched internet-facing systems | PR.PS-02 | 18.1 | High |
| R02 | Remote access without MFA | PR.AA-03 | 17.5 | High |
| R12 | Data exfiltration (double extortion) | PR.DS-01 | 17.1 | High |
| R11 | Insufficient logging and no 24/7 monitoring | DE.AE-02 | 16.0 | High |
| R18 | No Business Impact Analysis (RTO/RPO unknown) | ID.AM-05 | 16.0 | High |
| R09 | Untested backup restoration | RC.RP-03 | 15.2 | High |

## 4. Recommended next controls (largest risk reduction first)
| ID | Control | Risk points removed |
|---|---|---|
| C03 | Is multi-factor authentication (MFA) enforced on all VPN and remote access? | 15.2 |
| C10 | Do you keep immutable or offline backups with separate credentials? | 15.2 |
| C13 | Are logs centralised in a SIEM and monitored 24/7 (in-house or managed service)? | 14.2 |
| C08 | Do you use privileged access management and separate admin accounts (tiered admin)? | 13.1 |
| C11 | Do you test restoring from backups at least quarterly? | 11.7 |
| C21 | Have you completed a business impact analysis with recovery targets (RTO/RPO)? | 11.4 |
| C07 | Do you scan for vulnerabilities continuously and prioritise by exploitability? | 10.2 |
| C14 | Do you use data-loss-prevention and egress filtering to spot bulk data leaving? | 8.8 |

## 5. Average score by NIST CSF function
| Function | Inherent | Residual | Risks |
|---|---|---|---|
| Govern | 11.7 | 10.5 | 3 |
| Identify | 13.2 | 11.8 | 4 |
| Protect | 19.6 | 16.2 | 9 |
| Detect | 16.0 | 13.5 | 2 |
| Respond | 13.5 | 10.8 | 2 |
| Recover | 15.5 | 12.4 | 2 |

## 6. Method and limitations
Risk = Likelihood x Impact (1-5 each). Each control answer (Yes/Partial/No) reduces the likelihood and/or impact of the risks it is linked to; effect sizes are expert estimates in `data/control_map.csv` and should be calibrated for your organisation. Scores are decision support, not a guarantee of security.