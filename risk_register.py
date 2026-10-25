import argparse
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from openpyxl.styles import Alignment, Font, PatternFill

COLUMNS = ["Risk ID", "Risk", "Threat Scenario", "CSF Function", "CSF Category",
           "CSF Subcategory", "Asset", "Likelihood", "Impact", "Existing Controls",
           "Recommended Treatment", "Residual Likelihood", "Residual Impact",
           "Owner", "Timeline"]

# (title, scenario, function, category, subcategory, asset, L, I, existing,
#  treatment, residual L, residual I, owner, timeline)
RISKS = [
 ("Phishing-led initial access", "Employee opens malicious attachment/link that drops a loader and ransomware",
  "Protect", "PR.AT", "PR.AT-01", "Workforce / email", 5, 4, "Annual awareness training; basic spam filter",
  "Monthly phishing simulations; email sandboxing; report-phish button", 3, 3, "CISO", "0-90 days"),
 ("Remote access without MFA", "Attacker uses stolen credentials on VPN/RDP exposed to the internet",
  "Protect", "PR.AA", "PR.AA-03", "VPN / RDP gateways", 4, 5, "Password-only VPN",
  "Phishing-resistant MFA; close public RDP; geo/IP restrictions", 2, 4, "IT Infrastructure", "0-30 days"),
 ("Unpatched internet-facing systems", "Exploitation of known CVEs on edge devices and web servers",
  "Protect", "PR.PS", "PR.PS-02", "Edge devices / servers", 4, 5, "Monthly patch cycle",
  "72-hour SLA for actively exploited CVEs (CISA KEV); attack-surface scanning", 2, 4, "IT Operations", "0-60 days"),
 ("Incomplete asset inventory / shadow IT", "Unknown systems stay unpatched and unmonitored, becoming entry points",
  "Identify", "ID.AM", "ID.AM-01", "All IT assets", 4, 3, "Manual spreadsheet inventory",
  "Automated discovery; CMDB; owner assigned to each asset", 3, 3, "IT Operations", "30-120 days"),
 ("Weak vulnerability management", "Scans run irregularly; findings not prioritised by exploitability",
  "Identify", "ID.RA", "ID.RA-01", "Servers / endpoints", 3, 4, "Quarterly scans",
  "Continuous scanning; risk-based prioritisation; remediation tracking KPIs", 2, 3, "Security Team", "30-90 days"),
 ("Excessive privileges / domain admin compromise", "Attacker escalates to domain admin and deploys ransomware domain-wide",
  "Protect", "PR.AA", "PR.AA-05", "Active Directory", 4, 5, "Shared admin accounts",
  "Privileged Access Management; tiered admin model; LAPS; remove standing admin rights", 2, 4, "IT Infrastructure", "30-120 days"),
 ("Flat network enabling lateral movement", "Ransomware spreads rapidly across servers and workstations",
  "Protect", "PR.IR", "PR.IR-01", "Corporate network", 4, 5, "Partial VLANs",
  "Segment crown jewels; restrict SMB/RDP east-west; micro-segmentation", 2, 4, "Network Team", "60-180 days"),
 ("Backups not immutable or offline", "Attacker deletes or encrypts backups before detonation",
  "Protect", "PR.DS", "PR.DS-11", "Backup infrastructure", 4, 5, "Nightly backups on domain-joined storage",
  "3-2-1-1-0 strategy; immutable/air-gapped copy; separate backup credentials with MFA", 2, 3, "IT Operations", "0-60 days"),
 ("Untested backup restoration", "Backups fail or are slow to restore when needed",
  "Recover", "RC.RP", "RC.RP-03", "Backup / DR", 4, 4, "No scheduled restore tests",
  "Quarterly restore tests; verify integrity and malware-free before restore", 2, 3, "IT Operations", "30-90 days"),
 ("No EDR on endpoints and servers", "Ransomware executes undetected on unmanaged or legacy-AV hosts",
  "Detect", "DE.CM", "DE.CM-09", "Endpoints / servers", 4, 4, "Signature-based antivirus",
  "Deploy EDR with ransomware behaviour rules and auto-isolation", 2, 3, "Security Team", "30-90 days"),
 ("Insufficient logging and no 24/7 monitoring", "Intrusion goes unnoticed for days before encryption",
  "Detect", "DE.AE", "DE.AE-02", "SIEM / logs", 4, 4, "Local logs, no central SIEM",
  "Central SIEM; MDR/SOC 24/7; alerts for mass file changes and backup tampering", 2, 3, "Security Team", "60-180 days"),
 ("Data exfiltration (double extortion)", "Data stolen before encryption and leaked to force payment",
  "Protect", "PR.DS", "PR.DS-01", "Sensitive data stores", 4, 5, "No DLP; limited encryption",
  "Data classification; DLP; egress filtering; encryption at rest", 3, 4, "CISO / DPO", "60-180 days"),
 ("No tested incident response plan", "Slow, uncoordinated response increases dwell time and damage",
  "Respond", "RS.MA", "RS.MA-01", "IR capability", 3, 5, "Draft IR plan, never exercised",
  "Ransomware playbook; biannual tabletop exercises; IR retainer", 2, 3, "CISO", "30-90 days"),
 ("Poor crisis communication and legal notification", "Delayed regulator/customer/staff notification causes fines and reputational loss",
  "Respond", "RS.CO", "RS.CO-02", "Legal / Comms", 3, 4, "No defined process",
  "Comms plan; legal counsel on call; regulatory notification matrix", 2, 3, "Legal / Comms", "30-90 days"),
 ("Third-party / supply chain compromise", "Vendor or MSP compromised and used to push ransomware",
  "Govern", "GV.SC", "GV.SC-07", "Vendors / MSPs", 3, 5, "Contracts lack security clauses",
  "Vendor risk assessments; security clauses; least-privilege vendor access", 2, 4, "Procurement / CISO", "90-180 days"),
 ("No board-level cyber governance", "Weak oversight leads to underfunded controls and unclear risk appetite",
  "Govern", "GV.OV", "GV.OV-01", "Governance", 3, 4, "Annual CISO update",
  "Quarterly board reporting; documented cyber risk appetite; KPIs/KRIs", 2, 3, "Board / CISO", "60-120 days"),
 ("No ransom payment policy", "Ad hoc payment decision without legal, sanctions or insurance review",
  "Govern", "GV.PO", "GV.PO-01", "Policy", 2, 4, "None",
  "Documented decision framework; sanctions screening; cyber insurance review", 2, 3, "Legal / CFO", "60-120 days"),
 ("No Business Impact Analysis (RTO/RPO unknown)", "Recovery not prioritised by business criticality",
  "Identify", "ID.AM", "ID.AM-05", "Critical services", 4, 4, "None",
  "Complete BIA; define RTO/RPO; rank systems for restoration", 3, 3, "Business Continuity", "60-120 days"),
 ("Outdated disaster recovery plan", "Recovery of critical systems takes weeks",
  "Recover", "RC.RP", "RC.RP-01", "DR plan", 3, 5, "DR plan outdated",
  "Update DR plan; restoration runbooks; clean-room recovery environment", 2, 3, "IT Operations", "60-150 days"),
 ("No post-incident improvement process", "Same weaknesses repeat across incidents",
  "Identify", "ID.IM", "ID.IM-03", "Security programme", 3, 3, "Informal reviews",
  "Mandatory lessons-learned reviews; track corrective actions", 2, 2, "CISO", "90-180 days"),
 ("Credential theft via infostealers", "Stolen browser-saved credentials sold and used for access",
  "Protect", "PR.AA", "PR.AA-01", "User credentials", 4, 4, "Complexity policy only",
  "Password manager; MFA everywhere; dark-web credential monitoring", 3, 3, "Security Team", "30-90 days"),
 ("Unmanaged legacy / OT systems", "Unpatchable systems are easy targets and halt operations when encrypted",
  "Protect", "PR.PS", "PR.PS-01", "Legacy / OT", 3, 5, "Not tracked",
  "Isolate legacy systems; virtual patching; compensating controls", 3, 4, "IT / Operations", "90-240 days"),
]


def rating(score):
    if score >= 20: return "Critical"
    if score >= 13: return "High"
    if score >= 6: return "Medium"
    return "Low"


def build_register():
    rows = []
    for i, r in enumerate(RISKS, 1):
        rows.append([f"R{i:02d}", *r])
    df = pd.DataFrame(rows, columns=COLUMNS)
    df["Inherent Score"] = df["Likelihood"] * df["Impact"]
    df["Inherent Rating"] = df["Inherent Score"].apply(rating)
    df["Residual Score"] = df["Residual Likelihood"] * df["Residual Impact"]
    df["Residual Rating"] = df["Residual Score"].apply(rating)
    df["Risk Reduction %"] = ((1 - df["Residual Score"] / df["Inherent Score"]) * 100).round(0)
    return df.sort_values("Inherent Score", ascending=False, kind="stable").reset_index(drop=True)


COLORS = {"Critical": "C00000", "High": "ED7D31", "Medium": "FFD966", "Low": "92D050"}


def export_excel(df, path):
    with pd.ExcelWriter(path, engine="openpyxl") as xw:
        df.to_excel(xw, sheet_name="Risk Register", index=False)
        summary = (df.groupby("CSF Function")[["Inherent Score", "Residual Score"]]
                     .agg(["count", "mean"]).round(1))
        summary.to_excel(xw, sheet_name="CSF Summary")
        ws = xw.sheets["Risk Register"]
        for c in ws[1]:
            c.font = Font(bold=True, color="FFFFFF")
            c.fill = PatternFill("solid", fgColor="1F3864")
            c.alignment = Alignment(wrap_text=True, vertical="center")
        for col in ws.columns:
            width = min(max(len(str(c.value or "")) for c in col) + 2, 45)
            ws.column_dimensions[col[0].column_letter].width = width
        headers = [c.value for c in ws[1]]
        for name in ("Inherent Rating", "Residual Rating"):
            idx = headers.index(name) + 1
            for row in range(2, ws.max_row + 1):
                cell = ws.cell(row=row, column=idx)
                cell.fill = PatternFill("solid", fgColor=COLORS[cell.value])
        for row in ws.iter_rows(min_row=2):
            for c in row:
                c.alignment = Alignment(wrap_text=True, vertical="top")
        ws.freeze_panes = "C2"


def heatmap(ax, df, lcol, icol, title):
    grid = np.array([[l * i for i in range(1, 6)] for l in range(1, 6)])
    cmap = {"Low": "#92D050", "Medium": "#FFD966", "High": "#ED7D31", "Critical": "#C00000"}
    for l in range(1, 6):
        for i in range(1, 6):
            ax.add_patch(plt.Rectangle((i - .5, l - .5), 1, 1,
                         color=cmap[rating(grid[l - 1][i - 1])], alpha=.85, ec="white"))
            ids = df[(df[lcol] == l) & (df[icol] == i)]["Risk ID"].str.replace("R", "").tolist()
            if ids:
                ax.text(i, l, "\n".join(", ".join(ids[k:k + 3]) for k in range(0, len(ids), 3)),
                        ha="center", va="center", fontsize=8, fontweight="bold")
    ax.set_xlim(.5, 5.5); ax.set_ylim(.5, 5.5)
    ax.set_xticks(range(1, 6)); ax.set_yticks(range(1, 6))
    ax.set_xlabel("Impact"); ax.set_ylabel("Likelihood"); ax.set_title(title)


def make_charts(df, out):
    fig, axes = plt.subplots(1, 2, figsize=(13, 6))
    heatmap(axes[0], df, "Likelihood", "Impact", "Inherent Risk (before controls)")
    heatmap(axes[1], df, "Residual Likelihood", "Residual Impact", "Residual Risk (after treatment)")
    fig.suptitle("Ransomware Risk Heat Maps (numbers = Risk IDs)", fontsize=13)
    fig.tight_layout(); fig.savefig(os.path.join(out, "heatmap.png"), dpi=150); plt.close(fig)

    order = ["Govern", "Identify", "Protect", "Detect", "Respond", "Recover"]
    g = df.groupby("CSF Function")[["Inherent Score", "Residual Score"]].mean().reindex(order).dropna()
    ax = g.plot(kind="bar", figsize=(9, 5), color=["#C00000", "#4472C4"])
    ax.set_ylabel("Average risk score"); ax.set_title("Average Risk by NIST CSF 2.0 Function")
    plt.xticks(rotation=0); plt.tight_layout()
    plt.savefig(os.path.join(out, "csf_function_scores.png"), dpi=150); plt.close()

    top = df.nlargest(10, "Inherent Score").iloc[::-1]
    plt.figure(figsize=(10, 5))
    plt.barh(top["Risk ID"] + " " + top["Risk"].str[:42], top["Inherent Score"],
             color=[f"#{COLORS[r]}" for r in top["Inherent Rating"]])
    plt.xlabel("Inherent score (max 25)"); plt.title("Top 10 Ransomware Risks")
    plt.tight_layout(); plt.savefig(os.path.join(out, "top10_risks.png"), dpi=150); plt.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="output")
    out = ap.parse_args().out
    os.makedirs(out, exist_ok=True)
    df = build_register()
    df.to_csv(os.path.join(out, "risk_register.csv"), index=False)
    export_excel(df, os.path.join(out, "risk_register.xlsx"))
    make_charts(df, out)
    print(f"Risks: {len(df)}")
    print("Inherent:", df["Inherent Rating"].value_counts().to_dict())
    print("Residual:", df["Residual Rating"].value_counts().to_dict())
    print("Avg inherent %.1f -> residual %.1f" % (df["Inherent Score"].mean(), df["Residual Score"].mean()))
    print(df.groupby("CSF Function")[["Inherent Score", "Residual Score"]].mean().round(1))
    print(df[["Risk ID", "Risk", "Inherent Score", "Residual Score"]].head(8).to_string(index=False))
    print(f"Outputs written to ./{out}/")


if __name__ == "__main__":
    main()