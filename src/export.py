"""export.py - produces the downloadable deliverables: Excel register and a Markdown report."""
import io
from datetime import date

import pandas as pd
from openpyxl.styles import Alignment, Font, PatternFill

from .scoring import summary_by_function

HEX = {"Critical": "C00000", "High": "ED7D31", "Medium": "FFD966", "Low": "92D050"}


def to_excel_bytes(register, ranking):
    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as xw:
        register.to_excel(xw, sheet_name="Risk Register", index=False)
        ranking.to_excel(xw, sheet_name="Control Priorities", index=False)
        summary_by_function(register).to_excel(xw, sheet_name="CSF Summary")
        for ws in xw.book.worksheets:
            for c in ws[1]:
                c.font = Font(bold=True, color="FFFFFF")
                c.fill = PatternFill("solid", fgColor="1F3864")
            for col in ws.columns:
                ws.column_dimensions[col[0].column_letter].width = min(max(len(str(c.value or "")) for c in col) + 2, 45)
            for row in ws.iter_rows(min_row=2):
                for c in row:
                    c.alignment = Alignment(wrap_text=True, vertical="top")
            ws.freeze_panes = "B2"
        ws = xw.sheets["Risk Register"]
        heads = [c.value for c in ws[1]]
        for name in ("inherent_rating", "residual_rating"):
            idx = heads.index(name) + 1
            for r in range(2, ws.max_row + 1):
                cell = ws.cell(row=r, column=idx)
                cell.fill = PatternFill("solid", fgColor=HEX[cell.value])
    return buf.getvalue()


def _table(df, cols, headers):
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    for _, r in df.iterrows():
        lines.append("| " + " | ".join(str(r[c]) for c in cols) + " |")
    return "\n".join(lines)


def to_report_md(org, register, ranking, kev_summary, kev_label, answers):
    n = len(register)
    count = lambda col, vals: int(register[col].isin(vals).sum())
    yes = sum(v == "Yes" for v in answers.values())
    part = sum(v == "Partial" for v in answers.values())
    no = sum(v == "No" for v in answers.values())
    fsum = summary_by_function(register).reset_index()
    md = [f"# Ransomware Risk Assessment - {org}", f"_Generated {date.today():%d %B %Y}_", "",
          "## 1. Executive summary",
          f"- {n} ransomware risks assessed against NIST CSF 2.0.",
          f"- Controls: {yes} fully in place, {part} partial, {no} not in place (of {len(answers)}).",
          f"- Without controls: {count('inherent_rating', ['Critical','High'])} risks are Critical/High. "
          f"With current controls: {count('residual_rating', ['Critical','High'])}.",
          f"- Average risk score moves from {register['inherent_score'].mean():.1f} to {register['residual_score'].mean():.1f} (scale 1-25).", ""]
    if kev_summary:
        md += ["## 2. Threat intelligence (CISA KEV)",
               f"- Source: {kev_label}.",
               f"- {kev_summary['total']} scanned findings; {kev_summary['kev_total']} are known to be actively exploited "
               f"({kev_summary['kev_internet']} on internet-facing hosts, {kev_summary['kev_internal']} internal).", ""]
    md += ["## 3. Highest remaining risks",
           _table(register.head(8), ["risk_id", "risk", "csf_subcategory", "residual_score", "residual_rating"],
                  ["ID", "Risk", "CSF", "Score", "Rating"]), "",
           "## 4. Recommended next controls (largest risk reduction first)",
           _table(ranking.head(8), ["control_id", "question", "risk_points_removed"],
                  ["ID", "Control", "Risk points removed"]), "",
           "## 5. Average score by NIST CSF function",
           _table(fsum, ["csf_function", "inherent_score", "residual_score", "risks"],
                  ["Function", "Inherent", "Residual", "Risks"]), "",
           "## 6. Method and limitations",
           "Risk = Likelihood x Impact (1-5 each). Each control answer (Yes/Partial/No) reduces the likelihood and/or "
           "impact of the risks it is linked to; effect sizes are expert estimates in `data/control_map.csv` and should "
           "be calibrated for your organisation. Scores are decision support, not a guarantee of security."]
    return "\n".join(md)
