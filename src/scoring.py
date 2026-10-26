"""
scoring.py - the "brain". Pure functions: data in, scores out. No files, no screen.

Model:
  inherent L / I  = base values from risks.csv (+ a bump if a known-exploited
                    vulnerability was found - see threat_intel.py)
  for every control linked to a risk:
        L = L * (1 - likelihood_effect * answer_value)
        I = I * (1 - impact_effect     * answer_value)
  answer_value: Yes = 1, Partial = 0.5, No = 0   (from config.yaml)
  residual L / I = result, never below 1.   Score = L * I.
Multiplying (instead of adding) means stacked controls have diminishing returns
and can never push a value below zero.
"""
import pandas as pd


def rating(score, thresholds):
    if score <= thresholds["low"]:
        return "Low"
    if score <= thresholds["medium"]:
        return "Medium"
    if score <= thresholds["high"]:
        return "High"
    return "Critical"


def kev_bump(kev_summary, config):
    """How much to raise likelihood of 'KEV-sensitive' risks, from scan evidence."""
    if not kev_summary:
        return 0.0
    k = config["kev"]
    if kev_summary.get("kev_internet", 0) > 0:
        return float(k["bump_internet_facing"])
    if kev_summary.get("kev_internal", 0) > 0:
        return float(k["bump_internal_only"])
    return 0.0


def score_register(risks, cmap, answers, config, kev_summary=None):
    values = config["answer_values"]
    th = config["rating_thresholds"]
    smax = config["scale_max"]
    bump = kev_bump(kev_summary, config)
    by_risk = {rid: grp for rid, grp in cmap.groupby("risk_id")}

    rows = []
    for _, r in risks.iterrows():
        L0 = float(r["base_likelihood"])
        if r["kev_sensitive"] and bump:
            L0 = min(float(smax), L0 + bump)
        I0 = float(r["base_impact"])
        L, I = L0, I0
        gaps = []
        for _, m in by_risk.get(r["risk_id"], pd.DataFrame()).iterrows():
            ans = answers.get(m["control_id"], "No")
            v = values.get(ans, 0.0)
            L *= 1 - m["likelihood_effect"] * v
            I *= 1 - m["impact_effect"] * v
            if ans != "Yes":
                gaps.append(m["control_id"])
        L, I = max(1.0, L), max(1.0, I)
        inh, res = L0 * I0, L * I
        rows.append({
            "risk_id": r["risk_id"], "risk": r["risk"], "scenario": r["scenario"],
            "csf_function": r["csf_function"], "csf_category": r["csf_category"],
            "csf_subcategory": r["csf_subcategory"], "asset": r["asset"],
            "inherent_likelihood": round(L0, 2), "inherent_impact": round(I0, 2),
            "inherent_score": round(inh, 1), "inherent_rating": rating(inh, th),
            "residual_likelihood": round(L, 2), "residual_impact": round(I, 2),
            "residual_score": round(res, 1), "residual_rating": rating(res, th),
            "risk_reduction_pct": round((1 - res / inh) * 100, 0),
            "open_control_gaps": ", ".join(gaps), "owner": r["owner"],
            "timeline": r["timeline"], "treatment": r["treatment"],
        })
    return (pd.DataFrame(rows).sort_values("residual_score", ascending=False, kind="stable")
            .reset_index(drop=True))


def rank_controls(risks, cmap, controls, answers, config, kev_summary=None):
    """'What-if' engine: how many total risk points disappear if control X becomes 'Yes'?"""
    base = score_register(risks, cmap, answers, config, kev_summary)["residual_score"].sum()
    out = []
    for _, c in controls.iterrows():
        cid = c["control_id"]
        if answers.get(cid) == "Yes":
            continue
        trial = dict(answers)
        trial[cid] = "Yes"
        new = score_register(risks, cmap, trial, config, kev_summary)["residual_score"].sum()
        out.append({"control_id": cid, "question": c["question"], "csf_function": c["csf_function"],
                    "current_answer": answers.get(cid, "No"),
                    "risk_points_removed": round(base - new, 1),
                    "risks_affected": ", ".join(cmap[cmap["control_id"] == cid]["risk_id"])})
    return (pd.DataFrame(out).sort_values("risk_points_removed", ascending=False)
            .reset_index(drop=True))


def summary_by_function(register):
    from .loader import CSF_FUNCTIONS
    g = (register.groupby("csf_function")[["inherent_score", "residual_score"]]
         .mean().round(1).reindex(CSF_FUNCTIONS).dropna())
    g["risks"] = register.groupby("csf_function").size()
    return g
