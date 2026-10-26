"""
loader.py - reads the CSV/YAML input files and CHECKS them.

Why this exists: real users will edit these files by hand and make mistakes
(typos, a score of 7 on a 1-5 scale, a missing column). It is far better to stop
with a clear message than to produce silently wrong results.
"""
import pandas as pd
import yaml

CSF_FUNCTIONS = ["Govern", "Identify", "Protect", "Detect", "Respond", "Recover"]
RISK_COLUMNS = ["risk_id", "risk", "scenario", "csf_function", "csf_category",
                "csf_subcategory", "asset", "base_likelihood", "base_impact",
                "kev_sensitive", "owner", "timeline", "treatment"]


def _need(df, columns, name):
    missing = [c for c in columns if c not in df.columns]
    if missing:
        raise ValueError(f"{name}: missing column(s) {missing}")


def load_config(path):
    with open(path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    for key in ("scale_max", "rating_thresholds", "answer_values", "kev"):
        if key not in cfg:
            raise ValueError(f"config: missing setting '{key}'")
    return cfg


def load_risks(path, config):
    df = pd.read_csv(path)
    _need(df, RISK_COLUMNS, "risks")
    if df["risk_id"].duplicated().any():
        raise ValueError("risks: duplicate risk_id values")
    smax = config["scale_max"]
    for col in ("base_likelihood", "base_impact"):
        if not df[col].between(1, smax).all():
            raise ValueError(f"risks: '{col}' must be between 1 and {smax}")
    bad = set(df["csf_function"]) - set(CSF_FUNCTIONS)
    if bad:
        raise ValueError(f"risks: unknown csf_function {sorted(bad)}; use {CSF_FUNCTIONS}")
    df["kev_sensitive"] = (df["kev_sensitive"].astype(str).str.strip().str.lower()
                           .isin(["true", "1", "yes"]))
    return df


def load_controls(path):
    df = pd.read_csv(path)
    _need(df, ["control_id", "question", "csf_function", "why_it_matters"], "controls")
    if df["control_id"].duplicated().any():
        raise ValueError("controls: duplicate control_id values")
    return df


def load_control_map(path, risks, controls):
    """The many-to-many link: which control reduces which risk, and by how much."""
    df = pd.read_csv(path)
    _need(df, ["control_id", "risk_id", "likelihood_effect", "impact_effect"], "control_map")
    unknown_c = set(df["control_id"]) - set(controls["control_id"])
    unknown_r = set(df["risk_id"]) - set(risks["risk_id"])
    if unknown_c or unknown_r:
        raise ValueError(f"control_map: unknown control ids {sorted(unknown_c)} / risk ids {sorted(unknown_r)}")
    for col in ("likelihood_effect", "impact_effect"):
        if not df[col].between(0, 1).all():
            raise ValueError(f"control_map: '{col}' must be between 0 and 1")
    return df


def load_answers(source, controls, config):
    """Questionnaire answers -> {control_id: 'Yes'|'Partial'|'No'}. Unanswered = 'No'."""
    df = pd.read_csv(source)
    _need(df, ["control_id", "answer"], "answers")
    df["control_id"] = df["control_id"].astype(str).str.strip().str.upper()
    df["answer"] = df["answer"].astype(str).str.strip().str.title()
    valid = set(config["answer_values"])
    bad = df[~df["answer"].isin(valid)]
    if not bad.empty:
        raise ValueError(f"answers: invalid answer(s) {sorted(set(bad['answer']))}; allowed {sorted(valid)}")
    unknown = set(df["control_id"]) - set(controls["control_id"])
    if unknown:
        raise ValueError(f"answers: unknown control_id(s) {sorted(unknown)}")
    answers = {cid: "No" for cid in controls["control_id"]}
    answers.update(dict(zip(df["control_id"], df["answer"])))
    return answers


def load_vulns(source):
    """Vulnerability-scan export. Needs: host, internet_facing, cve, severity."""
    df = pd.read_csv(source)
    _need(df, ["host", "internet_facing", "cve", "severity"], "vulnerability scan")
    df["cve"] = df["cve"].astype(str).str.strip().str.upper()
    df["internet_facing"] = (df["internet_facing"].astype(str).str.strip().str.lower()
                             .isin(["yes", "true", "1", "y"]))
    return df
