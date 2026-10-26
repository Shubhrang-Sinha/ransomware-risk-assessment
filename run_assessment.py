"""
Command-line runner (no browser needed).

  python run_assessment.py
  python run_assessment.py --answers my_answers.csv --vulns my_scan.csv --org "Acme Ltd" --out results
  python run_assessment.py --offline        # don't contact CISA
"""
import argparse
from pathlib import Path

import matplotlib
matplotlib.use("Agg")

from src import charts, export, loader, scoring, threat_intel

DATA = Path(__file__).parent / "data"


def run(answers_path, vulns_path, org, out_dir, offline):
    cfg = loader.load_config(DATA / "config.yaml")
    risks = loader.load_risks(DATA / "risks.csv", cfg)
    controls = loader.load_controls(DATA / "controls.csv")
    cmap = loader.load_control_map(DATA / "control_map.csv", risks, controls)
    answers = loader.load_answers(answers_path, controls, cfg)

    kev_summary, kev_label = None, ""
    if vulns_path:
        vulns = loader.load_vulns(vulns_path)
        kev, kev_label = threat_intel.load_kev(cfg["kev"]["feed_url"], DATA / "kev_sample.json",
                                               cfg["kev"]["timeout_seconds"], not offline)
        kev_summary = threat_intel.summarise(threat_intel.match_vulns(vulns, kev))

    register = scoring.score_register(risks, cmap, answers, cfg, kev_summary)
    ranking = scoring.rank_controls(risks, cmap, controls, answers, cfg, kev_summary)

    out = Path(out_dir); out.mkdir(parents=True, exist_ok=True)
    register.to_csv(out / "risk_register.csv", index=False)
    (out / "risk_register.xlsx").write_bytes(export.to_excel_bytes(register, ranking))
    (out / "report.md").write_text(export.to_report_md(org, register, ranking, kev_summary, kev_label, answers),
                                   encoding="utf-8")
    th = cfg["rating_thresholds"]
    charts.heatmap_pair(register, th).savefig(out / "heatmap.png", dpi=150)
    charts.function_bars(scoring.summary_by_function(register)).savefig(out / "csf_function_scores.png", dpi=150)
    charts.top_risks(register).savefig(out / "top_risks.png", dpi=150)

    print(f"Org: {org}")
    print("Inherent ratings:", register["inherent_rating"].value_counts().to_dict())
    print("Residual ratings:", register["residual_rating"].value_counts().to_dict())
    print(f"Average score: {register['inherent_score'].mean():.1f} -> {register['residual_score'].mean():.1f}")
    if kev_summary:
        print(f"KEV ({kev_label}):", kev_summary)
    print("Top 5 next controls:")
    print(ranking.head(5)[["control_id", "risk_points_removed", "question"]].to_string(index=False))
    print(f"Files written to {out}/")
    return register, ranking


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Ransomware risk assessment (NIST CSF 2.0)")
    ap.add_argument("--answers", default=str(DATA / "sample_answers.csv"))
    ap.add_argument("--vulns", default=str(DATA / "sample_vulns.csv"), help="scan CSV, or '' to skip")
    ap.add_argument("--org", default="Demo Company")
    ap.add_argument("--out", default="output")
    ap.add_argument("--offline", action="store_true")
    a = ap.parse_args()
    run(a.answers, a.vulns or None, a.org, a.out, a.offline)
