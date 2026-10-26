import pandas as pd
import pytest
from pathlib import Path

from src import loader, scoring, threat_intel

DATA = Path(__file__).parent.parent / "data"


@pytest.fixture(scope="module")
def world():
    cfg = loader.load_config(DATA / "config.yaml")
    risks = loader.load_risks(DATA / "risks.csv", cfg)
    controls = loader.load_controls(DATA / "controls.csv")
    cmap = loader.load_control_map(DATA / "control_map.csv", risks, controls)
    return cfg, risks, controls, cmap


def all_answers(controls, value):
    return {c: value for c in controls["control_id"]}


def test_rating_boundaries(world):
    th = world[0]["rating_thresholds"]
    assert scoring.rating(5, th) == "Low"
    assert scoring.rating(6, th) == "Medium"
    assert scoring.rating(12, th) == "Medium"
    assert scoring.rating(13, th) == "High"
    assert scoring.rating(19, th) == "High"
    assert scoring.rating(20, th) == "Critical"


def test_no_controls_means_residual_equals_inherent(world):
    cfg, risks, controls, cmap = world
    reg = scoring.score_register(risks, cmap, all_answers(controls, "No"), cfg)
    assert (reg["inherent_score"] == reg["residual_score"]).all()


def test_all_controls_reduce_every_risk(world):
    cfg, risks, controls, cmap = world
    reg = scoring.score_register(risks, cmap, all_answers(controls, "Yes"), cfg)
    assert (reg["residual_score"] < reg["inherent_score"]).all()
    assert (reg["residual_likelihood"] >= 1).all() and (reg["residual_impact"] >= 1).all()


def test_partial_is_between_no_and_yes(world):
    cfg, risks, controls, cmap = world
    s = lambda v: scoring.score_register(risks, cmap, all_answers(controls, v), cfg)["residual_score"].sum()
    assert s("Yes") < s("Partial") < s("No")


def test_every_risk_has_at_least_one_control(world):
    _, risks, _, cmap = world
    assert set(risks["risk_id"]) <= set(cmap["risk_id"])


def test_mfa_lowers_remote_access_risk(world):
    cfg, risks, controls, cmap = world
    base = all_answers(controls, "No")
    with_mfa = {**base, "C03": "Yes"}
    r0 = scoring.score_register(risks, cmap, base, cfg).set_index("risk_id").loc["R02", "residual_score"]
    r1 = scoring.score_register(risks, cmap, with_mfa, cfg).set_index("risk_id").loc["R02", "residual_score"]
    assert r1 < r0


def test_kev_bump_raises_sensitive_risks_and_is_capped(world):
    cfg, risks, controls, cmap = world
    no = all_answers(controls, "No")
    plain = scoring.score_register(risks, cmap, no, cfg).set_index("risk_id")
    bumped = scoring.score_register(risks, cmap, no, cfg, {"kev_internet": 2, "kev_internal": 0}).set_index("risk_id")
    assert bumped.loc["R03", "inherent_likelihood"] == min(5, plain.loc["R03", "inherent_likelihood"] + 1)
    assert bumped.loc["R01", "inherent_likelihood"] == plain.loc["R01", "inherent_likelihood"]  # not KEV-sensitive
    assert (bumped["inherent_likelihood"] <= 5).all()


def test_ranking_is_sorted_and_skips_yes(world):
    cfg, risks, controls, cmap = world
    ans = all_answers(controls, "No"); ans["C03"] = "Yes"
    rk = scoring.rank_controls(risks, cmap, controls, ans, cfg)
    assert "C03" not in set(rk["control_id"])
    assert rk["risk_points_removed"].is_monotonic_decreasing
    assert (rk["risk_points_removed"] >= 0).all()


def test_loader_rejects_bad_likelihood(world, tmp_path):
    cfg = world[0]
    bad = pd.read_csv(DATA / "risks.csv"); bad.loc[0, "base_likelihood"] = 9
    bad.to_csv(tmp_path / "r.csv", index=False)
    with pytest.raises(ValueError, match="between 1 and 5"):
        loader.load_risks(tmp_path / "r.csv", cfg)


def test_loader_rejects_invalid_answer(world, tmp_path):
    cfg, _, controls, _ = world
    pd.DataFrame({"control_id": ["C01"], "answer": ["Maybe"]}).to_csv(tmp_path / "a.csv", index=False)
    with pytest.raises(ValueError, match="invalid answer"):
        loader.load_answers(tmp_path / "a.csv", controls, cfg)


def test_answers_are_case_insensitive_and_default_to_no(world, tmp_path):
    cfg, _, controls, _ = world
    pd.DataFrame({"control_id": ["c01"], "answer": ["yes"]}).to_csv(tmp_path / "a.csv", index=False)
    ans = loader.load_answers(tmp_path / "a.csv", controls, cfg)
    assert ans["C01"] == "Yes" and ans["C02"] == "No"


def test_kev_matching_offline():
    kev, label = threat_intel.load_kev("http://invalid.invalid", DATA / "kev_sample.json", 1, use_online=False)
    matched = threat_intel.match_vulns(loader.load_vulns(DATA / "sample_vulns.csv"), kev)
    s = threat_intel.summarise(matched)
    assert s["kev_total"] == 5 and s["kev_internet"] == 3 and s["kev_internal"] == 2
    assert "offline" in label
