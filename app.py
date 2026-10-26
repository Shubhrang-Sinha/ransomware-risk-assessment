"""
Streamlit dashboard.  Run with:   streamlit run app.py
Streamlit re-runs this whole script top-to-bottom every time the user changes a widget,
which is why the numbers and charts update live.
"""
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

from src import charts, export, loader, scoring, threat_intel

DATA = Path(__file__).parent / "data"
st.set_page_config(page_title="Ransomware Risk Assessment", layout="wide")


@st.cache_data
def load_static():
    cfg = loader.load_config(DATA / "config.yaml")
    risks = loader.load_risks(DATA / "risks.csv", cfg)
    controls = loader.load_controls(DATA / "controls.csv")
    cmap = loader.load_control_map(DATA / "control_map.csv", risks, controls)
    return cfg, risks, controls, cmap


@st.cache_data(ttl=6 * 3600)
def get_kev(url, timeout, use_online):
    return threat_intel.load_kev(url, DATA / "kev_sample.json", timeout, use_online)


def show(fig):
    st.pyplot(fig)
    plt.close(fig)


try:
    cfg, risks, controls, cmap = load_static()
except ValueError as e:
    st.error(f"Data file problem: {e}")
    st.stop()

# ----------------------------- sidebar: inputs -----------------------------
st.sidebar.title("Assessment inputs")
org = st.sidebar.text_input("Organisation name", "My Company")
mode = st.sidebar.radio("How do you want to give your security answers?",
                        ["Demo company", "Answer the questionnaire", "Upload answers CSV"])
scan_mode = st.sidebar.radio("Vulnerability scan", ["Sample scan", "Upload scan CSV", "None"])
online = st.sidebar.checkbox("Fetch live CISA KEV feed", value=True,
                             help="If unavailable, a small local sample list is used.")

answers = None
if mode == "Demo company":
    answers = loader.load_answers(DATA / "sample_answers.csv", controls, cfg)
elif mode == "Upload answers CSV":
    template = pd.DataFrame({"control_id": controls["control_id"], "answer": "No"})
    st.sidebar.download_button("Download answers template", template.to_csv(index=False), "answers_template.csv")
    up = st.sidebar.file_uploader("answers.csv (control_id, answer)", type="csv")
    if up is None:
        st.info("Upload an answers CSV in the sidebar (download the template first).")
        st.stop()
    try:
        answers = loader.load_answers(up, controls, cfg)
    except ValueError as e:
        st.error(str(e)); st.stop()
else:
    answers = {}
    st.sidebar.caption("Answer every question honestly. Yes = fully in place.")
    for fn in loader.CSF_FUNCTIONS:
        with st.sidebar.expander(f"{fn} questions", expanded=(fn == "Govern")):
            for _, c in controls[controls["csf_function"] == fn].iterrows():
                answers[c["control_id"]] = st.selectbox(
                    f"{c['control_id']}: {c['question']}", ["No", "Partial", "Yes"],
                    key=f"ans_{c['control_id']}", help=c["why_it_matters"])

kev_summary, kev_label, matched = None, "", None
if scan_mode != "None":
    src = DATA / "sample_vulns.csv"
    if scan_mode == "Upload scan CSV":
        up = st.sidebar.file_uploader("scan.csv (host, internet_facing, cve, severity)", type="csv")
        src = up
    if src is not None:
        try:
            vulns = loader.load_vulns(src)
            kev, kev_label = get_kev(cfg["kev"]["feed_url"], cfg["kev"]["timeout_seconds"], online)
            matched = threat_intel.match_vulns(vulns, kev)
            kev_summary = threat_intel.summarise(matched)
        except ValueError as e:
            st.error(str(e)); st.stop()

register = scoring.score_register(risks, cmap, answers, cfg, kev_summary)
ranking = scoring.rank_controls(risks, cmap, controls, answers, cfg, kev_summary)
th = cfg["rating_thresholds"]

# ----------------------------- main page -----------------------------
st.title(f"Ransomware Risk Assessment: {org}")
st.caption("Mapped to NIST Cybersecurity Framework 2.0. Scores = Likelihood x Impact (1-25).")

tabs = st.tabs(["Overview", "Risk register", "What to fix first", "Threat intelligence", "Export"])

with tabs[0]:
    high = lambda col: int(register[col].isin(["Critical", "High"]).sum())
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Risks assessed", len(register))
    c2.metric("Critical/High (no controls)", high("inherent_rating"))
    c3.metric("Critical/High (now)", high("residual_rating"), delta=high("residual_rating") - high("inherent_rating"), delta_color="inverse")
    c4.metric("Average score", f"{register['residual_score'].mean():.1f}",
              delta=f"{register['residual_score'].mean() - register['inherent_score'].mean():.1f}", delta_color="inverse")
    show(charts.heatmap_pair(register, th))
    left, right = st.columns(2)
    with left:
        show(charts.function_bars(scoring.summary_by_function(register)))
    with right:
        show(charts.top_risks(register))

with tabs[1]:
    f1, f2 = st.columns(2)
    fn_sel = f1.multiselect("CSF function", loader.CSF_FUNCTIONS, default=loader.CSF_FUNCTIONS)
    rt_sel = f2.multiselect("Residual rating", ["Critical", "High", "Medium", "Low"],
                            default=["Critical", "High", "Medium", "Low"])
    view = register[register["csf_function"].isin(fn_sel) & register["residual_rating"].isin(rt_sel)]
    st.dataframe(view[["risk_id", "risk", "csf_function", "csf_subcategory", "inherent_score", "residual_score",
                       "residual_rating", "risk_reduction_pct", "open_control_gaps", "owner", "timeline"]],
                 use_container_width=True, hide_index=True)
    pick = st.selectbox("Details for a risk", register["risk_id"] + " - " + register["risk"])
    row = register[register["risk_id"] == pick.split(" - ")[0]].iloc[0]
    st.write(f"**Scenario:** {row['scenario']}")
    st.write(f"**Recommended treatment:** {row['treatment']}")
    st.write(f"**Open control gaps:** {row['open_control_gaps'] or 'none'}")

with tabs[2]:
    st.subheader("Controls ranked by total risk points removed")
    st.caption("Calculated by pretending each missing control becomes 'Yes' and re-scoring everything.")
    st.dataframe(ranking, use_container_width=True, hide_index=True)
    if not ranking.empty:
        st.bar_chart(ranking.head(10).set_index("control_id")["risk_points_removed"])

with tabs[3]:
    if matched is None:
        st.info("Choose a vulnerability scan in the sidebar to see threat intelligence.")
    else:
        st.write(f"KEV source: **{kev_label}**")
        a, b, c = st.columns(3)
        a.metric("Findings scanned", kev_summary["total"])
        b.metric("Actively exploited (KEV)", kev_summary["kev_total"])
        c.metric("...on internet-facing hosts", kev_summary["kev_internet"])
        st.write(f"Likelihood bump applied to patching/vulnerability risks: **+{scoring.kev_bump(kev_summary, cfg)}**")
        st.dataframe(matched.sort_values("in_kev", ascending=False), use_container_width=True, hide_index=True)

with tabs[4]:
    st.download_button("Download Excel register", export.to_excel_bytes(register, ranking),
                       "risk_register.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    st.download_button("Download CSV", register.to_csv(index=False), "risk_register.csv", "text/csv")
    report = export.to_report_md(org, register, ranking, kev_summary, kev_label, answers)
    st.download_button("Download report (Markdown)", report, "report.md", "text/markdown")
    with st.expander("Preview report"):
        st.markdown(report)
