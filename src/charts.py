"""charts.py - draws figures. Returns matplotlib Figure objects so BOTH the
command-line tool (saves to PNG) and the dashboard (shows on screen) can use them."""
import numpy as np
import matplotlib.pyplot as plt
from .scoring import rating

PALETTE = {"Low": "#92D050", "Medium": "#FFD966", "High": "#ED7D31", "Critical": "#C00000"}


def _cell(x):
    return int(min(5, max(1, np.floor(x + 0.5))))   # round half up, clamp to 1..5


def _heat(ax, df, lcol, icol, title, thresholds):
    for l in range(1, 6):
        for i in range(1, 6):
            ax.add_patch(plt.Rectangle((i - .5, l - .5), 1, 1, ec="white", alpha=.85,
                                       color=PALETTE[rating(l * i, thresholds)]))
    cells = {}
    for _, r in df.iterrows():
        cells.setdefault((_cell(r[lcol]), _cell(r[icol])), []).append(str(int(r["risk_id"][1:])))
    for (l, i), ids in cells.items():
        ax.text(i, l, "\n".join(", ".join(ids[k:k + 3]) for k in range(0, len(ids), 3)),
                ha="center", va="center", fontsize=8, fontweight="bold")
    ax.set_xlim(.5, 5.5); ax.set_ylim(.5, 5.5)
    ax.set_xticks(range(1, 6)); ax.set_yticks(range(1, 6))
    ax.set_xlabel("Impact"); ax.set_ylabel("Likelihood"); ax.set_title(title)


def heatmap_pair(register, thresholds):
    fig, axes = plt.subplots(1, 2, figsize=(12, 5.5))
    _heat(axes[0], register, "inherent_likelihood", "inherent_impact", "Inherent risk (no controls)", thresholds)
    _heat(axes[1], register, "residual_likelihood", "residual_impact", "Residual risk (your controls)", thresholds)
    fig.suptitle("Heat maps (numbers are risk IDs)")
    fig.tight_layout()
    return fig


def function_bars(summary):
    fig, ax = plt.subplots(figsize=(8, 4.5))
    summary[["inherent_score", "residual_score"]].plot(kind="bar", ax=ax, color=["#C00000", "#4472C4"])
    ax.set_ylabel("Average risk score (max 25)")
    ax.set_title("Average risk by NIST CSF 2.0 function")
    ax.set_xlabel("")
    plt.setp(ax.get_xticklabels(), rotation=0)
    fig.tight_layout()
    return fig


def top_risks(register, n=10):
    top = register.nlargest(n, "residual_score").iloc[::-1]
    fig, ax = plt.subplots(figsize=(9, 4.5))
    ax.barh(top["risk_id"] + " " + top["risk"].str[:40], top["residual_score"],
            color=[PALETTE[r] for r in top["residual_rating"]])
    ax.set_xlabel("Residual score (max 25)")
    ax.set_title(f"Top {n} remaining risks")
    fig.tight_layout()
    return fig
