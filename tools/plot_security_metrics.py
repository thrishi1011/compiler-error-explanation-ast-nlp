#!/usr/bin/env python3
"""
tools/plot_security_metrics.py
------------------------------
Generates visualization plots for security metrics if matplotlib is installed.
If matplotlib is missing, prints one line and exits with code 0.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_DATA = _ROOT / "data" / "security_metrics.json"
_FIG_DIR = _ROOT / "docs" / "figures"


def main():
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("[plot_security_metrics] matplotlib not installed; skipping figure generation.")
        sys.exit(0)

    if not _DATA.exists():
        print(f"[plot_security_metrics] Metrics data not found at {_DATA}. Run tools/security_benchmark.py first.")
        sys.exit(0)

    _FIG_DIR.mkdir(parents=True, exist_ok=True)
    metrics = json.loads(_DATA.read_text(encoding="utf-8"))

    families = list(metrics.get("by_family", {}).keys())
    if not families:
        print("[plot_security_metrics] No family metrics to plot.")
        sys.exit(0)

    # 1. Detection rate per family (standard vs hard)
    fig, ax = plt.subplots(figsize=(10, 6))
    x = np.arange(len(families))
    width = 0.35

    std_rates = []
    std_err_low = []
    std_err_high = []
    hard_rates = []

    for fam in families:
        f_info = metrics["by_family"][fam]
        s_rate = f_info["standard_detection_rate"]["rate"]
        s_ci = f_info["standard_detection_rate"]["ci_95"]
        std_rates.append(s_rate * 100.0)
        std_err_low.append((s_rate - s_ci[0]) * 100.0)
        std_err_high.append((s_ci[1] - s_rate) * 100.0)

        h_rate = f_info["hard_detection_rate"]["rate"]
        hard_rates.append(h_rate * 100.0)

    ax.bar(x - width/2, std_rates, width, yerr=[std_err_low, std_err_high], capsize=4, label="Standard Set", color="#2b5c8f")
    ax.bar(x + width/2, hard_rates, width, label="Hard Set", color="#d95f02")

    ax.set_ylabel("Detection Rate (TPR %)")
    ax.set_title("Attack Detection Rate by Threat Family (Standard vs Hard)")
    ax.set_xticks(x)
    ax.set_xticklabels(families, rotation=35, ha="right")
    ax.set_ylim(0, 110)
    ax.legend()
    plt.tight_layout()
    fig.savefig(_FIG_DIR / "detection_rate_by_family.png", dpi=150)
    plt.close(fig)

    # 2. ASR Before vs After per family
    fig, ax = plt.subplots(figsize=(10, 6))
    b_asrs = [metrics["by_family"][f]["baseline_asr"] * 100.0 for f in families]
    d_asrs = [metrics["by_family"][f]["defended_asr"] * 100.0 for f in families]

    ax.bar(x - width/2, b_asrs, width, label="Baseline ASR (Before)", color="#e41a1c")
    ax.bar(x + width/2, d_asrs, width, label="Defended ASR (After)", color="#4daf4a")

    ax.set_ylabel("Attack Success Rate (ASR %)")
    ax.set_title("Attack Success Rate: Before (Baseline) vs After Defence")
    ax.set_xticks(x)
    ax.set_xticklabels(families, rotation=35, ha="right")
    ax.set_ylim(0, 110)
    ax.legend()
    plt.tight_layout()
    fig.savefig(_FIG_DIR / "asr_before_vs_after.png", dpi=150)
    plt.close(fig)

    # 3. Latency by Kind
    kinds = list(metrics.get("latency", {}).get("by_kind", {}).keys())
    if kinds:
        fig, ax = plt.subplots(figsize=(9, 5))
        medians = [metrics["latency"]["by_kind"][k]["median"] for k in kinds]
        p95s = [metrics["latency"]["by_kind"][k]["p95"] for k in kinds]
        x_k = np.arange(len(kinds))

        ax.bar(x_k - width/2, medians, width, label="Median Latency (ms)", color="#7570b3")
        ax.bar(x_k + width/2, p95s, width, label="P95 Latency (ms)", color="#e7298a")

        ax.set_ylabel("Review Latency (ms)")
        ax.set_title("Supervisor Review Latency by Input Kind")
        ax.set_xticks(x_k)
        ax.set_xticklabels(kinds, rotation=25, ha="right")
        ax.legend()
        plt.tight_layout()
        fig.savefig(_FIG_DIR / "latency_by_kind.png", dpi=150)
        plt.close(fig)

    # 4. Risk Score Distribution per family
    risk_data = metrics.get("risk_distribution", {})
    if risk_data:
        fig, ax = plt.subplots(figsize=(10, 5))
        r_fams = [f for f in families if f in risk_data] + (["benign"] if "benign" in risk_data else [])
        r_means = [risk_data[f]["mean"] for f in r_fams]
        r_maxs = [risk_data[f]["max"] for f in r_fams]
        x_r = np.arange(len(r_fams))

        ax.bar(x_r - width/2, r_means, width, label="Mean Risk Score", color="#1b9e77")
        ax.bar(x_r + width/2, r_maxs, width, label="Max Risk Score", color="#e6ab02")

        ax.set_ylabel("Risk Score (0 - 100)")
        ax.set_title("Risk Score Distribution Across Threat Families & Benign Cases")
        ax.set_xticks(x_r)
        ax.set_xticklabels(r_fams, rotation=35, ha="right")
        ax.legend()
        plt.tight_layout()
        fig.savefig(_FIG_DIR / "risk_distribution_by_family.png", dpi=150)
        plt.close(fig)

    print(f"[plot_security_metrics] Figures generated successfully in {_FIG_DIR}")


if __name__ == "__main__":
    main()
