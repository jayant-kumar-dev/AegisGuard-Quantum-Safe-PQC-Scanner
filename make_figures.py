#!/usr/bin/env python3
"""
Regenerates all six figures for the AegisGuard paper.

Place this file in the folder containing results.csv, site_study_results.csv
and sites_300.csv, then run:

    pip install pandas matplotlib
    python make_figures.py

Writes figs/fig1_kex.pdf ... figs/fig6_cert.pdf next to this script.
"""
import os
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BANK = "results.csv"
SITE = "site_study_results.csv"
TARGETS = "sites_300.csv"
OUT = "figs"

plt.rcParams.update({
    "font.family": "serif", "font.serif": ["DejaVu Serif"], "font.size": 8,
    "axes.linewidth": 0.6, "axes.grid": True, "grid.alpha": 0.25,
    "grid.linewidth": 0.4, "savefig.dpi": 400, "savefig.bbox": "tight",
})
C = {"h": "#2b6cb0", "n": "#b0b7c3", "t12": "#d69e2e",
     "t13": "#2f855a", "f": "#c53030"}

os.makedirs(OUT, exist_ok=True)
b = pd.read_csv(BANK)
s = pd.read_csv(SITE).merge(
    pd.read_csv(TARGETS)[["domain", "category"]], on="domain", how="left")
rb, rs = b[b.reachable == True], s[s.reachable == True]

# per-category summary
rows = []
for c, g in s.groupby("category"):
    r = g[g.reachable == True]
    rows.append({
        "category": c, "total": len(g), "reachable": len(r),
        "tls12": int((r.tls_version == "TLSv1.2").sum()),
        "tls13": int((r.tls_version == "TLSv1.3").sum()),
        "hybrid": int((g.pqc_status == "HYBRID_PQC").sum()),
        "hybrid_pct_reach": round(100 * (g.pqc_status == "HYBRID_PQC").sum() / len(r), 1),
        "hsts_pct": round(100 * r.hsts.sum() / len(r), 1),
    })
cat = pd.DataFrame(rows)

# ---- Fig 1: KEX resolution ----
fig, ax = plt.subplots(figsize=(3.4, 2.3))
t13b = rb[rb.tls_version == "TLSv1.3"]
t13s = rs[rs.tls_version == "TLSv1.3"]
hy = [(rb.pqc_status == "HYBRID_PQC").sum(), (rs.pqc_status == "HYBRID_PQC").sum(),
      (t13b.pqc_status == "HYBRID_PQC").sum(), (t13s.pqc_status == "HYBRID_PQC").sum()]
tot = [len(rb), len(rs), len(t13b), len(t13s)]
hp = [100 * h / t for h, t in zip(hy, tot)]
npc = [100 - v for v in hp]
labels = [f"Banking\n(n={tot[0]})", f"General\n(n={tot[1]})",
          f"Banking\nTLS1.3 (n={tot[2]})", f"General\nTLS1.3 (n={tot[3]})"]
x = np.arange(4)
ax.bar(x, hp, 0.6, label="HYBRID_PQC (X25519MLKEM768)", color=C["h"], edgecolor="k", linewidth=0.4)
ax.bar(x, npc, 0.6, bottom=hp, label="NOT_VERIFIED", color=C["n"], edgecolor="k", linewidth=0.4)
for i, a in enumerate(hp):
    ax.text(i, a / 2, f"{a:.1f}%", ha="center", va="center", fontsize=7, color="w", fontweight="bold")
ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=6.5)
ax.set_ylabel("Share of reachable endpoints (%)"); ax.set_ylim(0, 100)
ax.legend(fontsize=6, loc="lower right", framealpha=0.95)
plt.savefig(f"{OUT}/fig1_kex.pdf"); plt.close()

# ---- Fig 2: hybrid adoption by sector ----
fig, ax = plt.subplots(figsize=(3.4, 2.6))
c = cat.sort_values("hybrid_pct_reach")
overall = round(100 * (rs.pqc_status == "HYBRID_PQC").sum() / len(rs), 1)
cols = [C["f"] if v < 50 else (C["t12"] if v < 65 else C["h"]) for v in c.hybrid_pct_reach]
ax.barh(range(len(c)), c.hybrid_pct_reach, color=cols, edgecolor="k", linewidth=0.4, height=0.7)
ax.set_yticks(range(len(c)))
ax.set_yticklabels([f"{r.category} ({r.reachable})" for r in c.itertuples()], fontsize=6.5)
for i, v in enumerate(c.hybrid_pct_reach):
    ax.text(v + 1.2, i, f"{v:.1f}", va="center", fontsize=6.2)
ax.axvline(overall, ls="--", lw=0.8, color="k")
ax.text(overall + 1.1, 0.15, f"overall {overall}%", fontsize=5.8, rotation=90)
ax.set_xlabel("Hybrid PQC adoption among reachable endpoints (%)"); ax.set_xlim(0, 100)
plt.savefig(f"{OUT}/fig2_category.pdf"); plt.close()

# ---- Fig 3: TLS version by sector ----
fig, ax = plt.subplots(figsize=(3.4, 2.3))
c = cat.sort_values("tls13", ascending=False)
p13 = 100 * c.tls13 / c.reachable
p12 = 100 * c.tls12 / c.reachable
x = np.arange(len(c))
ax.bar(x, p13, 0.65, label="TLS 1.3", color=C["t13"], edgecolor="k", linewidth=0.4)
ax.bar(x, p12, 0.65, bottom=p13, label="TLS 1.2", color=C["t12"], edgecolor="k", linewidth=0.4)
ax.set_xticks(x); ax.set_xticklabels(c.category, rotation=38, ha="right", fontsize=5.8)
ax.set_ylabel("Share of reachable (%)"); ax.set_ylim(0, 100)
ax.legend(fontsize=6, loc="lower left")
plt.savefig(f"{OUT}/fig3_tls.pdf"); plt.close()

# ---- Fig 4: HSTS by sector ----
fig, ax = plt.subplots(figsize=(3.4, 2.3))
c = cat.sort_values("hsts_pct", ascending=False)
oh = round(100 * rs.hsts.sum() / len(rs), 1)
ax.bar(np.arange(len(c)), c.hsts_pct, 0.65, color=C["h"], edgecolor="k", linewidth=0.4)
ax.axhline(oh, ls="--", lw=0.8, color="k")
ax.text(len(c) - 3.6, oh + 2, f"overall {oh}%", fontsize=6)
ax.set_xticks(np.arange(len(c))); ax.set_xticklabels(c.category, rotation=38, ha="right", fontsize=5.8)
ax.set_ylabel("HSTS present (% of reachable)"); ax.set_ylim(0, 100)
plt.savefig(f"{OUT}/fig4_hsts.pdf"); plt.close()

# ---- Fig 5: risk grades ----
fig, ax = plt.subplots(figsize=(3.4, 2.1))
gr = ["A+", "A", "B", "C", "D", "F"]
bg = [int((b.risk_grade == g).sum()) for g in gr]
sg = [int((s.risk_grade == g).sum()) for g in gr]
x = np.arange(len(gr)); w = 0.38
ax.bar(x - w/2, [100*v/len(b) for v in bg], w, label=f"Banking (n={len(b)})",
       color=C["h"], edgecolor="k", linewidth=0.4)
ax.bar(x + w/2, [100*v/len(s) for v in sg], w, label=f"General (n={len(s)})",
       color=C["t13"], edgecolor="k", linewidth=0.4)
ax.set_xticks(x); ax.set_xticklabels(gr); ax.set_xlabel("AegisGuard risk grade")
ax.set_ylabel("Share of endpoints (%)"); ax.legend(fontsize=6)
plt.savefig(f"{OUT}/fig5_grades.pdf"); plt.close()

# ---- Fig 6: certificate validity ECDF ----
fig, ax = plt.subplots(figsize=(3.4, 2.1))
for d, lab, col in [(rb, f"Banking (n={len(rb)})", C["h"]),
                    (rs, f"General (n={len(rs)})", C["t13"])]:
    v = np.sort(d.certificate_days_remaining.dropna().values)
    ax.step(v, np.arange(1, len(v)+1)/len(v)*100, where="post", label=lab, color=col, lw=1.2)
ax.axvline(90, ls="--", lw=0.8, color=C["f"])
ax.text(93, 12, "90-day\n(ACME-typical)", fontsize=5.6, color=C["f"])
ax.set_xlabel("Certificate validity remaining (days)")
ax.set_ylabel("Cumulative % of endpoints")
ax.legend(fontsize=6, loc="lower right"); ax.set_xlim(0, 250)
plt.savefig(f"{OUT}/fig6_cert.pdf"); plt.close()

print(f"Wrote 6 figures to {OUT}/")
print(f"Reachable: banking {len(rb)}/{len(b)}, general {len(rs)}/{len(s)}")
print(f"Hybrid: {hp[0]:.1f}% banking, {hp[1]:.1f}% general")