#!/usr/bin/env python3
"""
Generates README-optimised PNG charts into docs/.
Run from the folder containing results.csv, site_study_results.csv, sites_300.csv.
    python make_readme_assets.py
"""
import os
import numpy as np, pandas as pd
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUT = "docs"; os.makedirs(OUT, exist_ok=True)
plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 11,
    "axes.linewidth": 0.8, "axes.grid": True, "grid.alpha": 0.2,
    "savefig.dpi": 160, "savefig.bbox": "tight", "figure.facecolor": "white",
})
BLUE, GREY, AMBER, GREEN, RED = "#2b6cb0", "#cbd5e0", "#d69e2e", "#2f855a", "#c53030"

b = pd.read_csv("results.csv")
s = pd.read_csv("site_study_results.csv").merge(
    pd.read_csv("sites_300.csv")[["domain", "category"]], on="domain", how="left")
rb, rs = b[b.reachable == True], s[s.reachable == True]

rows = []
for c, g in s.groupby("category"):
    r = g[g.reachable == True]
    rows.append({"category": c, "reachable": len(r),
                 "hyb": round(100*(g.pqc_status == "HYBRID_PQC").sum()/len(r), 1),
                 "hsts": round(100*r.hsts.sum()/len(r), 1),
                 "tls13": round(100*(r.tls_version == "TLSv1.3").sum()/len(r), 1)})
cat = pd.DataFrame(rows)

# 1 — sectoral gap (headline)
fig, ax = plt.subplots(figsize=(9, 4.6))
c = cat.sort_values("hyb")
cols = [RED if v < 50 else (AMBER if v < 65 else BLUE) for v in c.hyb]
ax.barh(range(len(c)), c.hyb, color=cols, edgecolor="white", linewidth=1.2, height=0.72)
ax.set_yticks(range(len(c)))
ax.set_yticklabels([f"{r.category}  (n={r.reachable})" for r in c.itertuples()], fontsize=10)
ax.axvline(63.4, ls="--", lw=1.3, color="#4a5568", zorder=1)
for i, v in enumerate(c.hyb):
    off = 3.2 if abs(v - 63.4) < 3 else 1.3   # avoid the mean line
    ax.text(v + off, i, f"{v}%", va="center", fontsize=10, fontweight="bold",
            color=cols[i], zorder=4)
ax.text(63.4, len(c) - 0.32, "overall 63.4%", fontsize=9, color="#4a5568",
        ha="center", va="bottom")
ax.set_ylim(-0.7, len(c) + 0.15)
ax.set_xlabel("Hybrid post-quantum key agreement, % of reachable endpoints", fontsize=11)
ax.set_title("Banking trails every other sector on post-quantum TLS",
             fontsize=13, fontweight="bold", pad=12, loc="left")
ax.set_xlim(0, 100); ax.spines[["top", "right"]].set_visible(False)
plt.savefig(f"{OUT}/sector_gap.png"); plt.close()

# 2 — KEX resolution
fig, ax = plt.subplots(figsize=(8, 4.2))
t13b, t13s = rb[rb.tls_version == "TLSv1.3"], rs[rs.tls_version == "TLSv1.3"]
hy = [(rb.pqc_status == "HYBRID_PQC").sum(), (rs.pqc_status == "HYBRID_PQC").sum(),
      (t13b.pqc_status == "HYBRID_PQC").sum(), (t13s.pqc_status == "HYBRID_PQC").sum()]
tot = [len(rb), len(rs), len(t13b), len(t13s)]
hp = [100*h/t for h, t in zip(hy, tot)]
x = np.arange(4)
ax.bar(x, hp, 0.62, label="HYBRID_PQC  (X25519MLKEM768, verified)",
       color=BLUE, edgecolor="white", linewidth=1.2)
ax.bar(x, [100-v for v in hp], 0.62, bottom=hp,
       label="NOT_VERIFIED  (group not observed)", color=GREY,
       edgecolor="white", linewidth=1.2)
for i, v in enumerate(hp):
    ax.text(i, v/2, f"{v:.1f}%", ha="center", va="center", color="white",
            fontweight="bold", fontsize=12)
ax.set_xticks(x)
ax.set_xticklabels([f"Banking\nall reachable\n(n={tot[0]})", f"General\nall reachable\n(n={tot[1]})",
                    f"Banking\nTLS 1.3 only\n(n={tot[2]})", f"General\nTLS 1.3 only\n(n={tot[3]})"],
                   fontsize=9.5)
ax.set_ylabel("% of endpoints", fontsize=11); ax.set_ylim(0, 100)
ax.set_title("Key-exchange resolution: what was actually observed",
             fontsize=13, fontweight="bold", pad=12, loc="left")
ax.legend(fontsize=9.5, loc="upper center", bbox_to_anchor=(0.5, -0.16), ncol=2, frameon=False)
ax.spines[["top", "right"]].set_visible(False)
plt.savefig(f"{OUT}/kex_resolution.png"); plt.close()

# 3 — TLS 1.3 vs hybrid
fig, ax = plt.subplots(figsize=(7.2, 4.8))
for r in cat.itertuples():
    col = RED if r.category == "Banking/Financial" else BLUE
    sz = 190 if r.category == "Banking/Financial" else 90
    ax.scatter(r.tls13, r.hyb, s=sz, color=col, alpha=0.85, edgecolor="white",
               linewidth=1.4, zorder=3)
    nudge = {"Media/Streaming": (6, 9), "Browser Ecosystem": (6, -11)}
    ax.annotate(r.category, (r.tls13, r.hyb), fontsize=8,
                xytext=nudge.get(r.category, (6, -3)),
                textcoords="offset points", color="#2d3748")
ax.set_xlabel("TLS 1.3 adoption (% of reachable)", fontsize=11)
ax.set_ylabel("Hybrid PQC adoption (% of reachable)", fontsize=11)
ax.set_title("The gap is not explained by protocol version alone",
             fontsize=13, fontweight="bold", pad=12, loc="left")
ax.spines[["top", "right"]].set_visible(False)
ax.set_xlim(60, 105); ax.set_ylim(35, 95)
plt.savefig(f"{OUT}/tls_vs_hybrid.png"); plt.close()

# 4 — HSTS
fig, ax = plt.subplots(figsize=(9, 3.8))
c = cat.sort_values("hsts", ascending=False)
ax.bar(range(len(c)), c.hsts, 0.66, color=[GREEN if v >= 58 else AMBER for v in c.hsts],
       edgecolor="white", linewidth=1.2)
ax.axhline(58.0, ls="--", lw=1.2, color="#4a5568")
ax.text(len(c)-2.6, 60.5, "overall 58.0%", fontsize=9, color="#4a5568")
ax.set_xticks(range(len(c)))
ax.set_xticklabels(c.category, rotation=32, ha="right", fontsize=9)
ax.set_ylabel("HSTS present (%)", fontsize=11); ax.set_ylim(0, 100)
ax.set_title("HSTS deployment by sector", fontsize=13, fontweight="bold", pad=12, loc="left")
ax.spines[["top", "right"]].set_visible(False)
plt.savefig(f"{OUT}/hsts.png"); plt.close()

print(f"Wrote 4 PNGs to {OUT}/")