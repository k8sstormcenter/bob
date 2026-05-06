#!/usr/bin/env python3
"""Render metrics.json into an animated GIF showing the tuning process.

Layout: Hybrid Radar + Kill-Chain Heatmap with per-attack detection detail.

  ┌────────────┬──────────────────┬────────────┐
  │  Radar     │  Profile Shrink  │  Score +   │
  │  (MITRE    │  (bar chart,     │  Sparkline │
  │   12-spoke │   ghost base,    │            │
  │   detected │   fixed axes)    │            │
  │   vs total)│                  │            │
  ├────────────┴──────────────────┴────────────┤
  │  Kill-Chain Detail Panel (full width)       │
  │  Per-attack cells: green=detected,          │
  │  red=missed, grey=no expectation            │
  └─────────────────────────────────────────────┘

Requires: pip install pillow matplotlib numpy

Usage:
    python3 render-metrics-gif.py results/metrics.json results/tune.gif
    python3 render-metrics-gif.py results/metrics.json results/tune.gif --title "webapp (ubuntu-24.04)"
"""
import argparse
import json
import sys
from io import BytesIO
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import numpy as np
from matplotlib.patches import Patch
from PIL import Image

# ── Colour palette (Tokyo Night) ─────────────────────────────────────────
C_BG       = "#1a1b26"
C_PANEL    = "#24283b"
C_BORDER   = "#414868"
C_TEXT     = "#c0caf5"
C_DIM      = "#565f89"
C_GREEN    = "#9ece6a"
C_RED      = "#f7768e"
C_YELLOW   = "#e0af68"
C_BLUE     = "#7aa2f7"
C_CYAN     = "#7dcfff"
C_GREY     = "#3b4261"

MITRE_PHASES = [
    "Recon", "Init Access", "Execution", "Persistence", "Priv Esc",
    "Def Evasion", "Cred Access", "Discovery", "Lat Movement",
    "Collection", "Exfil", "Impact",
]

PHASE_PREFIXES = {
    "recon": "Recon", "ssrf": "Init Access", "lfi": "Init Access",
    "cmdinject-whoami": "Execution", "cmdinject-ps": "Execution",
    "cmdinject-devshm": "Execution", "exec-whoami": "Execution",
    "exec-devshm": "Execution", "exec-from-devshm": "Execution",
    "exec-id": "Execution", "lua-fileless": "Execution",
    "lua-reverse": "Execution", "lua-cve": "Init Access",
    "painless": "Execution", "api-stix": "Execution",
    "persist": "Persistence", "api-server-sync": "Persistence",
    "api-trigger": "Persistence", "exec-cake-extract": "Persistence",
    "cmdinject-unshare": "Priv Esc", "exec-unshare": "Priv Esc",
    "sql-create-super": "Priv Esc",
    "cmdinject-drifted": "Def Evasion", "exec-drifted": "Def Evasion",
    "cmdinject-history": "Def Evasion", "exec-history": "Def Evasion",
    "evasion": "Def Evasion", "lua-ld": "Def Evasion", "exec-ld": "Def Evasion",
    "exec-ptrace": "Def Evasion", "api-warninglist": "Def Evasion",
    "cmdinject-sa-token": "Cred Access", "cmdinject-etc-passwd": "Cred Access",
    "cmdinject-etc-shadow": "Cred Access", "cmdinject-ls-secrets": "Cred Access",
    "cmdinject-symlink": "Cred Access", "postexploit-etc-shadow": "Cred Access",
    "exec-sa-token": "Cred Access", "exec-etc-shadow": "Cred Access",
    "exec-etc-passwd": "Cred Access", "exec-read-shadow": "Cred Access",
    "exec-read-passwd": "Cred Access", "exec-symlink": "Cred Access",
    "exec-read-db": "Cred Access", "exec-read-valkey": "Cred Access",
    "lua-credential": "Cred Access", "sql-dump-pg": "Cred Access",
    "sql-read": "Cred Access", "neighbor-sa": "Cred Access",
    "neighbor-etc": "Cred Access", "exec-mysql": "Cred Access",
    "exec-encryption": "Cred Access", "exec-gpg": "Cred Access",
    "cmdinject-proc-environ": "Discovery", "cmdinject-k8s-api": "Discovery",
    "cmdinject-net-recon": "Discovery", "cmdinject-ps-aux": "Discovery",
    "exec-proc-environ": "Discovery", "exec-read-environ": "Discovery",
    "exec-net-recon": "Discovery", "exec-k8s-api": "Discovery",
    "exec-enumerate": "Discovery", "exec-cake-admin": "Discovery",
    "exec-env-dump": "Discovery", "exec-pg-dump": "Discovery",
    "exec-network-recon": "Discovery", "recon-info": "Recon",
    "recon-config": "Recon", "recon-client": "Recon", "recon-keys": "Recon",
    "recon-cluster": "Recon", "recon-all": "Recon", "recon-mapping": "Recon",
    "sql-dump-all": "Recon", "sql-dump-settings": "Recon",
    "neighbor-k8s": "Discovery", "neighbor-proc": "Discovery",
    "neighbor-dns": "Discovery", "neighbor-app": "Recon",
    "lateral": "Lat Movement", "exec-ssh": "Lat Movement",
    "cmdinject-data-stage": "Collection", "exec-data-stage": "Collection",
    "api-bulk-export": "Collection", "api-export-stix": "Collection",
    "api-upload": "Collection", "api-galaxy": "Collection",
    "sql-copy": "Collection", "sql-large": "Collection",
    "exfil": "Exfil", "reindex-exfil": "Exfil", "reindex-remote": "Exfil",
    "cmdinject-c2-beacon": "Exfil", "cmdinject-dns-anomaly": "Exfil",
    "postexploit-dns": "Exfil", "exec-dns-anomaly": "Exfil",
    "lua-dns": "Exfil", "snapshot-repo": "Exfil",
    "impact": "Impact", "cmdinject-crypto": "Impact", "exec-crypto": "Impact",
    "sql-drop": "Impact",
    "api-create": "Execution", "api-ssrf": "Init Access",
    "api-fetch": "Init Access", "ssrf-cloud": "Init Access",
    "ssrf-internal": "Init Access", "sqli": "Init Access",
    "api-sqli": "Init Access",
    "neighbor-drifted": "Def Evasion", "neighbor-devshm": "Execution",
    # CVE-based attacks
    "cve-2022-0543": "Init Access", "cve-2022-24735": "Execution",
    "cve-2022-35951": "Impact", "cve-2023-28856": "Impact",
    "cve-2023-45145": "Priv Esc", "cve-module": "Persistence",
    "auth-brute": "Init Access", "lua-os": "Execution", "lua-network": "Discovery",
    "cve-2021-41773": "Init Access", "cve-2012-1823": "Init Access",
    "cmdinject-webshell": "Persistence", "cmdinject-reverse": "Execution",
    "cmdinject-download": "Execution", "cmdinject-php-filter": "Cred Access",
    "cmdinject-python": "Execution", "cmdinject-perl": "Execution",
    "cmdinject-k8s-enum": "Discovery", "cmdinject-proc-maps": "Discovery",
    "cve-2014-3120": "Execution", "cve-2015-1427": "Execution",
    "cve-2015-5531": "Cred Access", "cve-2021-44228": "Init Access",
    "cve-2018-17246": "Cred Access", "painless-runtime": "Execution",
    "es-template": "Execution", "es-watcher": "Persistence",
    "es-ingest": "Execution",
    "cve-2019-9193": "Execution", "sql-plpython": "Execution",
    "sql-plperlu": "Execution", "cve-2018-1058": "Priv Esc",
    "sql-lo-export": "Persistence", "sql-dblink": "Lat Movement",
    "sql-alter-system": "Persistence", "sql-pg-read": "Cred Access",
    "cve-2023-5868": "Discovery", "cve-2023-39417": "Priv Esc",
    "cve-2020-28043": "Init Access", "cve-2024-29859": "Cred Access",
    "cve-2022-29529": "Execution", "cve-2022-47928": "Priv Esc",
    "cve-2023-37307": "Cred Access", "php-deserialization": "Init Access",
    "api-attribute-enrichment": "Init Access", "cakephp-debug": "Recon",
    "api-malicious-php": "Persistence",
}


def classify_attack(name: str) -> str:
    best, best_len = "Execution", 0
    for prefix, phase in PHASE_PREFIXES.items():
        if name.startswith(prefix) and len(prefix) > best_len:
            best, best_len = phase, len(prefix)
    return best


def short_name(name: str) -> str:
    """Shorten attack name for cell labels."""
    # strip common prefixes to save space
    for pfx in ("cmdinject-", "postexploit-", "exec-", "api-", "sql-", "lua-",
                 "neighbor-", "recon-", "ssrf-", "sqli-", "lfi-", "painless-"):
        if name.startswith(pfx):
            return name[len(pfx):]
    return name


def compute_global_limits(records: list[dict]) -> dict:
    keys = ["opens", "execs", "syscalls", "endpoints", "policy_rules"]
    max_val = max(r[k] for r in records for k in keys)
    max_score = max(r["score"] for r in records)
    return {"max_entries": int(max_val * 1.2) or 10, "max_score": max(max_score + 2, 3)}


def build_attack_analysis(attacks, detections):
    """Build per-attack detection data + per-phase grouping."""
    det_by_attack = {}
    for d in detections:
        aname = d.get("attack_name", "")
        if aname not in det_by_attack:
            det_by_attack[aname] = {"found": set(), "missed": set(), "rules_found": [], "rules_missed": []}
        if d["found"]:
            det_by_attack[aname]["found"].add(d["rule_id"])
            det_by_attack[aname]["rules_found"].append(d["rule_id"])
        else:
            det_by_attack[aname]["missed"].add(d["rule_id"])
            det_by_attack[aname]["rules_missed"].append(d["rule_id"])

    phase_attacks = {p: [] for p in MITRE_PHASES}
    for a in attacks:
        phase = classify_attack(a["name"])
        info = det_by_attack.get(a["name"], {"found": set(), "missed": set(), "rules_found": [], "rules_missed": []})
        has_det = a["name"] in det_by_attack
        phase_attacks[phase].append({
            "name": a["name"],
            "short": short_name(a["name"]),
            "success": a["success"],
            "all_found": has_det and len(info["missed"]) == 0,
            "any_missed": has_det and len(info["missed"]) > 0,
            "has_expectations": has_det,
            "rules_found": sorted(info["found"]),
            "rules_missed": sorted(info["missed"]),
        })

    return det_by_attack, phase_attacks


def draw_frame(records, up_to, title, limits, width=1280, height=900):
    fig = plt.figure(figsize=(width / 100, height / 100), dpi=100)
    fig.patch.set_facecolor(C_BG)

    # Top row: 3 columns (radar wider, profile medium, score narrow)
    # Bottom row: full-width kill-chain detail
    gs = gridspec.GridSpec(2, 3, figure=fig, height_ratios=[0.9, 1.3],
                           width_ratios=[1.1, 1.0, 0.6],
                           hspace=0.30, wspace=0.30,
                           left=0.05, right=0.97, top=0.91, bottom=0.04)

    current = records[up_to]
    score = current["score"]
    phase = current["phase"]
    iteration = current["iteration"]
    attacks = current.get("attacks", [])
    detections = current.get("detections", [])

    score_color = C_GREEN if score == 0 and up_to > 0 else C_YELLOW if score <= 2 else C_RED
    result_text = "PERFECT" if score == 0 and up_to > 0 else f"score={score}"
    fig.suptitle(f"{title}  |  iter {iteration}: {phase}  |  {result_text}",
                 fontsize=13, fontweight="bold", color=score_color, y=0.96,
                 fontfamily="monospace")

    # ══════════════════════════════════════════════════════════════════════
    # TOP-LEFT: Radar Chart (MITRE 12-spoke)
    # ══════════════════════════════════════════════════════════════════════
    ax_radar = fig.add_subplot(gs[0, 0], polar=True)
    ax_radar.set_facecolor(C_PANEL)

    n_phases = len(MITRE_PHASES)
    angles = np.linspace(0, 2 * np.pi, n_phases, endpoint=False).tolist()
    angles += angles[:1]

    if attacks:
        det_by_attack, phase_attacks = build_attack_analysis(attacks, detections)

        total_per_phase = []
        detected_per_phase = []
        for p in MITRE_PHASES:
            pa = phase_attacks[p]
            total_per_phase.append(len(pa))
            detected_per_phase.append(sum(1 for a in pa if a["all_found"]))

        max_radar = max(max(total_per_phase), 1)
        total_vals = total_per_phase + total_per_phase[:1]
        det_vals = detected_per_phase + detected_per_phase[:1]

        ax_radar.fill(angles, total_vals, alpha=0.08, color=C_DIM)
        ax_radar.plot(angles, total_vals, "o-", color=C_DIM, linewidth=1, markersize=3, label="Total")
        ax_radar.fill(angles, det_vals, alpha=0.35, color=C_GREEN)
        ax_radar.plot(angles, det_vals, "o-", color=C_GREEN, linewidth=2, markersize=4, label="Detected")
        ax_radar.legend(fontsize=6, loc="lower center", bbox_to_anchor=(0.5, -0.18),
                        facecolor=C_PANEL, edgecolor=C_BORDER, labelcolor=C_TEXT, ncol=2)
        ax_radar.set_ylim(0, max_radar + 1)
        ax_radar.set_rgrids([max_radar // 2 or 1, max_radar], labels=[], color=C_BORDER, alpha=0.3)
    else:
        det_by_attack, phase_attacks = {}, {p: [] for p in MITRE_PHASES}
        ax_radar.text(0, 0, "(not tested)", fontsize=10, color=C_DIM, ha="center",
                      fontfamily="monospace")
        ax_radar.set_ylim(0, 5)
        ax_radar.set_rgrids([2, 4], labels=[], color=C_BORDER, alpha=0.3)

    ax_radar.set_thetagrids(np.degrees(angles[:-1]), MITRE_PHASES, fontsize=5.5, color=C_TEXT)
    ax_radar.spines["polar"].set_color(C_BORDER)
    ax_radar.tick_params(colors=C_DIM, pad=8)
    ax_radar.set_title("Kill-Chain Coverage", fontsize=9, color=C_TEXT,
                        fontfamily="monospace", pad=15)

    # ══════════════════════════════════════════════════════════════════════
    # TOP-CENTER: Profile Shrinkage (horizontal bars, fixed x-axis)
    # ══════════════════════════════════════════════════════════════════════
    ax_prof = fig.add_subplot(gs[0, 1])
    ax_prof.set_facecolor(C_PANEL)

    categories = ["Opens", "Execs", "Syscalls", "Endpoints", "Rules"]
    keys = ["opens", "execs", "syscalls", "endpoints", "policy_rules"]
    colors = [C_BLUE, C_CYAN, C_DIM, C_GREEN, C_YELLOW]
    vals = [current[k] for k in keys]

    if up_to > 0:
        base = [records[0][k] for k in keys]
        ax_prof.barh(categories, base, color=[C_GREY] * 5, height=0.55, alpha=0.25)
    bars = ax_prof.barh(categories, vals, color=colors, height=0.55)

    for i, (bar, val) in enumerate(zip(bars, vals)):
        lbl = str(val)
        if up_to > 0:
            d = val - records[0][keys[i]]
            if d < 0:
                lbl += f" ({d})"
            elif d > 0:
                lbl += f" (+{d})"
        ax_prof.text(bar.get_width() + 1, bar.get_y() + bar.get_height() / 2,
                     lbl, va="center", fontsize=7, color=C_TEXT, fontfamily="monospace")

    ax_prof.set_xlim(0, limits["max_entries"])
    ax_prof.set_title("Profile Entries", fontsize=9, color=C_TEXT, fontfamily="monospace")
    ax_prof.tick_params(colors=C_DIM, labelsize=7)
    for spine in ax_prof.spines.values():
        spine.set_color(C_BORDER)

    # ══════════════════════════════════════════════════════════════════════
    # TOP-RIGHT: Score + Sparkline + Stats
    # ══════════════════════════════════════════════════════════════════════
    ax_score = fig.add_subplot(gs[0, 2])
    ax_score.set_facecolor(C_PANEL)
    ax_score.axis("off")

    ax_score.text(0.5, 0.72, str(score), fontsize=48, fontweight="bold", color=score_color,
                  ha="center", va="center", fontfamily="monospace", transform=ax_score.transAxes)

    # Sparkline
    if up_to > 0:
        scores_hist = [r["score"] for r in records[:up_to + 1]]
        spark_x = np.linspace(0.15, 0.85, len(scores_hist))
        spark_y_base = 0.42
        spark_height = 0.08
        max_s = max(max(scores_hist), 1)
        for j in range(len(scores_hist)):
            sy = spark_y_base + (scores_hist[j] / max_s) * spark_height
            sx = spark_x[j]
            c = C_GREEN if scores_hist[j] == 0 else C_YELLOW if scores_hist[j] <= 2 else C_RED
            ax_score.plot(sx, sy, "o", color=c, markersize=5, transform=ax_score.transAxes)
            if j > 0:
                sy_prev = spark_y_base + (scores_hist[j - 1] / max_s) * spark_height
                ax_score.plot([spark_x[j - 1], sx], [sy_prev, sy], "-", color=C_BORDER,
                              linewidth=1, transform=ax_score.transAxes)

    ax_score.text(0.5, 0.28, f"missed {current['missed_detections']}  |  FP {current['false_positives']}",
                  fontsize=8, color=C_DIM, ha="center", fontfamily="monospace",
                  transform=ax_score.transAxes)
    n_atk = len(attacks)
    n_det = len([d for d in detections if d.get("found")])
    n_exp = len([d for d in detections if d.get("rule_id")])
    ax_score.text(0.5, 0.16, f"detected {n_det}/{n_exp}", fontsize=8, color=C_TEXT,
                  ha="center", fontfamily="monospace", transform=ax_score.transAxes)
    ax_score.text(0.5, 0.06, f"entries {current['total_entries']}", fontsize=7, color=C_DIM,
                  ha="center", fontfamily="monospace", transform=ax_score.transAxes)
    ax_score.set_title("Score", fontsize=9, color=C_TEXT, fontfamily="monospace")

    # ══════════════════════════════════════════════════════════════════════
    # BOTTOM: Kill-Chain Detail Heatmap (full width)
    # ══════════════════════════════════════════════════════════════════════
    ax_kc = fig.add_subplot(gs[1, :])
    ax_kc.set_facecolor(C_PANEL)

    if not attacks:
        ax_kc.text(0.5, 0.5, "MITRE ATT&CK Kill-Chain\n\n(attacks not yet executed)",
                   fontsize=12, color=C_DIM, ha="center", va="center",
                   fontfamily="monospace", transform=ax_kc.transAxes)
        ax_kc.set_title("Kill-Chain: Attack & Detection Detail", fontsize=10,
                         color=C_TEXT, fontfamily="monospace")
        ax_kc.axis("off")
    else:
        active_phases = [(i, p) for i, p in enumerate(MITRE_PHASES) if phase_attacks[p]]
        n_active = len(active_phases)
        max_in_phase = max((len(phase_attacks[p]) for _, p in active_phases), default=1)

        # Cell dimensions
        cell_w = 0.8
        cell_h = 0.7
        x_pad = 0.3   # left margin for labels
        y_pad = 0.15   # bottom margin

        # Compute total grid width needed
        total_w = x_pad + max_in_phase * (cell_w + 0.15) + 3.0  # extra for right annotations

        ax_kc.set_xlim(-0.2, total_w)
        ax_kc.set_ylim(-0.5, n_active * (cell_h + 0.25) + 0.3)

        for row_idx, (phase_global_idx, pname) in enumerate(reversed(active_phases)):
            pa = phase_attacks[pname]
            y_base = row_idx * (cell_h + 0.25) + y_pad

            # Phase label on left
            ax_kc.text(x_pad - 0.15, y_base + cell_h / 2, pname,
                       fontsize=7.5, fontweight="bold", color=C_TEXT,
                       ha="right", va="center", fontfamily="monospace")

            # Gather unique rules for this phase
            phase_rules_found = set()
            phase_rules_missed = set()

            for j, a in enumerate(pa):
                x = x_pad + j * (cell_w + 0.15)

                # Cell color
                if a["all_found"]:
                    fc = C_GREEN
                    alpha = 0.7
                elif a["any_missed"]:
                    fc = C_RED
                    alpha = 0.7
                elif not a["has_expectations"]:
                    fc = C_BLUE
                    alpha = 0.35
                else:
                    fc = C_YELLOW
                    alpha = 0.6

                rect = plt.Rectangle((x, y_base), cell_w, cell_h,
                                     facecolor=fc, edgecolor=C_BORDER,
                                     linewidth=0.5, alpha=alpha)
                ax_kc.add_patch(rect)

                # Attack short name inside cell
                label = a["short"]
                if len(label) > 10:
                    label = label[:9] + "\u2026"
                text_color = "#000000" if fc in (C_GREEN, C_YELLOW) else C_TEXT
                ax_kc.text(x + cell_w / 2, y_base + cell_h * 0.6, label,
                           fontsize=5.5, color=text_color,
                           ha="center", va="center", fontfamily="monospace",
                           fontweight="bold")

                # Rule IDs below the name (tiny)
                rules_text_parts = []
                for rid in a["rules_found"]:
                    rules_text_parts.append(rid)
                    phase_rules_found.add(rid)
                for rid in a["rules_missed"]:
                    phase_rules_found.discard(rid)  # keep missed separate
                    phase_rules_missed.add(rid)
                    rules_text_parts.append(f"!{rid}")

                if rules_text_parts:
                    rtxt = " ".join(rules_text_parts[:2])
                    if len(rules_text_parts) > 2:
                        rtxt += f"+{len(rules_text_parts) - 2}"
                    rule_text_color = "#000000" if fc in (C_GREEN, C_YELLOW) else C_DIM
                    ax_kc.text(x + cell_w / 2, y_base + cell_h * 0.2, rtxt,
                               fontsize=4, color=rule_text_color,
                               ha="center", va="center", fontfamily="monospace")

                # Collect rules for phase summary
                for rid in a["rules_found"]:
                    phase_rules_found.add(rid)
                for rid in a["rules_missed"]:
                    phase_rules_missed.add(rid)

            # Phase detection rate on the right
            detected_count = sum(1 for a in pa if a["all_found"])
            expected_count = sum(1 for a in pa if a["has_expectations"])
            rate_x = x_pad + len(pa) * (cell_w + 0.15) + 0.2

            if expected_count > 0:
                rate_color = C_GREEN if detected_count == expected_count else C_RED
                ax_kc.text(rate_x, y_base + cell_h * 0.65,
                           f"{detected_count}/{expected_count}",
                           fontsize=8, fontweight="bold", color=rate_color,
                           va="center", fontfamily="monospace")

            # Rules summary next to rate
            all_rules = sorted(phase_rules_found | phase_rules_missed)
            if all_rules:
                rules_summary = ", ".join(all_rules[:4])
                if len(all_rules) > 4:
                    rules_summary += f" +{len(all_rules) - 4}"
                ax_kc.text(rate_x, y_base + cell_h * 0.25,
                           rules_summary, fontsize=4.5, color=C_DIM,
                           va="center", fontfamily="monospace")

        ax_kc.set_title("Kill-Chain: Attack & Detection Detail", fontsize=10,
                         color=C_TEXT, fontfamily="monospace")
        ax_kc.axis("off")

        # Legend at bottom-right
        legend_elements = [
            Patch(facecolor=C_GREEN, edgecolor=C_BORDER, alpha=0.7, label="All detected"),
            Patch(facecolor=C_RED, edgecolor=C_BORDER, alpha=0.7, label="Detection missed"),
            Patch(facecolor=C_BLUE, edgecolor=C_BORDER, alpha=0.35, label="No expected detection"),
        ]
        ax_kc.legend(handles=legend_elements, fontsize=6, loc="lower right",
                      facecolor=C_PANEL, edgecolor=C_BORDER, labelcolor=C_TEXT,
                      bbox_to_anchor=(1.0, -0.02))

    buf = BytesIO()
    fig.savefig(buf, format="png", facecolor=fig.get_facecolor(), bbox_inches="tight", pad_inches=0.15)
    plt.close(fig)
    buf.seek(0)
    return Image.open(buf).convert("RGBA")


def main():
    parser = argparse.ArgumentParser(description="Design 5: Hybrid Radar + Kill-Chain Detail")
    parser.add_argument("metrics_json")
    parser.add_argument("output_gif")
    parser.add_argument("--title", default="bobctl tune")
    parser.add_argument("--duration", type=int, default=2000)
    parser.add_argument("--last-duration", type=int, default=4000)
    args = parser.parse_args()

    with open(args.metrics_json) as f:
        records = json.load(f)
    if not records:
        print("No iterations", file=sys.stderr)
        sys.exit(1)

    limits = compute_global_limits(records)
    print(f"Rendering {len(records)} frames (Design 5: Hybrid)...", file=sys.stderr)

    frames = []
    for i in range(len(records)):
        frame = draw_frame(records, i, args.title, limits)
        frames.append(frame.convert("RGB").quantize(colors=128, method=Image.Quantize.MEDIANCUT))

    durations = [args.duration] * len(frames)
    durations[-1] = args.last_duration

    frames[0].save(args.output_gif, save_all=True, append_images=frames[1:],
                   duration=durations, loop=0)
    size_kb = Path(args.output_gif).stat().st_size / 1024
    print(f"Wrote {args.output_gif} ({len(frames)} frames, {size_kb:.0f} KB)", file=sys.stderr)


if __name__ == "__main__":
    main()
