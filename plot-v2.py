#!/usr/bin/env python3
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib import rcParams
import glob
import os
import re
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analyze as A


OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'img-v2')

rcParams['font.family'] = 'serif'
rcParams['font.serif'] = [
    'Times New Roman',
    'Liberation Serif',
    'TeX Gyre Termes',
    'Nimbus Roman',
    'Times',
]
rcParams['mathtext.fontset'] = 'stix'
rcParams['pdf.fonttype'] = 42
rcParams['savefig.dpi'] = 600

PURPLE = '#6f4e8f'
PURPLE_EDGE = '#503668'
PINK = '#ff7a8a'

LINE = dict(
    color=PURPLE, linewidth=1.5,
    marker='o', markersize=5,
    markerfacecolor=PURPLE, markeredgecolor=PURPLE_EDGE, markeredgewidth=0.6,
)
REF = dict(color='#00a878', linewidth=1.0, linestyle=(0, (1, 2)))
IDEAL = dict(color='#8da9c4', linewidth=1.2, linestyle='--')
TXT = dict(color='black')

FIGSIZE = (3.4, 2.4)


def style_axes(ax):
    ax.tick_params(axis='both', labelcolor='black', labelsize=8.5)
    ax.grid(True, alpha=0.3, linewidth=0.5, color='#b0b0b0')
    ax.set_axisbelow(True)
    for sp in ax.spines.values():
        sp.set_edgecolor('black')
        sp.set_linewidth(0.5)


def fail(msg):
    sys.exit(f"error: {msg} Unpack the reports first (see the README).")


def numbers_in_names(pattern, regex):
    found = sorted({int(m.group(1)) for f in glob.glob(pattern) if (m := re.search(regex, os.path.basename(f)))})
    return found, len(glob.glob(pattern))


def attack_values(names):
    return [A.attack_mb(t) for t in (A.read_report(n) for n in names) if t]


def data_a():
    pattern = f"{A.TXT}/udp-n{A.N}-dmgnbat-qstatic-qf20-qmcs9-fp3-rlc100KB-fpprobe*kbps-run*"
    rates, n_reports = numbers_in_names(pattern, r"fpprobe(\d+)kbps")
    x, q1, y, q3 = [], [], [], []
    for kbps in rates:
        tputs = []
        for s in A.SEEDS:
            txt = A.read_report(f"{A.TXT}/udp-n{A.N}-dmgnbat-qstatic-qf20-qmcs9-fp3-rlc100KB-fpprobe{kbps}kbps-run{s}")
            if not txt:
                continue
            for b in A.flow_blocks(txt):
                if 'falsepositive' in b:
                    mr = re.search(r'Rx Bytes:\s+(\d+)', b)
                    if mr:
                        tputs.append(int(mr.group(1)) * 8 / A.ATTACK_S / 1e6)
        if tputs:
            a, m, b_ = A.quartiles(tputs)
            x.append(kbps / 1000); q1.append(a); y.append(m); q3.append(b_)
    if not x:
        fail(f"no offered-rate reports (fpprobe) in {A.TXT}/.")
    return x, q1, y, q3, y[-1], n_reports


def data_b():
    start_ms = round(A.SIM['attackStartTime'] * 1000)
    pattern = f"{A.TXT}/udp-n{A.N}-dmgnbat-qswitch-qf20-t*ms-qmcs9-fp3-rlc100KB-run*"
    tags, n_reports = numbers_in_names(pattern, r"-t(\d+)ms-")
    x, q1, y, q3 = [], [], [], []
    for ms in tags:
        vals = attack_values(f"{A.TXT}/udp-n{A.N}-dmgnbat-qswitch-qf20-t{ms}ms-qmcs9-fp3-rlc100KB-run{s}" for s in A.SEEDS)
        if vals:
            a, m, b_ = A.quartiles(vals)
            x.append((ms - start_ms) / 1000); q1.append(a); y.append(m); q3.append(b_)
    control = attack_values(f"{A.TXT}/" + A.CTRL.format(n=A.N, t='dmgnbat', s=s) for s in A.SEEDS)
    ideal = attack_values(f"{A.TXT}/" + A.QUAR.format(n=A.N, t='dmgnbat', s=s) for s in A.SEEDS)
    if not x or not control or not ideal:
        fail(f"no detection-delay, control or ideal reports in {A.TXT}/.")
    return x, q1, y, q3, statistics.median(control), statistics.median(ideal), n_reports + len(control) + len(ideal)


def admitted_mbps(folder):
    pattern = f"{folder}/udp-n{A.N}-dmgnbat-qstatic-qf20-qmcs*-fp3-rlc100KB-run*"
    mcs_list, _ = numbers_in_names(pattern, r"-qmcs(\d+)-fp3-rlc100KB-run")
    points, n_reports = [], 0
    for m in mcs_list:
        names = [f for f in glob.glob(f"{folder}/udp-n{A.N}-dmgnbat-qstatic-qf20-qmcs{m}-fp3-rlc100KB-run*") if 'fpprobe' not in f]
        vals = attack_values(names)
        if vals:
            points.append((m, statistics.median(vals) * 8 / A.ATTACK_S)); n_reports += len(vals)
    return points, n_reports


def data_c():
    base, n_base = admitted_mbps(A.TXT)
    high = []
    n_high = 0
    for folder in ('run-ue23/txt-v2', 'run-ue23-mcs4/txt-v2'):
        pts, n = admitted_mbps(folder)
        high += pts; n_high += n
    operating = int(re.search(r"qmcs(\d+)", A.QUAR).group(1))
    if not base or not high:
        fail(f"no MCS-sweep reports in {A.TXT}/ or no 23 dBm reports in run-ue23*/txt-v2/.")
    return base, sorted(high), operating, n_base + n_high


def plot_a(data):
    x, q1, y, q3, ceiling, n_reports = data
    err_lo = [m - a for m, a in zip(y, q1)]
    err_hi = [b - m for m, b in zip(y, q3)]

    fig, ax = plt.subplots(figsize=FIGSIZE)
    ax.axhline(ceiling, **REF, zorder=1, label='Ceiling')
    ax.plot([0, 0.56], [0, 0.56], **IDEAL, zorder=2, label='Ideal')
    ax.errorbar(x, y, yerr=[err_lo, err_hi],
                ecolor=PURPLE, elinewidth=1.0, capsize=3, capthick=1.0,
                zorder=3, label='Measured', **LINE)
    ax.text(0.86, ceiling + 0.025, f'Ceiling $\\approx$ {ceiling:.2f} Mbps', fontsize=7.5, ha='right', **TXT)
    ax.set_xlabel('False-positive offered rate (Mbps)', fontsize=9.5, color='black')
    ax.set_ylabel('Delivered throughput (Mbps)', fontsize=9.5, color='black')
    ax.set_xlim(-0.02, 0.88)
    ax.set_ylim(-0.02, 0.56)
    style_axes(ax)
    leg = ax.legend(loc='upper left', fontsize=7, frameon=True, fancybox=False, edgecolor='black', framealpha=1)
    leg.get_frame().set_linewidth(0.8)
    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, 'fig_threshold.pdf'), bbox_inches='tight')
    plt.close()
    print(f'(a) fig_threshold.pdf generated from {n_reports} reports')


def plot_b(data):
    x, q1, y, q3, control, ideal, n_reports = data
    err = [[m - a for m, a in zip(y, q1)], [b - m for m, b in zip(y, q3)]]

    fig, ax = plt.subplots(figsize=FIGSIZE)
    ax.axhline(control, **REF, zorder=1, label='No quarantine')
    ax.axhline(ideal, **IDEAL, zorder=2, label='Ideal')
    ax.errorbar(x, y, yerr=err,
                ecolor=PURPLE, elinewidth=1.0, capsize=3, capthick=1.0,
                zorder=3, label='Measured', **LINE)
    ax.set_xlabel('Detection delay (s)', fontsize=9.5, color='black')
    ax.set_ylabel('Attack delivered (MB)', fontsize=9.5, color='black')
    ax.set_xlim(-0.3, 11)
    ax.set_ylim(0, 300)
    style_axes(ax)
    leg = ax.legend(loc='upper left', fontsize=7, frameon=True, fancybox=False, edgecolor='black', framealpha=1)
    leg.get_frame().set_linewidth(0.8)
    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, 'fig_delay.pdf'), bbox_inches='tight')
    plt.close()
    print(f'(b) fig_delay.pdf generated from {n_reports} reports')


def plot_c(data):
    base, high, operating, n_reports = data
    mcs, atk = [m for m, _ in base], [v for _, v in base]
    mcs_23dbm, atk_23dbm = [m for m, _ in high], [v for _, v in high]

    fig, ax = plt.subplots(figsize=FIGSIZE)
    ax.plot(mcs, atk, zorder=3, label='Measured (2 dBm)', clip_on=False, **LINE)
    ax.plot(mcs_23dbm, atk_23dbm, zorder=4, label='Measured (23 dBm)', linestyle='none', marker='D', clip_on=False,
            markersize=5, markerfacecolor='none', markeredgecolor=PINK, markeredgewidth=1.5)
    ax.axvline(operating, **REF, zorder=1, label='Operating point')
    ax.set_xlabel('Quarantine MCS index', fontsize=9.5, color='black')
    ax.set_ylabel('Attack admitted (Mbps)', fontsize=9.5, color='black')
    ax.set_ylim(-0.6, 11.5)
    style_axes(ax)
    handles, labels = ax.get_legend_handles_labels()
    idx = [labels.index(lab) for lab in ('Operating point', 'Measured (23 dBm)', 'Measured (2 dBm)')]
    leg = ax.legend([handles[i] for i in idx], [labels[i] for i in idx],
                    loc='upper left', fontsize=7, frameon=True, fancybox=False, edgecolor='black', framealpha=1)
    leg.get_frame().set_linewidth(0.8)
    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, 'fig_mcs_tradeoff.pdf'), bbox_inches='tight')
    plt.close()
    print(f'(c) fig_mcs_tradeoff.pdf generated from {n_reports} reports')


if __name__ == '__main__':
    data = (data_a(), data_b(), data_c())
    existed = os.path.isdir(OUT_DIR)
    os.makedirs(OUT_DIR, exist_ok=True)
    print(f'Output folder: {OUT_DIR} ({"already existed, reused" if existed else "created"}); '
          'the three PDFs in it are replaced')
    from matplotlib import font_manager
    used = font_manager.findfont(font_manager.FontProperties(family='serif'))
    print(f'Serif font in use: {used.split("/")[-1]}')
    print()

    plot_a(data[0])
    plot_b(data[1])
    plot_c(data[2])
