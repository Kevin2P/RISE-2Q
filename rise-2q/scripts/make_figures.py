#!/usr/bin/env python3
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib import rcParams
import os

OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'figures')

rcParams['font.family'] = 'serif'
rcParams['font.serif'] = [
    'Times New Roman',
    'TeX Gyre Termes',
    'Nimbus Roman',
    'Liberation Serif',
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


def plot_a():
    x = [0.1, 0.2, 0.3, 0.4, 0.6, 0.8]
    q1 = [0.006, 0.200, 0.237, 0.237, 0.237, 0.237]
    y = [0.100, 0.200, 0.300, 0.400, 0.442, 0.442]
    q3 = [0.100, 0.200, 0.300, 0.400, 0.452, 0.452]
    err_lo = [m - a for m, a in zip(y, q1)]
    err_hi = [b - m for m, b in zip(y, q3)]

    fig, ax = plt.subplots(figsize=FIGSIZE)
    ax.axhline(0.44, **REF, zorder=1, label='Ceiling')
    ax.plot([0, 0.56], [0, 0.56], **IDEAL, zorder=2, label='Ideal')
    ax.errorbar(x, y, yerr=[err_lo, err_hi],
                ecolor=PURPLE, elinewidth=1.0, capsize=3, capthick=1.0,
                zorder=3, label='Measured', **LINE)
    ax.text(0.86, 0.465, 'Ceiling $\\approx$ 0.44 Mbps', fontsize=7.5, ha='right', **TXT)
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
    print('(a) fig_threshold.pdf generated')


def plot_b():
    x = [1.05, 5, 10]
    q1 = [45.5, 61.9, 84.1]
    y = [50.5, 69.4, 90.7]
    q3 = [53.6, 79.0, 112.2]
    err = [[m - a for m, a in zip(y, q1)], [b - m for m, b in zip(y, q3)]]

    fig, ax = plt.subplots(figsize=FIGSIZE)
    ax.axhline(269.6, **REF, zorder=1, label='No quarantine')
    ax.axhline(41.7, **IDEAL, zorder=2, label='Ideal')
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
    print('(b) fig_delay.pdf generated')


def plot_c():
    mcs = [4, 6, 8, 9, 12]
    atk = [0.03, 2.29, 5.50, 6.67, 10.62]
    mcs_23dbm = [4, 9]
    atk_23dbm = [0.03, 8.52]

    fig, ax = plt.subplots(figsize=FIGSIZE)
    ax.plot(mcs, atk, zorder=3, label='Measured (2 dBm)', clip_on=False, **LINE)
    ax.plot([mcs_23dbm[1]], [atk_23dbm[1]], zorder=4, label='Measured (23 dBm)', linestyle='none', marker='D', clip_on=False,
            markersize=5, markerfacecolor='none', markeredgecolor=PINK, markeredgewidth=1.5)
    ax.plot([mcs_23dbm[0]], [atk_23dbm[0]], zorder=4, linestyle='none', marker='D', clip_on=False,
            markersize=5, markerfacecolor='none', markeredgecolor=PINK, markeredgewidth=1.5)
    ax.axvline(9, **REF, zorder=1, label='Operating point')
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
    print('(c) fig_mcs_tradeoff.pdf generated')


if __name__ == '__main__':
    existed = os.path.isdir(OUT_DIR)
    os.makedirs(OUT_DIR, exist_ok=True)
    print(f'Output folder: {OUT_DIR} ({"already existed, reused" if existed else "created"}); '
          'the three PDFs in it are replaced')
    from matplotlib import font_manager
    used = font_manager.findfont(font_manager.FontProperties(family='serif'))
    print(f'Serif font in use: {used.split("/")[-1]}')
    print()

    plot_a()
    plot_b()
    plot_c()
