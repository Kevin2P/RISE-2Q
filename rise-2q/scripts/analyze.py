#!/usr/bin/env python3
USAGE = """Usage: python3 scripts/analyze.py [command]
Without a command, prints everything, in the order of the paper.
Commands: tables, figures, robustness, 23dbm, derived, final, port5000, fpcs,
throughput, quartiles, switch, mcs, ue23dbm, ue23dbm-mcs4, percell, help"""
import glob
import math
import os
import re
import statistics
import sys

TXT = "txt-v2"
N = 20
SEEDS = range(1, 32)
IPS = {"7.0.0.2": "Healthcare", "7.0.0.3": "Factory", "7.0.0.4": "Process"}
TOPOLOGIES = [("dmgnbat", "DMgNBAT"), ("pcgnbatc2", "PCgNBAT"), ("csgnbat", "CSgNBAT")]
CTRL = "udp-n{n}-{t}-qsliced-qf20-qmcs9-rlc100KB-run{s}"
QUAR = "udp-n{n}-{t}-qstatic-qf20-qmcs9-fp3-rlc100KB-run{s}"
ATTACK_S = 50.0


def read_report(f):
    try:
        return open(f, encoding="utf-8", errors="ignore").read()
    except OSError:
        return None


def flow_blocks(t):
    return re.split(r"Flow \d+ \(", t)[1:]


def attack_mb(t):
    rx = 0
    for b in flow_blocks(t):
        if re.search(r"label=(attack|quarantined)", b):
            m = re.search(r"Rx Bytes:\s+(\d+)", b)
            if m:
                rx += int(m.group(1))
    return rx / 1e6


def p95(xs):
    if not xs:
        return 0
    s = sorted(xs)
    return s[int(0.95 * (len(s) - 1))]


def quartiles(xs):
    if len(xs) < 4:
        return (min(xs) if xs else 0, statistics.median(xs) if xs else 0, max(xs) if xs else 0)
    q = statistics.quantiles(xs, n=4)
    return (q[0], statistics.median(xs), q[2])


def cmd_final():
    print("=== FALSE POSITIVE (DM static) - median + p95 (31 seeds) ===")
    for ip, name in IPS.items():
        dv = []
        dl = []
        for s in SEEDS:
            txt = read_report(f"{TXT}/udp-n{N}-dmgnbat-qstatic-qf20-qmcs9-fp3-rlc100KB-run{s}")
            if not txt:
                continue
            for b in flow_blocks(txt):
                if f"{ip}:" in b and 'falsepositive' in b:
                    mt = re.search(r'Tx Packets:\s+(\d+)', b)
                    mr = re.search(r'Rx Packets:\s+(\d+)', b)
                    md = re.search(r'Mean delay:\s+([\d.]+)', b)
                    if mt and int(mt.group(1)) > 0:
                        dv.append(100 * int(mr.group(1)) / int(mt.group(1)))
                        if int(mr.group(1)) > 0 and md:
                            dl.append(float(md.group(1)))
        if dv:
            print(f"  {name}: delivery med={statistics.median(dv):.1f}% (p95={p95(dv):.1f}%) | "
                  f"delay med={statistics.median(dl):.1f}ms mean={statistics.mean(dl):.1f}ms p95={p95(dl):.1f}ms")

    print("\n=== MITIGATION (median, 31 seeds) ===")
    for topology in ["dmgnbat", "pcgnbatc2", "csgnbat"]:
        nq = []
        q = []
        for s in SEEDS:
            tc = read_report(f"{TXT}/udp-n{N}-{topology}-qsliced-qf20-qmcs9-rlc100KB-run{s}")
            tq = read_report(f"{TXT}/udp-n{N}-{topology}-qstatic-qf20-qmcs9-fp3-rlc100KB-run{s}")
            for t, lst in [(tc, nq), (tq, q)]:
                if t:
                    lst.append(attack_mb(t))
        if nq and q:
            mnq = statistics.median(nq)
            mq = statistics.median(q)
            red = 100 * (mnq - mq) / mnq if mnq > 0.1 else 0
            print(f"  {topology}: noquar med={mnq:.1f}MB | quar med={mq:.2f}MB | reduction={red:.1f}%")

    print("\n=== AGGREGATE C_Q (attack in the DM static quarantine) ===")
    agg = []
    for s in SEEDS:
        tq = read_report(f"{TXT}/udp-n{N}-dmgnbat-qstatic-qf20-qmcs9-fp3-rlc100KB-run{s}")
        if tq:
            agg.append(attack_mb(tq))
    if agg:
        med = statistics.median(agg)
        print(f"  attack quar median={med:.1f}MB in 50s = {med * 8 / 50:.2f} Mbps (actual aggregate C_Q)")


def _normal_stats(txt):
    if not txt:
        return None, None
    tx_tot = rx_tot = 0
    delays = []
    for b in flow_blocks(txt):
        if 'label=normal' in b:
            mtx = re.search(r'Tx Bytes:\s+(\d+)', b)
            mrx = re.search(r'Rx Bytes:\s+(\d+)', b)
            md = re.search(r'Mean delay:\s+([\d.]+)', b)
            if mtx and mrx:
                tx_tot += int(mtx.group(1))
                rx_tot += int(mrx.group(1))
            if md:
                delays.append(float(md.group(1)))
    deliv = 100 * rx_tot / tx_tot if tx_tot > 0 else None
    delay = statistics.mean(delays) if delays else None
    return deliv, delay


def cmd_port5000():
    print("=== PORT 5000 (label=normal): CORRECTLY classified legitimate devices, with and without quarantine ===\n")
    print("Question: does the quarantine give resources back to the correctly classified legitimate devices of the attacked cell?\n")
    topologies = [('dmgnbat', 'DM (distributed)'), ('pcgnbatc2', 'PC (partial)'), ('csgnbat', 'CS (concentrated)')]
    for topology, tlbl in topologies:
        print(f"--- {tlbl} ---")
        for mode, lbl in [('qsliced', 'WITHOUT quar (control)'), ('qstatic', 'WITH quar (ideal)   ')]:
            delivs = []
            delays = []
            for s in SEEDS:
                txt = read_report(f"{TXT}/udp-n{N}-{topology}-{mode}-qf20-qmcs9-rlc100KB-run{s}")
                if not txt:
                    txt = read_report(f"{TXT}/udp-n{N}-{topology}-{mode}-qf20-qmcs9-fp3-rlc100KB-run{s}")
                if txt:
                    d, dl = _normal_stats(txt)
                    if d is not None:
                        delivs.append(d)
                    if dl is not None:
                        delays.append(dl)
            if delivs:
                print(f"  {lbl}: delivery med={statistics.median(delivs):5.1f}% | "
                      f"delay med={statistics.median(delays):6.1f}ms (n={len(delivs)})")
            else:
                print(f"  {lbl}: NO DATA")
        print()

    print("=== INTERPRETATION ===")
    print("If in CS the delivery WITHOUT quar is low and WITH quar is high,")
    print("  -> the quarantine GIVES BACK resources to the correctly classified legitimate devices (the best outcome!)")
    print("If it is the same (already 100% in both), round-robin already protected them (less impactful).")


def cmd_fpcs(folder=None):
    txt_dir = folder if folder else TXT

    def med(xs):
        return statistics.median(xs) if xs else None

    def f(x, fmt):
        return "n/a" if x is None else fmt.format(x)

    print("=== 1. ATTACK VOLUME DELIVERED (MB, 4 decimals), median of 31 seeds ===")
    for t, name in TOPOLOGIES:
        for pattern, label in [(CTRL, "control    "), (QUAR, "quarantine ")]:
            v = []
            for s in SEEDS:
                txt = read_report(f"{txt_dir}/" + pattern.format(n=N, t=t, s=s))
                if txt:
                    v.append(attack_mb(txt))
            if v:
                print(f"  {name:8s} {label}: n={len(v):2d} median={statistics.median(v):.4f} mean={statistics.mean(v):.4f} "
                      f"min={min(v):.4f} max={max(v):.4f} seeds_with_zero={sum(1 for x in v if x == 0)}")
            else:
                print(f"  {name:8s} {label}: no data")

    def qos(pattern, t, ip, mark):
        deliv, delay = [], []
        for s in SEEDS:
            txt = read_report(f"{txt_dir}/" + pattern.format(n=N, t=t, s=s))
            if not txt:
                continue
            for b in flow_blocks(txt):
                if f"{ip}:" in b and mark in b:
                    mt = re.search(r"Tx Packets:\s+(\d+)", b)
                    mr = re.search(r"Rx Packets:\s+(\d+)", b)
                    md = re.search(r"Mean delay:\s+([\d.]+)", b)
                    if mt and mr and int(mt.group(1)) > 0:
                        deliv.append(100 * int(mr.group(1)) / int(mt.group(1)))
                        if int(mr.group(1)) > 0 and md:
                            delay.append(float(md.group(1)))
        return deliv, delay

    print("\n=== 2. QoS OF THE 3 FALSE-POSITIVE DEVICES (median of 31 seeds) ===")
    print("    delivery (%) and delay (ms, median and p95); 'low' = seeds with delivery < 50%")
    for t, name in TOPOLOGIES:
        print(f"\n  {name}")
        for ip, profile in IPS.items():
            line = f"    {profile:11s}"
            for pattern, mark, mode_name in [(QUAR, "falsepositive", "WITH quarantine"), (CTRL, "label=normal", "WITHOUT quarantine")]:
                deliv, delay = qos(pattern, t, ip, mark)
                if not deliv:
                    line += f" | {mode_name}: no data"
                    continue
                line += (f" | {mode_name}: delivery med={f(med(deliv), '{:.1f}')}% (low in {sum(1 for x in deliv if x < 50)} of {len(deliv)})"
                          f", delay med={f(med(delay), '{:.1f}')} p95={f(p95(delay) if delay else None, '{:.1f}')} ms")
            print(line)


def cmd_throughput():
    print("=== CURVE (a): FP THROUGHPUT per device (median + IQR) ===")
    print(f"{'rate(Mbps)':>10} | {'Q1':>7} | {'median':>7} | {'Q3':>7}")
    for kbps in [100, 200, 300, 400, 600, 800]:
        tputs = []
        for s in SEEDS:
            txt = read_report(f"{TXT}/udp-n{N}-dmgnbat-qstatic-qf20-qmcs9-fp3-rlc100KB-fpprobe{kbps}kbps-run{s}")
            if not txt:
                continue
            for b in flow_blocks(txt):
                if 'falsepositive' in b:
                    mr = re.search(r'Rx Bytes:\s+(\d+)', b)
                    if mr:
                        tputs.append(int(mr.group(1)) * 8 / 50 / 1e6)
        if tputs:
            q1, med, q3 = quartiles(tputs)
            print(f"{kbps / 1000:>10.1f} | {q1:>7.3f} | {med:>7.3f} | {q3:>7.3f}")
    print()
    print("-> the median throughput must SATURATE near 0.44 (the ceiling)")
    print("-> where the curve stops rising = the per-device ceiling")


def cmd_quartiles():
    print("=== PANEL (a): threshold curve - median + Q1/Q3 (IQR) ===")
    print(f"{'rate':>6} | {'Q1':>6} | {'median':>7} | {'Q3':>6}")
    for kbps in [100, 200, 300, 400, 600, 800]:
        delivs = []
        for s in SEEDS:
            txt = read_report(f"{TXT}/udp-n{N}-dmgnbat-qstatic-qf20-qmcs9-fp3-rlc100KB-fpprobe{kbps}kbps-run{s}")
            if not txt:
                continue
            for b in flow_blocks(txt):
                if 'falsepositive' in b:
                    mt = re.search(r'Tx Packets:\s+(\d+)', b)
                    mr = re.search(r'Rx Packets:\s+(\d+)', b)
                    if mt and int(mt.group(1)) > 0:
                        delivs.append(100 * int(mr.group(1)) / int(mt.group(1)))
        if delivs:
            q1, med, q3 = quartiles(delivs)
            print(f"{kbps / 1000:>6.1f} | {q1:>6.1f} | {med:>7.1f} | {q3:>6.1f}")

    print("\n=== PANEL (b): degradation by delay - median + Q1/Q3 (IQR) ===")
    print(f"{'delay':>6} | {'Q1':>6} | {'median':>7} | {'Q3':>6}")
    for dtag, lbl in [("101050ms", "1.05"), ("105000ms", "5"), ("110000ms", "10")]:
        vals = []
        for s in SEEDS:
            txt = read_report(f"{TXT}/udp-n{N}-dmgnbat-qswitch-qf20-t{dtag}-qmcs9-fp3-rlc100KB-run{s}")
            if not txt:
                continue
            vals.append(attack_mb(txt))
        if vals:
            q1, med, q3 = quartiles(vals)
            print(f"{lbl:>6} | {q1:>6.1f} | {med:>7.1f} | {q3:>6.1f}")


def cmd_switch():
    dets = [("101050ms", "1.05"), ("105000ms", "5"), ("110000ms", "10")]

    print("=== PANEL (b): DEGRADATION BY DELAY (31 seeds, median) ===\n")
    print(f"{'delay(s)':>8} | {'attack median(MB)':>18} | {'mean(MB)':>10} | {'p95(MB)':>10} | {'n seeds':>7}")
    for dtag, lbl in dets:
        vals = []
        for s in SEEDS:
            for pat in [f"udp-n{N}-dmgnbat-qswitch-qf20-t{dtag}-qmcs9-fp3-rlc100KB-run{s}",
                        f"udp-n{N}-dmgnbat-qswitch-qf20-t{dtag}-qmcs9-rlc100KB-run{s}"]:
                txt = read_report(f"{TXT}/{pat}")
                if txt:
                    vals.append(attack_mb(txt))
                    break
        if vals:
            p = sorted(vals)[int(0.95 * (len(vals) - 1))]
            print(f"{lbl:>8} | {statistics.median(vals):>18.1f} | {statistics.mean(vals):>10.1f} | {p:>10.1f} | {len(vals):>7}")
        else:
            print(f"{lbl:>8} | (no file found - check the name)")

    print("\n=== REFERENCES (control and ideal, 31 seeds median) ===")
    for mode, lbl in [("qsliced", "control (no quar)"), ("qstatic", "static (ideal)")]:
        vals = []
        for s in SEEDS:
            for pat in [f"udp-n{N}-dmgnbat-{mode}-qf20-qmcs9-fp3-rlc100KB-run{s}",
                        f"udp-n{N}-dmgnbat-{mode}-qf20-qmcs9-rlc100KB-run{s}"]:
                txt = read_report(f"{TXT}/{pat}")
                if txt:
                    vals.append(attack_mb(txt))
                    break
        if vals:
            print(f"  {lbl}: median={statistics.median(vals):.1f} MB (n={len(vals)})")

    print("\n=== If 'no file', list the switch names to see the pattern: ===")
    print("    ls txt-v2 | grep qswitch | head")


def cmd_mcs(folder=None):
    txt_dir = folder if folder else TXT
    for mcs in [4, 6, 8, 9, 12]:
        vals = [attack_mb(read_report(f) or "") for f in glob.glob(f"{txt_dir}/udp-n20-dmgnbat-qstatic-qf20-qmcs{mcs}-fp3-rlc100KB-run*")
                if "fpprobe" not in f]
        if not vals:
            print(f"MCS {mcs}: NO DATA")
            continue
        sd = statistics.stdev(vals) if len(vals) > 1 else 0.0
        med = statistics.median(vals)
        print(f"MCS {mcs}: med={med:.1f} min={min(vals):.1f} max={max(vals):.1f} std={sd:.1f}"
              f"  | {med * 8 / 50:.2f} Mbps | n={len(vals)}")


def cmd_ue23dbm(base=None, new=None):
    BASE = base if base else "txt-v2"
    NEW = new if new else "run-ue23/txt-v2"
    PAPER_CONTROL_MB, PAPER_QUAR_MB = 269.6, 41.7
    NAME_CONTROL = "udp-n{n}-dmgnbat-qsliced-qf20-qmcs9-rlc100KB-run{s}"
    NAME_QUAR = "udp-n{n}-dmgnbat-qstatic-qf20-qmcs9-fp3-rlc100KB-run{s}"

    def analyze(folder):
        r = {"nq": [], "q": [], "fp": {}}
        for s in SEEDS:
            tc = read_report(f"{folder}/" + NAME_CONTROL.format(n=N, s=s))
            tq = read_report(f"{folder}/" + NAME_QUAR.format(n=N, s=s))
            if tc:
                r["nq"].append(attack_mb(tc))
            if tq:
                r["q"].append(attack_mb(tq))
        for ip, name in IPS.items():
            dv, dl = [], []
            for s in SEEDS:
                txt = read_report(f"{folder}/" + NAME_QUAR.format(n=N, s=s))
                if not txt:
                    continue
                for b in flow_blocks(txt):
                    if f"{ip}:" in b and "falsepositive" in b:
                        mt = re.search(r"Tx Packets:\s+(\d+)", b)
                        mr = re.search(r"Rx Packets:\s+(\d+)", b)
                        md = re.search(r"Mean delay:\s+([\d.]+)", b)
                        if mt and mr and int(mt.group(1)) > 0:
                            dv.append(100 * int(mr.group(1)) / int(mt.group(1)))
                            if int(mr.group(1)) > 0 and md:
                                dl.append(float(md.group(1)))
            r["fp"][name] = (dv, dl)
        return r

    def med(xs):
        return statistics.median(xs) if xs else None

    def f(x, fmt="{:.1f}"):
        return "n/a" if x is None else fmt.format(x)

    for d in (BASE, NEW):
        if not os.path.isdir(d):
            sys.exit(f"ERROR: the folder {d} does not exist. Run from ns-3-dev.")

    a, b = analyze(BASE), analyze(NEW)
    if not b["nq"] and not b["q"]:
        sys.exit(f"ERROR: no result in {NEW}. Has the 23 dBm batch finished?")

    def summary(r):
        mnq, mq = med(r["nq"]), med(r["q"])
        red = 100 * (mnq - mq) / mnq if (mnq is not None and mq is not None and mnq > 0.1) else None
        cq = mq * 8 / 50 if mq is not None else None
        return mnq, mq, red, cq

    A, B = summary(a), summary(b)
    print(f"{'':34s}{'2 dBm (base)':>16s}{'23 dBm':>14s}")
    print(f"{'seeds (control / quarantine)':34s}{str(len(a['nq'])) + ' / ' + str(len(a['q'])):>16s}{str(len(b['nq'])) + ' / ' + str(len(b['q'])):>14s}")
    print(f"{'Attack without quarantine (MB)':34s}{f(A[0]):>16s}{f(B[0]):>14s}")
    print(f"{'Attack with quarantine (MB)':34s}{f(A[1], '{:.2f}'):>16s}{f(B[1], '{:.2f}'):>14s}")
    print(f"{'Reduction (%)':34s}{f(A[2]):>16s}{f(B[2]):>14s}")
    print(f"{'Aggregate C_Q (Mbps)':34s}{f(A[3], '{:.2f}'):>16s}{f(B[3], '{:.2f}'):>14s}")
    print()
    print("Confined false positive (median):  delivery (%)  |  delay (ms)")
    for name in IPS.values():
        dva, dla = a["fp"][name]
        dvb, dlb = b["fp"][name]
        print(f"  {name:11s} 2 dBm: {f(med(dva)):>6s} | {f(med(dla)):>6s}      23 dBm: {f(med(dvb)):>6s} | {f(med(dlb)):>6s}")

    print()
    ok_base = (A[0] is not None and A[1] is not None
               and abs(A[0] - PAPER_CONTROL_MB) < 0.05 and abs(A[1] - PAPER_QUAR_MB) < 0.05)
    if ok_base:
        print(f"SELF-TEST OK: the base reproduces the paper ({PAPER_CONTROL_MB} and {PAPER_QUAR_MB} MB).")
    else:
        print(f"SELF-TEST FAILED: the base does not reproduce the paper ({PAPER_CONTROL_MB} and {PAPER_QUAR_MB} MB). "
              "The analysis or the base data changed. Do NOT use this comparison until it is resolved.")
    complete = len(b["nq"]) == len(SEEDS) and len(b["q"]) == len(SEEDS)
    if complete:
        print("23 dBm COMPLETE: 31 seeds in each case.")
    else:
        print(f"23 dBm PARTIAL: {len(b['nq'])}/31 control and {len(b['q'])}/31 quarantine. "
              "Wait for it to finish before using the numbers.")


def cmd_ue23dbm_mcs4(base=None, new=None):
    BASE = base if base else "txt-v2"
    NEW = new if new else "run-ue23-mcs4/txt-v2"
    MCS = 4
    NAME = "udp-n{n}-dmgnbat-qstatic-qf20-qmcs{m}-fp3-rlc100KB-run{s}"

    def analyze(folder):
        r = {"mb": {}, "fp": {name: ([], []) for name in IPS.values()}}
        for s in SEEDS:
            txt = read_report(f"{folder}/" + NAME.format(n=N, m=MCS, s=s))
            if not txt:
                continue
            r["mb"][s] = attack_mb(txt)
            for ip, name in IPS.items():
                for b in flow_blocks(txt):
                    if f"{ip}:" in b and "falsepositive" in b:
                        mt = re.search(r"Tx Packets:\s+(\d+)", b)
                        mr = re.search(r"Rx Packets:\s+(\d+)", b)
                        md = re.search(r"Mean delay:\s+([\d.]+)", b)
                        if mt and mr and int(mt.group(1)) > 0:
                            r["fp"][name][0].append(100 * int(mr.group(1)) / int(mt.group(1)))
                            if int(mr.group(1)) > 0 and md:
                                r["fp"][name][1].append(float(md.group(1)))
        return r

    def med(xs):
        return statistics.median(xs) if xs else None

    def quartiles_incl(xs):
        if len(xs) < 2:
            return None, None
        q = statistics.quantiles(xs, n=4, method="inclusive")
        return q[0], q[2]

    def f(x, fmt="{:.2f}"):
        return "n/a" if x is None else fmt.format(x)

    for d in (BASE, NEW):
        if not os.path.isdir(d):
            sys.exit(f"ERROR: the folder {d} does not exist. Run from ns-3-dev.")
    a, b = analyze(BASE), analyze(NEW)
    if not b["mb"]:
        sys.exit(f"ERROR: no MCS {MCS} result in {NEW}. Has the batch finished?")

    va, vb = list(a["mb"].values()), list(b["mb"].values())
    ma, mb_ = med(va), med(vb)
    print(f"MCS {MCS} fixed in the quarantine (static, 3 false positives, DMgNBAT, N={N})")
    print(f"{'':44s}{'2 dBm (base)':>14s}{'23 dBm':>12s}")
    print(f"{'seeds':44s}{len(va):>14d}{len(vb):>12d}")
    print(f"{'Attack admitted, median (MB)':44s}{f(ma):>14s}{f(mb_):>12s}")
    print(f"{'Attack admitted, median (Mbps)':44s}{f(ma * 8 / ATTACK_S if ma is not None else None):>14s}{f(mb_ * 8 / ATTACK_S if mb_ is not None else None):>12s}")
    qa, qb = quartiles_incl(va), quartiles_incl(vb)
    print(f"{'  Q1 | Q3 (MB)':44s}{(f(qa[0]) + ' | ' + f(qa[1])):>14s}{(f(qb[0]) + ' | ' + f(qb[1])):>12s}")
    print(f"{'  minimum | maximum (MB)':44s}{(f(min(va)) + ' | ' + f(max(va))):>14s}{(f(min(vb)) + ' | ' + f(max(vb))):>12s}")
    common = sorted(set(a["mb"]) & set(b["mb"]))
    more = sum(1 for s in common if b["mb"][s] > a["mb"][s])
    print(f"{'Seeds where 23 dBm admits more (paired)':44s}{'':>14s}{(str(more) + ' of ' + str(len(common))):>12s}")
    if ma and mb_ is not None and ma > 0:
        print(f"{'Ratio of the medians, 23 dBm / 2 dBm':44s}{'':>14s}{'x' + f(mb_ / ma, '{:.1f}'):>12s}")
    print()
    print("Confined false positive at this MCS (median):  delivery (%)  |  delay (ms)   [informative]")
    for name in IPS.values():
        dva, dla = a["fp"][name]
        dvb, dlb = b["fp"][name]
        print(f"  {name:11s} 2 dBm: {f(med(dva), '{:.1f}'):>6s} | {f(med(dla), '{:.1f}'):>6s}      23 dBm: {f(med(dvb), '{:.1f}'):>6s} | {f(med(dlb), '{:.1f}'):>6s}")
    print()
    ok_base = ma is not None and round(ma, 1) == 0.2 and round(ma * 8 / ATTACK_S, 2) == 0.03
    if ok_base:
        print("SELF-TEST OK: the MCS 4 base reproduces the paper (0.2 MB, 0.03 Mbps).")
    else:
        print(f"SELF-TEST FAILED: the MCS 4 base gave {f(ma)} MB ({f(ma * 8 / ATTACK_S if ma is not None else None)} Mbps), the paper cites 0.2 MB (0.03 Mbps). "
              "The analysis or the base data changed. Do NOT use this comparison until it is resolved.")
    if len(vb) == len(SEEDS):
        print("23 dBm COMPLETE: 31 seeds.")
    else:
        print(f"23 dBm PARTIAL: {len(vb)}/31 seeds. Wait for it to finish before using the numbers.")


DIR = 'txt-v2'
DIR23 = 'run-ue23/txt-v2'
N_ATK, K_FP = 20, 3
HDR = 28
SURVIVES = 90.0
MCS_LIST = [4, 6, 8, 9, 12]
PROFILES = [('7.0.0.2', 'Healthcare', 512, 0.033), ('7.0.0.3', 'Factory', 20, 0.002), ('7.0.0.4', 'Process', 256, 0.2)]


def _flow_blocks_of(path):
    t = read_report(path)
    return None if t is None else flow_blocks(t)


def _attack_of(path):
    bl = _flow_blocks_of(path)
    if bl is None:
        return None
    return sum(int(m.group(1)) for b in bl if re.search(r'label=(attack|quarantined)', b)
               for m in [re.search(r'Rx Bytes:\s+(\d+)', b)] if m) / 1e6


def _delivery_of(path, ip, mark):
    bl = _flow_blocks_of(path)
    if bl is None:
        return None
    for b in bl:
        if f'{ip}:' in b and mark in b:
            tx = int(re.search(r'Tx Packets:\s+(\d+)', b).group(1))
            rx = int(re.search(r'Rx Packets:\s+(\d+)', b).group(1))
            return 100 * rx / tx
    return None


def _report_name(topology, mode, mcs=9):
    if mode == 'control':
        return f'udp-n20-{topology}-qsliced-qf20-qmcs{mcs}-rlc100KB-run{{}}'
    return f'udp-n20-{topology}-qstatic-qf20-qmcs{mcs}-fp3-rlc100KB-run{{}}'


def _robustness_1():
    print('1) Attack reduction seed by seed, control versus static quarantine (section IV-A)')
    for topology in ['dmgnbat', 'pcgnbatc2']:
        red, low_seeds = [], []
        for s in SEEDS:
            c = _attack_of(f'{DIR}/' + _report_name(topology, 'control').format(s))
            q = _attack_of(f'{DIR}/' + _report_name(topology, 'quarantine').format(s))
            if c and q is not None and c > 0:
                r = 100 * (1 - q / c)
                red.append(r)
                if r < 50:
                    low_seeds.append((s, c, q, r))
        if not red:
            print(f'{topology}: no data')
            continue
        red.sort()
        qs = statistics.quantiles(red, n=4) if len(red) >= 4 else [red[0], statistics.median(red), red[-1]]
        print(f'{topology}: seeds={len(red)} | reduction per seed (%): min={red[0]:.1f} Q1={qs[0]:.1f} median={qs[1]:.1f} '
              f'Q3={qs[2]:.1f} max={red[-1]:.1f} | seeds with reduction >= 50%: {sum(1 for x in red if x >= 50)}, '
              f'>= 70%: {sum(1 for x in red if x >= 70)}, >= 80%: {sum(1 for x in red if x >= 80)}')
        for s, c, q, r in low_seeds:
            print(f'   seed {s:2d} with reduction < 50%: control {c:7.2f} MB | quarantine {q:6.2f} MB | reduction {r:6.1f}%')
    print()


def _robustness_2():
    print('2) Tail of the misclassified devices, DMgNBAT with quarantine at MCS 9 (section IV-C)')
    Q, C = _report_name('dmgnbat', 'quarantine'), _report_name('dmgnbat', 'control')
    has23 = os.path.isdir(DIR23)
    folders = [(DIR, ' 2 dBm')] + ([(DIR23, '23 dBm')] if has23 else [])
    for folder, label in folders:
        for ip, profile, _, _ in PROFILES:
            v = [_delivery_of(f'{folder}/' + Q.format(s), ip, 'falsepositive') for s in SEEDS]
            v = [x for x in v if x is not None]
            if v:
                print(f'  {label} {profile:10s}: {sum(1 for x in v if x < 50):2d} of {len(v)} seeds below 50% | '
                      f'minimum delivery {min(v):5.1f}%')
    if not has23:
        print(f'  (no {DIR23}: the 23 dBm part was skipped)')
    print('   seeds where the device fails at 2 dBm: the same device in the control (adaptive MCS) and at 23 dBm')
    print('   seed | profile    | quarantine 2 dBm | control 2 dBm  | quarantine 23 dBm')
    f = lambda x: '   n/a' if x is None else f'{x:6.1f}'
    for s in SEEDS:
        for ip, profile, _, _ in PROFILES:
            q2 = _delivery_of(f'{DIR}/' + Q.format(s), ip, 'falsepositive')
            if q2 is not None and q2 < 50:
                c2 = _delivery_of(f'{DIR}/' + C.format(s), ip, 'label=normal')
                q23 = _delivery_of(f'{DIR23}/' + Q.format(s), ip, 'falsepositive') if has23 else None
                print(f'   {s:4d} | {profile:10s} | {f(q2)}           | {f(c2)}         | {f(q23)}')
    print()


def _robustness_3():
    print('3) Preservation along the quarantine MCS and the sizing condition (section IV-E)')
    print('MCS | profile    | seeds | median delivery (%) | seeds below 50%')
    rows, cq = [], {}
    for m in MCS_LIST:
        paths = [f'{DIR}/' + _report_name('dmgnbat', 'quarantine', m).format(s) for s in SEEDS]
        volumes = [x for x in (_attack_of(a) for a in paths) if x is not None]
        if volumes:
            cq[m] = statistics.median(volumes) * 8 / ATTACK_S
        for ip, profile, _, _ in PROFILES:
            deliv = [x for x in (_delivery_of(a, ip, 'falsepositive') for a in paths) if x is not None]
            if deliv:
                print(f'{m:3d} | {profile:10s} | {len(deliv):5d} | {statistics.median(deliv):19.1f} | '
                      f'{sum(1 for x in deliv if x < 50):2d}')
                rows.append((m, profile, statistics.median(deliv)))
    print()
    print(f'Sizing condition: nominal share = C_Q(m) / (N_atk + K) = C_Q(m) / {N_ATK + K_FP}, '
          f'with C_Q(m) = median admitted attack x 8 / {ATTACK_S:.0f} s.')
    print(f'A profile counts as preserved if its median delivery is >= {SURVIVES:.0f}%.')
    print('MCS | C_Q (Mbps) | share (Mbps)   | profile    | offered (Mbps)   | predicted   | observed (median %)   | matches')
    ok = tot = 0
    for m, profile, med in rows:
        if m not in cq:
            continue
        share = cq[m] / (N_ATK + K_FP)
        offered = [8 * (b + HDR) / p / 1e6 for ip, n, b, p in PROFILES if n == profile][0]
        prev, obs = offered <= share, med >= SURVIVES
        ok += prev == obs
        tot += 1
        print(f'{m:3d} | {cq[m]:10.3f} | {share:14.4f} | {profile:10s} | {offered:16.4f} | '
              f'{"preserved" if prev else "cut off":11s} | {med:21.1f} | {"yes" if prev == obs else "NO"}')
    print(f'\nThe condition agrees with the observation in {ok} of {tot} pairs (MCS index, profile).')


def cmd_robustness():
    if not os.path.isdir(DIR):
        raise SystemExit(f'ERROR: could not find {DIR}/. Run from ns-3-dev.')
    _robustness_1()
    _robustness_2()
    _robustness_3()


UDP_IP_HEADER_B = 28
SIM = {
    "totalAttackRatePps": 101010.0,
    "packetSizeAttack": 1400,
    "numLegit": 10,
    "numGnb": 5,
    "numerologyBwp1": 1,
    "bandwidthBand1": 20e6,
    "quarantineFraction": 0.2,
    "legitProfilePacketSize": (512.0, 20.0, 256.0),
    "legitProfileIntervalMs": (33.032, 2.0, 200.0),
    "attackStartTime": 100.0,
    "simTime": 150.0,
}
K_MISCLASSIFIED = 3
SIM_SOURCES = ["scratch/rise-2q.cc"]
SIM_PATTERNS = {
    "totalAttackRatePps": r"double\s+totalAttackRatePps\s*=\s*([0-9.eE+]+)",
    "packetSizeAttack": r"uint32_t\s+packetSizeAttack\s*=\s*(\d+)",
    "numLegit": r"uint16_t\s+numLegit\s*=\s*(\d+)",
    "numGnb": r"const\s+uint16_t\s+numGnb\s*=\s*(\d+)",
    "numerologyBwp1": r"uint16_t\s+numerologyBwp1\s*=\s*(\d+)",
    "bandwidthBand1": r"double\s+bandwidthBand1\s*=\s*([0-9.eE+]+)",
    "quarantineFraction": r"double\s+quarantineFraction\s*=\s*([0-9.]+)",
    "legitProfilePacketSize": r"legitProfilePacketSize\[3\]\s*=\s*\{([^}]*)\}",
    "legitProfileIntervalMs": r"legitProfileIntervalMs\[3\]\s*=\s*\{([^}]*)\}",
    "attackStartTime": r"Time\s+attackStartTime\s*=\s*Seconds\(([0-9.]+)\)",
    "simTime": r"Time\s+simTime\s*=\s*Seconds\(([0-9.]+)\)",
}


def _check_constants():
    src = next((p for p in SIM_SOURCES if os.path.isfile(p)), None)
    if src is None:
        return [f"(simulator source not found as {' or '.join(SIM_SOURCES)}; constants not checked)"]
    code = open(src, encoding="utf-8", errors="ignore").read()
    bad = []
    for key, pat in SIM_PATTERNS.items():
        m = re.search(pat, code)
        if not m:
            bad.append(f"{key}: not found in the source")
            continue
        want = SIM[key] if isinstance(SIM[key], tuple) else (float(SIM[key]),)
        got = tuple(float(x) for x in m.group(1).split(","))
        if len(got) != len(want) or any(abs(a - b) > 1e-9 for a, b in zip(got, want)):
            bad.append(f"{key}: the source has {m.group(1).strip()}, expected {SIM[key]}")
    checked = src
    sh = "scripts/simulate.sh"
    if os.path.isfile(sh):
        checked += " and " + sh
        m = re.search(r"^N=(\d+)", open(sh, encoding="utf-8", errors="ignore").read(), re.M)
        if not m or int(m.group(1)) != N:
            bad.append(f"N in {sh}: {m.group(1) if m else 'not found'}, expected {N}")
    return [f"constants checked against {checked}: " + ("all match" if not bad else "MISMATCH")] + [f"  {b}" for b in bad]


def _median_attack(names):
    vals = []
    for s in SEEDS:
        for name in names:
            txt = read_report(f"{TXT}/{name(s)}")
            if txt:
                vals.append(attack_mb(txt))
                break
    return (statistics.median(vals), len(vals)) if vals else (None, 0)


def cmd_derived():
    for line in _check_constants():
        print(line)
    pps, L, H = SIM["totalAttackRatePps"], SIM["packetSizeAttack"], UDP_IP_HEADER_B
    print("\n=== From the constants (Section III, Tables II and III, Fig. 1) ===")
    print(f"aggregate attack rate R_tot = {pps:.0f} pps x {L} B x 8 = {pps * L * 8 / 1e9:.3f} Gbps  (paper: 1.131 Gbps)")
    lam = pps / N
    print(f"per attacker, N = {N}: {lam:.1f} pps, r_atk = 8 x {lam:.1f} x ({L} + {H}) B = "
          f"{8 * lam * (L + H) / 1e6:.1f} Mbps  (paper: 57.7 Mbps)")
    names = ("Healthcare", "Factory", "Process")
    eff_ms = [math.floor(x) for x in SIM["legitProfileIntervalMs"]]
    rates = [8 * (Lj + H) / (tj / 1e3) / 1e6 for Lj, tj in zip(SIM["legitProfilePacketSize"], eff_ms)]
    for nm, Lj, tj, r in zip(names, SIM["legitProfilePacketSize"], eff_ms, rates):
        print(f"profile {nm:10s}: 8 x ({Lj:.0f} + {H}) B / {tj} ms = {r:.4f} Mbps")
    print("  (Table III: 0.131, 0.192 and 0.011 Mbps; the Healthcare period is written 33.032 ms and runs as 33 ms)")
    r_l = sum(rates[i % 3] for i in range(SIM["numLegit"]))
    print(f"legitimate load R_L, {SIM['numLegit']} devices, profile i mod 3 = {r_l:.3f} Mbps  (paper: 1.134 Mbps)")
    w, B = 12 * 15e3 * 2 ** SIM["numerologyBwp1"], SIM["bandwidthBand1"]
    n_q = math.floor(SIM["quarantineFraction"] * B / w)
    n_n = math.floor((B - n_q * w) / w)
    print(f"RB width w = 12 x 15 kHz x 2^{SIM['numerologyBwp1']} = {w / 1e3:.0f} kHz; "
          f"n_Q = floor(phi B / w) = {n_q}, n_N = floor((B - n_Q w) / w) = {n_n}, {n_q + n_n} in total")
    print(f"  quarantine BWP {n_q * w / 1e6:.2f} MHz, normal BWP {n_n * w / 1e6:.2f} MHz, together "
          f"{(n_q + n_n) * w / 1e6:.2f} MHz  (paper: 3.96, 15.84 and 19.8 MHz)")

    print(f"\n=== From the medians of the reports (DMgNBAT, {TXT}/) ===")
    d_c, n_c = _median_attack([lambda s: CTRL.format(n=N, t="dmgnbat", s=s)])
    d_q, n_qr = _median_attack([lambda s: QUAR.format(n=N, t="dmgnbat", s=s)])
    if d_c is None or d_q is None:
        print(f"(reports of the distributed control or quarantine not found in {TXT}/; run from the folder that has {TXT}/)")
        return
    print(f"delivered attack, median: control {d_c:.1f} MB ({n_c} seeds), quarantine {d_q:.1f} MB ({n_qr} seeds)  (Table IV)")
    c_n, r_off = d_c * 8 / ATTACK_S, pps * L * 8 / 1e6
    print(f"without quarantine {c_n:.1f} Mbps of attack reach the victim (C_N = {d_c:.1f} MB x 8 / {ATTACK_S:.0f} s); the offered "
          f"{r_off:.1f} Mbps is {r_off / c_n:.1f} times C_N  (paper: 26 times the 43.1 Mbps, Section III-E)")
    print(f"removed by the quarantine itself: {d_c:.1f} - {d_q:.1f} = {d_c - d_q:.0f} MB  (Section IV-A: about 228 MB)")
    c_q = d_q * 8 / ATTACK_S
    print(f"C_Q = {d_q:.1f} MB x 8 / {ATTACK_S:.0f} s = {c_q:.2f} Mbps, {c_q / SIM['numGnb']:.2f} Mbps per cell  "
          f"(paper: 6.7 Mbps, about 1.33 Mbps per cell)")
    slope = (d_c - d_q) / ATTACK_S
    print(f"model slope (8) = ({d_c:.1f} - {d_q:.1f}) / {ATTACK_S:.0f} s = {slope:.2f} MB/s  (paper: about 4.6 MB/s)")
    sw = {}
    for dtag in ("101050ms", "110000ms"):
        sw[dtag] = _median_attack([
            lambda s, d=dtag: f"udp-n{N}-dmgnbat-qswitch-qf20-t{d}-qmcs9-fp3-rlc100KB-run{s}",
            lambda s, d=dtag: f"udp-n{N}-dmgnbat-qswitch-qf20-t{d}-qmcs9-rlc100KB-run{s}"])[0]
    if sw["101050ms"] is not None and sw["110000ms"] is not None:
        meas = sw["110000ms"] - sw["101050ms"]
        pred = slope * (10.0 - 1.05)
        print(f"realistic mode, median: {sw['101050ms']:.1f} MB at 1.05 s and {sw['110000ms']:.1f} MB at 10 s, "
              f"measured growth {meas:+.1f} MB")
        print(f"  model: {slope:.2f} MB/s x (10 - 1.05) s = {pred:+.1f} MB, {abs(pred - meas) / meas * 100:.1f}% from the "
              f"measured growth  (paper: +41 against +40.1 MB, a 2% agreement)")
        rem10 = (d_c - sw["110000ms"]) / d_c * 100
        print(f"  at 10 s the quarantine still removes ({d_c:.1f} - {sw['110000ms']:.1f}) / {d_c:.1f} = {rem10:.1f}% of the "
              f"unmitigated attack  (paper: 66%, Section IV-B and Conclusion)")
    else:
        print("(reports of the realistic mode at 1.05 s and 10 s not found; growth with the delay not computed)")
    share = c_q / (N + K_MISCLASSIFIED)
    print(f"nominal share at N_atk = {N}, K = {K_MISCLASSIFIED}: {c_q:.2f} / {N + K_MISCLASSIFIED} = {share:.2f} Mbps  "
          f"(paper: about 0.29 Mbps)")
    top = max(rates)
    print(f"the most demanding profile ({top:.3f} Mbps) fits the share up to N_atk = floor({c_q:.2f} / {top:.3f} - "
          f"{K_MISCLASSIFIED}) = {math.floor(c_q / top - K_MISCLASSIFIED)} evenly spread attackers")
    per_cell = c_q / SIM["numGnb"]
    print(f"CSgNBAT, equal split of one cell: {per_cell:.2f} / ({N} + 2) = {per_cell / (N + 2):.2f} Mbps per device  "
          f"(paper: about 0.06 Mbps)")


def _mwu_p(x, y):
    v = list(x) + list(y)
    n1, n2 = len(x), len(y)
    n = n1 + n2
    order = sorted(range(n), key=lambda i: v[i])
    ranks = [0.0] * n
    ties = 0
    i = 0
    while i < n:
        j = i
        while j + 1 < n and v[order[j + 1]] == v[order[i]]:
            j += 1
        for k in range(i, j + 1):
            ranks[order[k]] = (i + j) / 2 + 1
        ties += (j - i + 1) ** 3 - (j - i + 1)
        i = j + 1
    u1 = sum(ranks[:n1]) - n1 * (n1 + 1) / 2
    u = max(u1, n1 * n2 - u1)
    sigma = math.sqrt(n1 * n2 / 12 * ((n + 1) - ties / (n * (n - 1))))
    return min(1.0, math.erfc((u - n1 * n2 / 2 - 0.5) / sigma / math.sqrt(2)))


def cmd_percell():
    print("=== TABLE VII: per-cell attack goodput and flow variability (DMgNBAT, static quarantine, MCS 9) ===")
    print("attacker 7.0.0.(12+k) is in gNB k // 4; the Healthcare and Factory false positives (7.0.0.2, 7.0.0.3) are in gNB 0")
    seeds = []
    for s in SEEDS:
        t = read_report(f"{TXT}/" + QUAR.format(n=N, t="dmgnbat", s=s))
        if not t:
            continue
        cells = {c: [] for c in range(5)}
        fp = {}
        for b in flow_blocks(t):
            m = re.match(r"([\d.]+):\d+ ->", b)
            rx = re.search(r"Rx Bytes:\s+(\d+)", b)
            if not (m and rx):
                continue
            ip = m.group(1)
            mbps = int(rx.group(1)) * 8 / ATTACK_S / 1e6
            if "label=quarantined" in b:
                cells[(int(ip.split(".")[-1]) - 12) // 4].append(mbps)
            elif "label=falsepositive" in b:
                tx = re.search(r"Tx Packets:\s+(\d+)", b)
                rp = re.search(r"Rx Packets:\s+(\d+)", b)
                fp[ip] = (mbps, 100 * int(rp.group(1)) / int(tx.group(1)) if int(tx.group(1)) else 0.0)
        seeds.append((cells, fp))
    if not seeds:
        print("  no reports found")
        return
    ns = len(seeds)

    def cv(v):
        return statistics.pstdev(v) / statistics.mean(v) if v and statistics.mean(v) > 0 else float("nan")

    print(f"{'cell':>6} | {'median':>7} | {'Q1':>6} - {'Q3':<6} | {'med CV':>6} | zero-flow seeds")
    for c in range(5):
        tot = [sum(x[0][c]) for x in seeds]
        q1, med, q3 = quartiles(tot)
        cvs = [v for v in (cv(x[0][c]) for x in seeds) if v == v]
        zero = sum(1 for x in seeds if any(g == 0 for g in x[0][c]))
        print(f"gNB {c} | {med:7.3f} | {q1:6.3f} - {q3:<6.3f} | {statistics.median(cvs):6.3f} | {zero}/{ns}")
    prob = [x[1].get("7.0.0.2", (0, 0))[1] < 50 or x[1].get("7.0.0.3", (0, 0))[1] < 50 for x in seeds]
    print(f"\nproblematic seeds (Healthcare or Factory below 50% delivery): {sum(prob)}/{ns}")
    series = [("gNB 0 attack goodput (Mbps)", [sum(x[0][0]) for x in seeds]),
              ("gNB 0 total, with the two false positives (Mbps)",
               [sum(x[0][0]) + x[1].get("7.0.0.2", (0, 0))[0] + x[1].get("7.0.0.3", (0, 0))[0] for x in seeds]),
              ("gNB 0 CV of the four attack flows", [cv(x[0][0]) for x in seeds])]
    for name, v in series:
        a = [vv for vv, p in zip(v, prob) if p]
        b = [vv for vv, p in zip(v, prob) if not p]
        print(f"  {name}: problematic {statistics.median(a):.3f} | others {statistics.median(b):.3f}"
              f" | Mann-Whitney U, two-sided p = {_mwu_p(a, b):.3f}")


COMMANDS = {
    "final":        (cmd_final,        0, "Tables IV and V (DMgNBAT quarantine) and aggregate C_Q"),
    "port5000":     (cmd_port5000,     0, "Table IV, delay columns (correctly classified devices, with and without quarantine)"),
    "fpcs":         (cmd_fpcs,         1, "CSgNBAT, Control column of Table V, Table VI and section IV-C"),
    "throughput":   (cmd_throughput,   0, "Fig. 2(a): throughput of the false positives"),
    "quartiles":    (cmd_quartiles,    0, "Figs. 2(a) and 2(b): medians and quartiles"),
    "switch":       (cmd_switch,       0, "Fig. 2(b): attack delivered by detection delay"),
    "mcs":          (cmd_mcs,          1, "Fig. 2(c): attack admitted by MCS"),
    "ue23dbm":      (cmd_ue23dbm,      2, "23 dBm batch against the 2 dBm base"),
    "ue23dbm-mcs4": (cmd_ue23dbm_mcs4, 2, "MCS 4 at 23 dBm against the 2 dBm base (optional)"),
    "robustness":   (cmd_robustness,   0, "reduction seed by seed, tail and preservation by MCS"),
    "derived":      (cmd_derived,      0, "Section III equations, Section IV-B model and sizing values"),
    "percell":      (cmd_percell,      0, "Table VII and Section IV-D: per-cell goodput, flow CV and problematic seeds"),
}
GROUPS = {
    "tables":     ["final", "port5000", "fpcs", "percell"],
    "figures":    ["throughput", "quartiles", "switch", "mcs"],
    "robustness": ["robustness"],
    "23dbm":      ["ue23dbm", "ue23dbm-mcs4"],
    "derived":    ["derived"],
}
ALL_ORDER = ["tables", "figures", "robustness", "23dbm", "derived"]


def _help():
    print(USAGE)


def _run_group(names):
    for name in names:
        func, _, descr = COMMANDS[name]
        if name == "ue23dbm" and not os.path.isdir("run-ue23/txt-v2"):
            print(f"\n######## {name}: {descr} ########\n(skipped: the folder run-ue23/txt-v2 does not exist)")
            continue
        if name == "ue23dbm-mcs4" and not os.path.isdir("run-ue23-mcs4/txt-v2"):
            print(f"\n######## {name}: {descr} ########\n(skipped: the folder run-ue23-mcs4/txt-v2 does not exist; it is an optional batch)")
            continue
        print(f"\n######## {name}: {descr} ########\n")
        try:
            func()
        except SystemExit as e:
            print(f"ERROR in {name}: {e.code}")
        except Exception as e:
            print(f"ERROR in {name}: {type(e).__name__}: {e}")


def main(argv):
    if not argv or argv[0] == "all":
        names = [n for g in ALL_ORDER for n in GROUPS[g]]
        return _run_group(names)
    cmd, args = argv[0], argv[1:]
    if cmd in ("help", "-h", "--help"):
        return _help()
    if cmd in GROUPS and cmd not in COMMANDS:
        return _run_group(GROUPS[cmd])
    if cmd in COMMANDS:
        func, nargs, _ = COMMANDS[cmd]
        if len(args) > nargs:
            sys.exit(f"ERROR: '{cmd}' accepts at most {nargs} argument(s) (folders). See: python3 scripts/analyze.py help")
        return func(*args)
    sys.exit(f"ERROR: unknown command: {cmd}\nSee: python3 scripts/analyze.py help")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
        sys.stdout.flush()
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
