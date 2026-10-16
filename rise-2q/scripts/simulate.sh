#!/usr/bin/env bash
set -u
PROG=${SIMULATOR:-rise-2q}
N=20
SEEDS=${SEEDS:-31}
JOBS=${JOBS:-8}
POLL=${POLL:-5}
ROOT=$PWD

die() { echo "ERROR: $*"; exit 1; }

list_base() {
    local PCC=2 PROBES="0.1 0.2 0.3 0.4 0.6 0.8" seed t ms mbps kbps D P C
    local TAIL="--attackers=$N --quarantineFraction=0.2 --quarantineMcs=9 --rlcBufferKB=100"
    for seed in $(seq 1 $SEEDS); do
        D="--dmgnbat $TAIL --RngRun=$seed"
        echo "udp-n$N-dmgnbat-qsliced-qf20-qmcs9-rlc100KB-run$seed|$D --quarantine=sliced"
        echo "udp-n$N-dmgnbat-qstatic-qf20-qmcs9-fp3-rlc100KB-run$seed|$D --quarantine=static --falsePositives=3"
        for t in 101.05 105 110; do
            ms=$(awk -v t="$t" 'BEGIN{printf "%d", t*1000+0.5}')
            echo "udp-n$N-dmgnbat-qswitch-qf20-t${ms}ms-qmcs9-fp3-rlc100KB-run$seed|$D --quarantine=switch --falsePositives=3 --detectionTime=$t"
        done
        P="--pcgnbat --pcClusters=$PCC $TAIL --RngRun=$seed"
        echo "udp-n$N-pcgnbatc$PCC-qsliced-qf20-qmcs9-rlc100KB-run$seed|$P --quarantine=sliced"
        echo "udp-n$N-pcgnbatc$PCC-qstatic-qf20-qmcs9-fp3-rlc100KB-run$seed|$P --quarantine=static --falsePositives=3"
        C="--csgnbat $TAIL --RngRun=$seed"
        echo "udp-n$N-csgnbat-qsliced-qf20-qmcs9-rlc100KB-run$seed|$C --quarantine=sliced"
        echo "udp-n$N-csgnbat-qstatic-qf20-qmcs9-fp3-rlc100KB-run$seed|$C --quarantine=static --falsePositives=3"
        for mbps in $PROBES; do
            kbps=$(awk -v m="$mbps" 'BEGIN{printf "%d", m*1000+0.5}')
            echo "udp-n$N-dmgnbat-qstatic-qf20-qmcs9-fp3-rlc100KB-fpprobe${kbps}kbps-run$seed|$D --quarantine=static --falsePositives=3 --fpProbeMbps=$mbps"
        done
    done
}

list_mcs() {
    local MCS_LIST="4 6 8 12" seed mcs D
    local TAIL="--attackers=$N --quarantineFraction=0.2 --rlcBufferKB=100"
    for seed in $(seq 1 $SEEDS); do
        for mcs in $MCS_LIST; do
            D="--dmgnbat $TAIL --quarantineMcs=$mcs --RngRun=$seed"
            echo "udp-n$N-dmgnbat-qstatic-qf20-qmcs${mcs}-fp3-rlc100KB-run$seed|$D --quarantine=static --falsePositives=3"
        done
    done
}

mode_base() {
    if [ "${DRYRUN:-0}" = "1" ]; then list_base; exit 0; fi

    ./ns3 run "$PROG --PrintHelp" >/dev/null 2>&1 || { echo "build failed"; exit 1; }
    mkdir -p logs-v2

    TOTAL=$(list_base | wc -l)
    echo "=== $TOTAL runs, up to $JOBS in parallel ($(date +%H:%M)) ==="
    while IFS='|' read -r name args; do
        if [ -f "txt-v2/$name" ]; then echo "skip  $name"; continue; fi
        while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do sleep "$POLL"; done
        echo "start $name  ($(date +%H:%M))"
        ./ns3 run --no-build "$PROG $args" > "logs-v2/$name.log" 2>&1 < /dev/null &
    done < <(list_base)
    wait
    DONE=$(ls txt-v2 2>/dev/null | grep -c "^udp-n$N-")
    echo "=== DONE ($(date +%H:%M)). Reports: $DONE of $TOTAL ==="
    echo "Analyze the results:  python3 scripts/analyze.py"
}

mode_mcs() {
    if [ "${DRYRUN:-0}" = "1" ]; then list_mcs; exit 0; fi

    ./ns3 run "$PROG --PrintHelp" >/dev/null 2>&1 || { echo "build failed"; exit 1; }
    mkdir -p logs-v2

    TOTAL=$(list_mcs | wc -l)
    echo "=== MCS SWEEP: $TOTAL runs, up to $JOBS in parallel ($(date +%H:%M)) ==="
    while IFS='|' read -r name args; do
        if [ -f "txt-v2/$name" ]; then echo "skip  $name"; continue; fi
        while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do sleep "$POLL"; done
        echo "start $name  ($(date +%H:%M))"
        ./ns3 run --no-build "$PROG $args" > "logs-v2/$name.log" 2>&1 < /dev/null &
    done < <(list_mcs)
    wait
    echo "=== END OF SWEEP ($(date +%H:%M)) ==="
    echo "Analyze the results:  python3 scripts/analyze.py figures"
}

mode_ue23() {
    local VARIANT=$1
    PWR=23
    if [ "$VARIANT" = mcs4 ]; then
        MCS=4
        RUN23=$ROOT/run-ue23-mcs4
        RUN2=$ROOT/run-ue2-mcs4check
        LOGS=$ROOT/logs-v2-ue23-mcs4
        TAIL="--attackers=$N --quarantineFraction=0.2 --rlcBufferKB=100"
        CHECK_NAME="udp-n$N-dmgnbat-qstatic-qf20-qmcs${MCS}-fp3-rlc100KB-run1"
        ARGS_A="--dmgnbat $TAIL --quarantineMcs=$MCS --RngRun=1 --quarantine=static --falsePositives=3"
        MODE_CMD="ue23-mcs4"
        ANALYSIS="python3 scripts/analyze.py ue23dbm-mcs4"
    else
        RUN23=$ROOT/run-ue23
        RUN2=$ROOT/run-ue2check
        LOGS=$ROOT/logs-v2-ue23
        TAIL="--attackers=$N --quarantineFraction=0.2 --quarantineMcs=9 --rlcBufferKB=100"
        CHECK_NAME="udp-n$N-dmgnbat-qsliced-qf20-qmcs9-rlc100KB-run1"
        ARGS_A="--dmgnbat $TAIL --RngRun=1 --quarantine=sliced"
        MODE_CMD="ue23"
        ANALYSIS="python3 scripts/analyze.py ue23dbm"
    fi

    jobs_list() {
        local seed D
        for seed in $(seq 1 $SEEDS); do
            if [ "$VARIANT" = mcs4 ]; then
                D="--dmgnbat $TAIL --quarantineMcs=$MCS --ueTxPowerDbm=$PWR --RngRun=$seed"
                echo "udp-n$N-dmgnbat-qstatic-qf20-qmcs${MCS}-fp3-rlc100KB-run$seed|$D --quarantine=static --falsePositives=3"
            else
                D="--dmgnbat $TAIL --ueTxPowerDbm=$PWR --RngRun=$seed"
                echo "udp-n$N-dmgnbat-qsliced-qf20-qmcs9-rlc100KB-run$seed|$D --quarantine=sliced"
                echo "udp-n$N-dmgnbat-qstatic-qf20-qmcs9-fp3-rlc100KB-run$seed|$D --quarantine=static --falsePositives=3"
            fi
        done
    }

    if [ "${DRYRUN:-0}" = "1" ]; then jobs_list; exit 0; fi

    [ -x ./ns3 ] || die "could not find ./ns3. Run from ns-3-dev."
    [ -f "scratch/$PROG.cc" ] || die "scratch/$PROG.cc does not exist. Copy rise-2q.cc from the repository to scratch/ (with another name: SIMULATOR=name)."

    if [ "${KEEP_PCAP:-0}" = "1" ]; then MIN_GB=${MIN_GB:-15}; else MIN_GB=${MIN_GB:-5}; fi
    FREE_KB=$(df -Pk "$ROOT" | awk 'NR==2 {print $4}')
    if [ "$((FREE_KB / 1024 / 1024))" -lt "$MIN_GB" ] && [ "${SKIP_DISK:-0}" != "1" ]; then
        die "low free space in $ROOT: $((FREE_KB / 1024 / 1024)) GB (minimum $MIN_GB GB). Free some space or use SKIP_DISK=1."
    fi

    for dir in "$RUN23" "$RUN2"; do
        if [ -n "$(ls -A "$dir" 2>/dev/null)" ] && [ "${RESUME:-0}" != "1" ]; then
            echo "ERROR: $dir already exists and is not empty."
            echo "  If it is from a previous attempt, move it and run again:  mv $dir $dir.old"
            die "if this is a resume of the same batch, use:  RESUME=1 bash scripts/simulate.sh $MODE_CMD"
        fi
    done
    if [ "$VARIANT" != mcs4 ] && [ -n "$(ls -A txt-v2-ue23 2>/dev/null)" ]; then
        echo "WARNING: txt-v2-ue23 (from the old guide) has files. This batch does NOT use that folder; do not mix them."
    fi

    mkdir -p "$RUN23" "$RUN2" "$LOGS"
    ./ns3 run "$PROG --PrintHelp" > "$LOGS/help.txt" 2>&1 || die "build failed. See $LOGS/help.txt"
    grep -q "ueTxPowerDbm" "$LOGS/help.txt" || die "the binary does not have the ueTxPowerDbm parameter."
    ./ns3 run --help 2>&1 | grep -q -e '--cwd' || die "this ns3 does not accept --cwd; without it the base pcaps would be overwritten."

    run_job() {
        local name=$1 args=$2 dir=$3 log=$4
        ./ns3 run --no-build --cwd="$dir" "$PROG $args" > "$log" 2>&1 < /dev/null
        [ "${KEEP_PCAP:-0}" = "1" ] || rm -f "$dir/pcaps-v2/$name"-*.pcap
    }
    snap_pcaps() { ls -l --time-style=full-iso "$ROOT/pcaps-v2" 2>/dev/null; }
    mb() {
        python3 - "$1" 2>/dev/null << 'PYEOF'
import re, sys
t = open(sys.argv[1], encoding="utf-8", errors="ignore").read()
rx = sum(int(m.group(1)) for b in re.split(r"Flow \d+ \(", t)[1:]
         if re.search(r"label=(attack|quarantined)", b)
         for m in [re.search(r"Rx Bytes:\s+(\d+)", b)] if m)
print(f"{rx/1e6:.1f}")
PYEOF
    }

    BASE="$ROOT/txt-v2/$CHECK_NAME"
    A_OUT="$RUN2/txt-v2/$CHECK_NAME"
    IFS='|' read -r NAME_B ARGS_B < <(jobs_list | head -1)
    B_OUT="$RUN23/txt-v2/$NAME_B"
    PCAPS_BEFORE=$(snap_pcaps)

    if [ "$VARIANT" = mcs4 ]; then
        T_CANARY0=$(date +%s)
        echo "=== CANARIES (seed 1, quarantine MCS $MCS): A = 2 dBm, B = $PWR dBm ($(date +%H:%M)) ==="
    else
        echo "=== CANARIES (seed 1, control): A = 2 dBm, B = $PWR dBm ($(date +%H:%M)) ==="
    fi
    if [ ! -f "$A_OUT" ]; then
        run_job "$CHECK_NAME" "$ARGS_A" "$RUN2" "$LOGS/canary-2dbm.log" &
        PID_A=$!
    else PID_A=""; fi
    if [ ! -f "$B_OUT" ]; then
        run_job "$NAME_B" "$ARGS_B" "$RUN23" "$LOGS/$NAME_B.log" &
        PID_B=$!
    else PID_B=""; fi
    [ -n "$PID_A$PID_B" ] && wait $PID_A $PID_B

    ok=1
    [ -f "$BASE" ]  || { echo "ERROR: missing base report $BASE"; ok=0; }
    [ -f "$A_OUT" ] || { echo "ERROR: the 2 dBm canary produced no result (see $LOGS/canary-2dbm.log)"; ok=0; }
    [ -f "$B_OUT" ] || { echo "ERROR: the $PWR dBm canary produced no result (see $LOGS/$NAME_B.log)"; ok=0; }
    if [ "$ok" = 1 ]; then
        if [ "$VARIANT" = mcs4 ]; then
            cmp -s "$BASE" "$A_OUT" || { echo "GATE 1 FAILED: the new binary at 2 dBm DIFFERS from the base sweep (MCS $MCS, seed 1). The code or the parameters do not reproduce the base."; ok=0; }
        else
            cmp -s "$BASE" "$A_OUT" || { echo "GATE 1 FAILED: the new binary at 2 dBm DIFFERS from the base batch (seed 1). The code or the parameters do not reproduce the base."; ok=0; }
        fi
        cmp -s "$BASE" "$B_OUT" && { echo "GATE 2 FAILED: at $PWR dBm the result is IDENTICAL to the 2 dBm one. The power had no effect."; ok=0; }
    fi
    [ "$(snap_pcaps)" = "$PCAPS_BEFORE" ] || { echo "GATE 3 FAILED: the base pcaps (pcaps-v2) were changed by the canaries. Check whether --cwd was respected."; ok=0; }
    if [ "$VARIANT" = mcs4 ]; then N_BATCH=$SEEDS; else N_BATCH=$((SEEDS * 2)); fi
    [ "$ok" = 1 ] || die "a gate failed. The batch of $N_BATCH runs was NOT started."
    echo "GATES OK: base reproduced byte by byte, $PWR dBm differs from 2 dBm, base pcaps intact."
    if [ "$VARIANT" = mcs4 ]; then
        echo "  seed 1, MCS $MCS, attack admitted by the quarantine: 2 dBm = $(mb "$A_OUT") MB | $PWR dBm = $(mb "$B_OUT") MB"
        MIN_CANARY=$(( ( $(date +%s) - T_CANARY0 + 59 ) / 60 ))
        if [ "$MIN_CANARY" -ge 2 ]; then
            echo "  the canaries took ~${MIN_CANARY} min; rough batch estimate: ~$(( ( (SEEDS - 1 + JOBS - 1) / JOBS ) * MIN_CANARY )) min"
        fi
    else
        echo "  seed 1, control, attack delivered: 2 dBm = $(mb "$A_OUT") MB | $PWR dBm = $(mb "$B_OUT") MB"
    fi
    echo

    TOTAL=$(jobs_list | wc -l)
    echo "=== $TOTAL runs at $PWR dBm, up to $JOBS in parallel ($(date +%H:%M)) ==="
    while IFS='|' read -r name args; do
        if [ -f "$RUN23/txt-v2/$name" ]; then echo "skip  $name"; continue; fi
        while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do sleep "$POLL"; done
        echo "start $name  ($(date +%H:%M))"
        run_job "$name" "$args" "$RUN23" "$LOGS/$name.log" &
    done < <(jobs_list)
    wait

    DONE=$(ls "$RUN23/txt-v2" 2>/dev/null | grep -c "^udp-n$N-")
    echo "=== DONE ($(date +%H:%M)). Reports: $DONE of $TOTAL ==="
    if [ "$DONE" -lt "$TOTAL" ]; then
        echo "MISSING:"
        jobs_list | cut -d'|' -f1 | while read -r n; do [ -f "$RUN23/txt-v2/$n" ] || echo "  $n"; done
        echo "See the logs in $LOGS and run again with:  RESUME=1 bash scripts/simulate.sh $MODE_CMD"
        exit 1
    fi
    echo "Batch complete. Analysis:  $ANALYSIS"
}

mode_verify() {
    local RUNV=$ROOT/run-verify
    local LOGS=$ROOT/logs-verify

    local SAMPLE=(
      "udp-n20-dmgnbat-qsliced-qf20-qmcs9-rlc100KB-run7"
      "udp-n20-dmgnbat-qstatic-qf20-qmcs9-fp3-rlc100KB-run13"
      "udp-n20-dmgnbat-qstatic-qf20-qmcs9-fp3-rlc100KB-run26"
      "udp-n20-dmgnbat-qswitch-qf20-t101050ms-qmcs9-fp3-rlc100KB-run19"
      "udp-n20-dmgnbat-qswitch-qf20-t110000ms-qmcs9-fp3-rlc100KB-run25"
      "udp-n20-pcgnbatc2-qsliced-qf20-qmcs9-rlc100KB-run5"
      "udp-n20-pcgnbatc2-qstatic-qf20-qmcs9-fp3-rlc100KB-run11"
      "udp-n20-csgnbat-qsliced-qf20-qmcs9-rlc100KB-run17"
      "udp-n20-csgnbat-qstatic-qf20-qmcs9-fp3-rlc100KB-run23"
      "udp-n20-dmgnbat-qstatic-qf20-qmcs9-fp3-rlc100KB-fpprobe600kbps-run29"
      "udp-n20-dmgnbat-qstatic-qf20-qmcs12-fp3-rlc100KB-run3"
      "udp-n20-dmgnbat-qstatic-qf20-qmcs4-fp3-rlc100KB-run31"
    )

    local ALL name args
    ALL=$( { list_base; list_mcs; } )
    local JOBLIST=()
    for name in "${SAMPLE[@]}"; do
        [ -n "${ONLY:-}" ] && ! [[ "$name" =~ $ONLY ]] && continue
        args=$(printf '%s\n' "$ALL" | awk -F'|' -v n="$name" '$1==n {print $2}')
        [ -n "$args" ] || die "the case is not in the lists of the base and mcs modes: $name"
        [ -f "$ROOT/txt-v2/$name" ] || die "missing reference result txt-v2/$name"
        JOBLIST+=("$name|$args")
    done
    [ "${#JOBLIST[@]}" -gt 0 ] || die "no case selected."

    [ -x ./ns3 ] || die "could not find ./ns3. Run from ns-3-dev."
    if [ -n "$(ls -A "$RUNV" 2>/dev/null)" ] && [ "${RESUME:-0}" != "1" ]; then
        die "$RUNV already exists and is not empty. Move it or use RESUME=1."
    fi
    mkdir -p "$RUNV" "$LOGS"
    ./ns3 run "$PROG --PrintHelp" > "$LOGS/help.txt" 2>&1 || die "build failed. See $LOGS/help.txt"
    ./ns3 run --help 2>&1 | grep -q -e '--cwd' || die "this ns3 does not accept --cwd; without it the check could overwrite txt-v2/."
    echo "simulator in use: scratch/$PROG.cc"

    run_job() {
        local name=$1 args=$2
        ./ns3 run --no-build --cwd="$RUNV" "$PROG $args" > "$LOGS/$name.log" 2>&1 < /dev/null
        rm -f "$RUNV/pcaps-v2/$name"-*.pcap
    }
    echo "=== checking ${#JOBLIST[@]} cases, up to $JOBS in parallel ($(date +%H:%M)) ==="
    while IFS='|' read -r name args; do
        if [ -f "$RUNV/txt-v2/$name" ]; then echo "skip  $name"; continue; fi
        while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do sleep "$POLL"; done
        echo "start $name  ($(date +%H:%M))"
        run_job "$name" "$args" &
    done < <(printf '%s\n' "${JOBLIST[@]}")
    wait

    local pass=0 fail=0 j
    echo; echo "=== RESULT (byte-by-byte comparison with txt-v2/) ==="
    for j in "${JOBLIST[@]}"; do
        name=${j%%|*}
        if [ ! -f "$RUNV/txt-v2/$name" ]; then echo "FAILED    $name  (the simulation produced no result; see $LOGS/$name.log)"; fail=$((fail + 1))
        elif cmp -s "$ROOT/txt-v2/$name" "$RUNV/txt-v2/$name"; then echo "IDENTICAL $name"; pass=$((pass + 1))
        else echo "DIFFERS   $name"; fail=$((fail + 1)); fi
    done
    echo; echo "=== $pass identical, $fail with problems, of ${#JOBLIST[@]} ($(date +%H:%M)) ==="
    [ "$fail" -eq 0 ] || exit 1
    echo "REPRODUCIBILITY CONFIRMED for the sample: the code in this repository reproduces the paper's results."
}

usage() {
    cat << 'EOF'
RISE-2Q: ALL the simulations and the reproduction check, in a single script.

Usage, from ns-3-dev, inside screen:
  bash scripts/simulate.sh base        main batch: 465 runs (Tables IV to VII, Figs. 2a and 2b)
  bash scripts/simulate.sh mcs         MCS sweep: 124 runs (Fig. 2c)
  bash scripts/simulate.sh ue23        23 dBm batch: 62 runs, with 2 canaries
  bash scripts/simulate.sh ue23-mcs4   MCS 4 at 23 dBm: 31 runs, with 2 canaries (Fig. 2c)
  bash scripts/simulate.sh verify      re-runs 12 cases and compares byte by byte with txt-v2/
  bash scripts/simulate.sh all         base, mcs and ue23, in sequence (a few days)

Every mode: up to 8 runs in parallel (server policy: at most half of the 16 physical cores)
and resumable (they skip what already exists). Optional variables common to all modes:
  DRYRUN=1 (only lists the runs, name|arguments), SEEDS=n, JOBS=n, POLL=s, SIMULATOR=name (ns-3 program)
Variables of each mode:
  ue23 and ue23-mcs4: RESUME=1, KEEP_PCAP=1, SKIP_DISK=1, MIN_GB=n
  verify:             ONLY="regex" (only the cases whose name matches), RESUME=1

After the simulations, the analyses are in:  python3 scripts/analyze.py
EOF
}

case "${1:-}" in
    base)       mode_base ;;
    mcs)        mode_mcs ;;
    ue23)       mode_ue23 main ;;
    ue23-mcs4)  mode_ue23 mcs4 ;;
    verify)     mode_verify ;;
    all)        bash "$0" base && bash "$0" mcs && bash "$0" ue23 ;;
    ""|help|-h|--help) usage ;;
    *)          echo "ERROR: unknown mode: $1"; echo "See: bash scripts/simulate.sh help"; exit 1 ;;
esac
