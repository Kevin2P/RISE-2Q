# RISE-2Q : Radio-Level Isolation and Slicing Enforcing Quarantine and QoS

A UDP-flood botnet attacks a five-cell 5G NR network simulated in ns-3 with the 5G-LENA module. Suspected devices are moved to a quarantine bandwidth part (BWP) with a fixed uplink MCS. The study measures how much attack traffic still reaches the victim and how well the legitimate devices quarantined by mistake keep their service.

## Contents

```
scratch/rise-2q.cc          ns-3 simulation program
scripts/simulate.sh         runs every simulation of the paper
scripts/analyze.py          computes every number of the paper from the reports
scripts/plot-v2.py          draws Fig. 2 from the reports
data/                       the simulation reports used in the paper, with their SHA-256 manifests
```

## Reproducing the results from the data

Requirements: Python 3 (the analysis uses only the standard library) and `matplotlib` for the figures
(`pip install matplotlib`). Run every step from the root of this repository.

1. Unpack the reports of all simulations:

   ```
   tar xzf data/reports.tgz
   tar xzf data/reports-ue23-mcs4.tgz
   ```

2. Check that the reports are intact. Every line must end in `OK` (651 lines, then 31); on macOS, use
   `shasum -a 256 -c` instead of `sha256sum -c`:

   ```
   sha256sum -c data/reports.sha256
   sha256sum -c data/reports-ue23-mcs4.sha256
   ```

3. Compute every number of the paper, in the order of the paper (medians over the 31 seeds):

   ```
   python3 scripts/analyze.py
   ```

   A single part is printed with `python3 scripts/analyze.py <command>` (`help` lists all commands):

   | Paper item | Command |
   |---|---|
   | Tables II and III, Fig. 1 and the values of Section III | `derived` |
   | Table IV | `final`, `port5000`, `fpcs` |
   | Tables V and VI | `final`, `fpcs` |
   | Table VII and Section IV-D | `percell` |
   | Fig. 2(a) | `throughput`, `quartiles` |
   | Fig. 2(b) and Section IV-B | `switch`, `quartiles`, `derived` |
   | Fig. 2(c) and the 23 dBm results | `mcs`, `ue23dbm`, `ue23dbm-mcs4` |
   | Seed-by-seed results of Sections IV-A, IV-C and IV-E | `robustness` |

4. Draw the three panels of Fig. 2 into `img-v2/`:

   ```
   python3 scripts/plot-v2.py
   ```

   The script reads the reports unpacked in step 1 and computes the plotted values with the same functions as `analyze.py`; without the reports, it stops with an error. Fig. 1 is a diagram drawn by the authors.

## Reproducing the simulations

The reports of the paper were reproduced byte by byte on Debian GNU/Linux 13 with gcc 14.2.0, CMake 3.31.6 and Python 3.13.5.

1. Get ns-3.40 and the 5G-LENA NR module (branch `5g-lena-v2.6.y`) at the commits used in the paper. No patch is needed:

   ```
   git clone https://gitlab.com/nsnam/ns-3-dev.git
   cd ns-3-dev
   git checkout 4fdc985b5d5b800992e0ce87df7a727e32033794
   git clone https://gitlab.com/cttc-lena/nr.git contrib/nr
   git -C contrib/nr checkout f2412cb6a59377491d692cad46abf8c733bddffd
   ```

2. Copy the simulator and the scripts of this repository into `ns-3-dev` (the commands assume that this repository is next to `ns-3-dev`, in `../rise-2q`):

   ```
   cp ../rise-2q/scratch/rise-2q.cc scratch/
   cp -r ../rise-2q/scripts .
   ```

3. Configure and build with the default profile, as in the paper:

   ```
   ./ns3 configure
   ./ns3 build
   ```

   The quick check below reproduces the reports of the paper byte by byte with a default build that has Eigen support enabled: install Eigen (for example, the `libeigen3-dev` package) before configuring, and check that `./ns3 show config` reports `Eigen3 support : ON` and `Build profile : default`. The options of the program are listed with `./ns3 run "rise-2q --help"`.

4. Quick check (12 simulations instead of the full set): unpack the reports into `ns-3-dev` and rerun 12 representative cases, which are compared byte by byte with the reports of the paper:

   ```
   tar xzf ../rise-2q/data/reports.tgz
   bash scripts/simulate.sh verify
   ```

   The simulator is deterministic for a given build and platform; with another compiler or CPU, expect the same medians rather than identical files.

5. Full set, from `ns-3-dev`:

   | Command | Runs | Used for |
   |---|---|---|
   | `bash scripts/simulate.sh base` | 465 | Tables IV to VII, Fig. 2(a) and 2(b) |
   | `bash scripts/simulate.sh mcs` | 124 | Fig. 2(c) |
   | `bash scripts/simulate.sh ue23` | 62 | the 23 dBm results |
   | `bash scripts/simulate.sh ue23-mcs4` | 31 | the 23 dBm point at MCS 4 in Fig. 2(c) |
   | `bash scripts/simulate.sh all` | 651 | `base`, `mcs` and `ue23` |

   The script runs up to 8 simulations in parallel (`JOBS=n` changes this), skips the runs whose report already exists, and only lists the runs when called with `DRYRUN=1`. Reports are written to `txt-v2/`, and those of the 23 dBm batches to `run-ue23/` and `run-ue23-mcs4/`. The 23 dBm batches first run two short checks and do not start unless the 2 dBm check reproduces the base report byte by byte and the 23 dBm check differs from it.

6. Compute the numbers from the new reports, still from `ns-3-dev`:

   ```
   python3 scripts/analyze.py
   ```

## License

GPL-2.0-only. `scratch/rise-2q.cc` derives from a 5G-LENA example by CTTC that is distributed under this license (see the header of the file). The full text is in `LICENSE`.
