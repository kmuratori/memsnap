# MemSnap

Automated **Linux memory forensics** - infects, captures, extracts features, and detects rootkits, code injection, and backdoors using a two-stage AI pipeline.

## Quick start

```bash
git clone https://github.com/kmuratori/memsnap.git
cd memsnap
sudo apt install -y libsnappy-dev build-essential linux-headers-$(uname -r)
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
make                # compiles attack binaries from assets/src/
# Rootkit: clone, patch, build and copy diamorphine.ko into assets/ (see below)
./memsnap infect -i -a dumps/                              # infect all + capture dump
./memsnap extract dumps/ assets/binary.csv                 # extract features
./memsnap train -i assets/binary.csv -b -o assets/ai-model/binary_clf.joblib   # train stage 1
./memsnap train -i assets/family.csv -o assets/ai-model/family_clf.joblib      # train stage 2
./memsnap detect dumps/memdump_...rootkit.raw              # detect threats
./memsnap web                                              # start web interface (FastAPI)
```

## Setup

1. **System dependencies**
   ```bash
   sudo apt install -y libsnappy-dev build-essential linux-headers-$(uname -r)
   ```

2. **Python environment & Volatility 3**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Build assets**
   - Injection library:
     ```bash
     cd assets
     gcc -shared -fPIC evil.c -o evil.so
     cd ..
     ```
   - Rootkit module (Diamorphine):
     ```bash
     cd /tmp
     git clone https://github.com/m0nad/Diamorphine
     cd Diamorphine
     sed -i 's/PROC_ROOT_INO/PROCFS_ROOT_INO/g' diamorphine.c
     make
     cp diamorphine.ko ~/memsnap/assets/
     cd ~/memsnap
     ```
     (Rebuild the module if you change the kernel version.)

4. **Symbol table** — pre-generated ISF file for kernel `6.17.0-22-generic` is already in `assets/symbols/`. For other kernels, generate a new one with `dwarf2json`.

5. **Memory acquisition** — AVML is downloaded automatically on first use.

## Usage

All commands use the `./memsnap` entry point:

| Command | Purpose |
|---------|---------|
| `./memsnap infect -i [components] -a [dir]` | Infect VM, optionally capture a dump |
| `./memsnap extract <dumps_dir> [csv]` | Extract features from dumps |
| `./memsnap train -i <csv> [-b] [-o model]` | Train stage 1 (binary, `-b`) or stage 2 (family) model |
| `./memsnap detect <dump> [-b binary_clf.joblib] [-m family_clf.joblib]` | Detect threats in a single dump |
| `./memsnap web` | Launch web-based detection interface (FastAPI) |
| `./memsnap vol <dump>` | Run raw Volatility 3 analysis |

Examples:
```bash
# Infect and capture
./memsnap infect -i rootkit -a dumps/

# Build training datasets
./memsnap extract dumps/ assets/binary.csv
./memsnap extract dumps/ assets/family.csv --no-db

# Train models
./memsnap train -i assets/binary.csv -b -o assets/ai-model/binary_clf.joblib
./memsnap train -i assets/family.csv -o assets/ai-model/family_clf.joblib

# Detect (uses assets/ai-model/ defaults)
./memsnap detect dumps/memdump_20260518_rootkit.raw
./memsnap detect dumps/memdump_20260518_rootkit.raw --json

# Force re-extraction (skip DB cache)
./memsnap detect dumps/memdump_20260518_rootkit.raw --no-cache
```

Dumps are named `memdump_<timestamp>_<components>.raw`.

> **Note:** After cleaning with `./memsnap infect -c`, the rootkit may persist. Reboot to fully remove it.

## Detection pipeline

Detection runs in two stages:

**Stage 1 — binary triage** (`binary_clf.joblib`)
Answers: is this machine infected? If clean, pipeline stops here.

**Stage 2 — family identification** (`family_clf.joblib`)
Answers: which malware families are present? Runs only when stage 1 flags infection.

Both models use 7 live features derived from 8 Volatility plugins:

| Feature | Source |
|---------|--------|
| `hidden_proc_count` | pslist vs psscan delta |
| `masqueraded_proc_count` | bracket-named procs with wrong PPID |
| `hidden_module_count` | Hidden_modules plugin |
| `rwx_region_count` | Anonymous executable memory regions |
| `total_sockets` | Sockstat |
| `raw_socket_count` | Sockstat (PACKET/RAW families) |
| `unknown_lib_count` | Shared libs outside standard paths |

Plugin results and feature vectors are cached in SQLite (`~/.local/share/memsnap/memsnap.db`). Re-running detection against the same dump skips Volatility entirely.

## Training data

| File | Used for | Clean | Infected | Total |
|------|----------|-------|----------|-------|
| `assets/binary.csv` | Stage 1 (`-b`) | 195 (augmented) | 195 | 390 |
| `assets/family.csv` | Stage 2 (default) | 0 | 195 | 195 |

Stage 1 was trained on an augmented balanced dataset (195 synthetic clean + 195 real infected). Stage 2 uses infected-only samples across 13 malware families.

## Project structure

```
memsnap                    -> unified entry script
scripts/
  infect                   -> infection & memory capture
  extract                  -> batch feature extraction
  train                    -> unified model trainer (stage 1 + stage 2)
  detect                   -> single-dump CLI detection
  dumper                   -> training dump generator / manifest writer
  web                      -> FastAPI web interface
assets/
  ai-model/
    binary_clf.joblib      -> stage 1: binary triage model
    family_clf.joblib      -> stage 2: family identification model
    binary.csv             -> stage 1 training data
    family.csv             -> stage 2 training data
  symbols/                 -> Volatility symbol tables
  src/                     -> attack source files (compiled by make)
  diamorphine.ko           -> pre-built rootkit module
  evil.so                  -> pre-built injection library
  index.html / app.js      -> web UI
lib/
  memsnap_lib.py           -> shared utilities (features, inference, Volatility runner)
  db.py                    -> SQLite persistence layer
  migrations/
    0001.sql               -> schema
report/                    -> technical report
Makefile                   -> compiles attack binaries from assets/src/
requirements.txt
```

## Known limitations

- **Stage 2 family discrimination** — rootkit and azazel share similar feature profiles at high `hidden_proc_count` / `masqueraded_proc_count` values; the RF boundary between them is weak with current features.
- **Clean sample diversity** — augmented clean samples are synthetic variations of a small number of real clean captures; unusual-but-clean systems (e.g. high kernel thread count) may push closer to the infected boundary.
- **Dead features** — `deleted_exe_count`, `hooked_syscall_count`, `foreign_conn_count`, `high_port_count`, `netfilter_hook_count` are extracted but excluded from training (zero variance on current dataset). They activate on different kernels or malware variants and will contribute once more diverse data is available.

## Environment

- **VM**: Ubuntu 24.04, kernel `6.17.0-22-generic`, 512 MB RAM, VirtualBox
- **Volatility**: 3.2.8.0 (installed via `requirements.txt`)
- **Python**: 3.x, inside a venv
