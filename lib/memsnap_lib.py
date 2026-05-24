#!/usr/bin/env python3

"""memsnap_lib.py — shared utilities for MemSnap train / detect pipeline.

Exports
-------
Column definitions
    ALL_FEATURES, BINARY_FEATURES, DEAD_FEATURES, LABELS, SENTINEL,
    TRAINING_MEDIANS

CSV loading (training)
    load_csv_and_clean(csv_path, binary=False)
    sample_weights(y)

Inference helpers
    impute_sentinels(X), align_features(X, feature_names), load_model(path, label)
    stage1_binary(...), stage2_families(...)

Volatility runner
    run_plugin(dump_path, plugin, symbols_dir, verbose=False, timeout=900)
    run_all_plugins(dump_path, symbols_dir, plugin_workers=2, verbose=False, timeout=900)
    extract_features(results)

Output helpers
    print_feature_vector(X), print_family_table(family_results)
    print_importances(clf, features)

Checksum
    compute_checksum(path)  -> sha256 hex string
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

# ── Column / label definitions ────────────────────────────────────────────────

# Features dropped from the binary classifier (zero-variance in training data)
DEAD_FEATURES: list[str] = [
    "deleted_exe_count",
    "hooked_syscall_count",
    "foreign_conn_count",
    "high_port_count",
    "netfilter_hook_count",
]

# Full feature set used by the multi-label RF
ALL_FEATURES: list[str] = [
    "hidden_proc_count",
    "masqueraded_proc_count",
    "deleted_exe_count",
    "hooked_syscall_count",
    "hidden_module_count",
    "netfilter_hook_count",
    "rwx_region_count",
    "total_sockets",
    "raw_socket_count",
    "foreign_conn_count",
    "high_port_count",
    "unknown_lib_count",
]

# Reduced feature set used by the binary classifier
BINARY_FEATURES: list[str] = [f for f in ALL_FEATURES if f not in DEAD_FEATURES]

LABELS: list[str] = [
    "label_rootkit",      "label_azazel",       "label_orbit",
    "label_mirai",        "label_syslogk",      "label_reptile",
    "label_bpfbackdoor",  "label_reverseshell", "label_skidmap",
    "label_cryptominer",  "label_teamtnt",      "label_multistage",
    "label_credscrape",
]

SENTINEL: int = -1

# Medians from the training set — must match train-time imputation
TRAINING_MEDIANS: dict[str, int | float] = {
    "rwx_region_count":  8,
    "unknown_lib_count": 0,
}

# Volatility plugins to execute
PLUGINS: list[str] = [
    "linux.pslist.PsList",
    "linux.psscan.PsScan",
    "linux.malware.check_syscall.Check_syscall",
    "linux.malware.hidden_modules.Hidden_modules",
    "linux.sockstat.Sockstat",
    "linux.malware.malfind.Malfind",
    "linux.malware.netfilter.Netfilter",
    "linux.proc.Maps",
]

_BRACKET_RE = re.compile(r"^\[.+\]$")
_LOCAL_RE   = re.compile(
    r"^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|::1$|$)"
)

# ─────────────────────────────────────────────────────────────────────────────
# CSV loading (training)
# ─────────────────────────────────────────────────────────────────────────────

def _impute_sentinel_cols(X: pd.DataFrame) -> pd.DataFrame:
    """Replace SENTINEL (-1) values in-place using column medians; logs to stderr."""
    sentinel_counts = (X == SENTINEL).sum()
    sentinel_cols   = sentinel_counts[sentinel_counts > 0]
    if not sentinel_cols.empty:
        print("[*] Imputing sentinel (-1) values:")
        for col in sentinel_cols.index:
            X[col]  = X[col].astype(float)
            median  = X.loc[X[col] != SENTINEL, col].median()
            n       = int(sentinel_counts[col])
            X.loc[X[col] == SENTINEL, col] = median
            print(f"    {col}: {n} row(s) -> median {median:.0f}")
    return X


def load_csv_and_clean(
    csv_path: str,
    binary: bool = False,
) -> tuple[pd.DataFrame, pd.DataFrame | pd.Series]:
    """Load *csv_path*, validate columns, impute sentinels, return (X, y).

    Parameters
    ----------
    csv_path : str
        Path to the features CSV.
    binary : bool
        If True, derive a single binary label (infected=1 / clean=0) from
        the family columns and use BINARY_FEATURES.  If False, return the
        full multi-label matrix and use ALL_FEATURES.

    Returns
    -------
    X : pd.DataFrame
    y : pd.DataFrame (multi-label) or pd.Series (binary)
    """
    df = pd.read_csv(csv_path)

    features = BINARY_FEATURES if binary else ALL_FEATURES

    missing_feats = [c for c in features if c not in df.columns]
    if missing_feats:
        print(f"[!] Missing feature columns: {missing_feats}", file=sys.stderr)
        sys.exit(1)

    X = df[features].copy()

    if binary:
        present = [c for c in LABELS if c in df.columns]
        if not present:
            print("[!] No family label columns found in CSV.", file=sys.stderr)
            sys.exit(1)

        y = (df[present] == 1).any(axis=1).astype(int)
        n_clean    = int((y == 0).sum())
        n_infected = int((y == 1).sum())
        print(f"[*] Binary label derived from {len(present)} family columns")
        print(f"    clean={n_clean}  infected={n_infected}  total={len(y)}")

        if n_clean == 0:
            print(
                "[!] No clean samples found — binary classifier needs both classes.\n"
                "[!] Use features.csv (204 rows), not features_nocleanlines.csv.",
                file=sys.stderr,
            )
            sys.exit(1)
    else:
        missing_labels = [c for c in LABELS if c not in df.columns]
        if missing_labels:
            print(f"[!] Missing label columns: {missing_labels}", file=sys.stderr)
            sys.exit(1)
        y = df[LABELS].copy()

    X = _impute_sentinel_cols(X)
    return X, y


def sample_weights(y: pd.Series) -> np.ndarray:
    """Return per-sample weights that up-weight clean samples to balance classes."""
    n_infected = int((y == 1).sum())
    n_clean    = int((y == 0).sum())
    ratio      = n_infected / n_clean
    weights    = np.where(y == 0, ratio, 1.0)
    print(f"[*] Class weights: infected=1.0  clean={ratio:.1f}")
    return weights


# ─────────────────────────────────────────────────────────────────────────────
# Inference helpers
# ─────────────────────────────────────────────────────────────────────────────

def impute_sentinels(X: pd.DataFrame) -> pd.DataFrame:
    """Apply TRAINING_MEDIANS then replace any remaining -1 with 0."""
    X = X.copy()
    for col, median in TRAINING_MEDIANS.items():
        if col in X.columns:
            X.loc[X[col] == SENTINEL, col] = median
    X = X.replace(SENTINEL, 0)
    return X


def align_features(X: pd.DataFrame, feature_names: list[str]) -> pd.DataFrame:
    """Add missing columns (zeroed) and reorder to match *feature_names*."""
    for col in feature_names:
        if col not in X.columns:
            X[col] = 0
    return X[feature_names]


def load_model(path: str, label: str) -> tuple[Any, list | None, list | None, str | None]:
    """Load a model artifact; returns (model, feature_names, label_names, type_str)."""
    try:
        meta = joblib.load(path)
    except FileNotFoundError:
        print(
            f"[!] {label} model not found at {path}. "
            "Run the appropriate train script first."
        )
        sys.exit(1)

    if isinstance(meta, dict):
        return (
            meta["model"],
            meta.get("features"),
            meta.get("labels"),
            meta.get("type"),
        )
    return meta, None, None, None


def _to_scalar(val: Any) -> Any:
    """Coerce a possibly-wrapped prediction/probability to a Python scalar."""
    if isinstance(val, (np.ndarray, list, tuple)):
        val = np.asarray(val).ravel()
        return val[0] if val.size else 0
    return val


def stage1_binary(
    model: Any,
    feature_names: list[str] | None,
    X_raw: pd.DataFrame,
    threshold: float,
) -> tuple[bool, float | None]:
    """Stage 1 — binary triage.  Returns (is_infected, confidence)."""
    X = X_raw.copy()
    if feature_names:
        X = align_features(X, feature_names)
    X = impute_sentinels(X)

    pred = int(_to_scalar(model.predict(X)[0]))

    conf: float | None = None
    try:
        proba = model.predict_proba(X)
        if isinstance(proba, list):
            proba = proba[0]
        proba = proba[0]
        # DEBUG
        # proba = _to_scalar(proba)
        # conf  = float(proba[1]) if hasattr(proba, "__len__") and len(proba) > 1 else float(proba)
        conf  = float(proba[1])
    except Exception:
        pass

    is_infected = bool(pred) or (conf is not None and conf >= threshold)
    return is_infected, conf


def stage2_families(
    model: Any,
    feature_names: list[str] | None,
    label_names: list[str] | None,
    X_raw: pd.DataFrame,
    threshold: float,
) -> list[dict]:
    """Stage 2 — family identification.  Returns list of {family, detected, confidence}."""
    X = X_raw.copy()
    if feature_names:
        X = align_features(X, feature_names)
    X = impute_sentinels(X)

    pred = model.predict(X)[0]

    try:
        probas    = model.predict_proba(X)
        has_proba = True
    except Exception:
        probas    = None
        has_proba = False

    labels = (
        [l.replace("label_", "") for l in label_names]
        if label_names
        else [
            "rootkit", "azazel", "orbit", "mirai", "syslogk", "reptile",
            "bpfbackdoor", "reverseshell", "skidmap", "cryptominer",
            "teamtnt", "multistage", "credscrape",
        ]
    )

    results = []
    for i, label in enumerate(labels):
        conf: float | None = None
        if has_proba and i < len(probas):
            arr  = probas[i][0]
            conf = float(arr[1]) if len(arr) > 1 else float(arr[0])
        is_detected = bool(pred[i]) or (conf is not None and conf >= threshold)
        results.append({
            "family":     label,
            "detected":   is_detected,
            "confidence": round(conf, 4) if conf is not None else None,
        })
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Volatility runner + feature extractor
# ─────────────────────────────────────────────────────────────────────────────

_print_lock = threading.Lock()


def run_plugin(
    dump_path: str | Path,
    plugin: str,
    symbols_dir: str | Path,
    verbose: bool = False,
    timeout: int = 900,
) -> tuple[str, list]:
    """Run a single Volatility 3 plugin; returns (plugin_name, rows)."""
    short = plugin.split(".")[-1]
    cmd = [
        "vol", "-f", str(dump_path),
        "-s", str(symbols_dir),
        "--renderer", "json",
        plugin,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0 or not proc.stdout.strip():
            if verbose:
                with _print_lock:
                    print(f"  [!] {short:<20s} failed (exit {proc.returncode})", file=sys.stderr)
            return plugin, []
        data = json.loads(proc.stdout)
        if isinstance(data, list):
            rows = data
        elif isinstance(data, dict):
            rows = data.get("rows", data.get("data", []))
        else:
            rows = []
        if verbose:
            with _print_lock:
                status = f"{len(rows)} rows" if rows else "empty"
                print(f"  [+] {short:<20s} {status}", file=sys.stderr)
        return plugin, rows
    except Exception as e:
        if verbose:
            with _print_lock:
                print(f"  [!] {short:<20s} failed: {e}", file=sys.stderr)
        return plugin, []


def run_all_plugins(
    dump_path: str | Path,
    symbols_dir: str | Path,
    plugin_workers: int = 2,
    verbose: bool = False,
    timeout: int = 900,
) -> dict[str, list]:
    """Run all PLUGINS in parallel; returns mapping of plugin -> rows."""
    results: dict[str, list] = {}
    with ThreadPoolExecutor(max_workers=plugin_workers) as pool:
        futures = {
            pool.submit(run_plugin, dump_path, p, symbols_dir, verbose, timeout): p
            for p in PLUGINS
        }
        for fut in as_completed(futures):
            plugin, rows = fut.result()
            results[plugin] = rows
    return results


def extract_features(results: dict[str, list]) -> dict[str, int]:
    """Derive the 12 scalar features from raw Volatility plugin output."""
    pslist    = results.get("linux.pslist.PsList",                         [])
    psscan    = results.get("linux.psscan.PsScan",                         [])
    chk       = results.get("linux.malware.check_syscall.Check_syscall",   [])
    hidden    = results.get("linux.malware.hidden_modules.Hidden_modules", [])
    socks     = results.get("linux.sockstat.Sockstat",                     [])
    malfind   = results.get("linux.malware.malfind.Malfind",               [])
    netfilter = results.get("linux.malware.netfilter.Netfilter",           [])
    maps      = results.get("linux.proc.Maps",                             [])

    f: dict[str, int] = {}

    # hidden processes
    if pslist and psscan:
        pids_list = {r.get("PID") for r in pslist if isinstance(r, dict)}
        pids_scan = {r.get("PID") for r in psscan if isinstance(r, dict)}
        f["hidden_proc_count"] = len(pids_scan - pids_list)
    else:
        f["hidden_proc_count"] = SENTINEL

    # masqueraded kernel threads
    if pslist:
        f["masqueraded_proc_count"] = sum(
            1 for p in pslist
            if isinstance(p, dict)
            and _BRACKET_RE.match(str(p.get("COMM", p.get("Name", p.get("Process", "")))))
            and p.get("PPID", p.get("ParentPID", 2)) not in (2, "2")
        )
    else:
        f["masqueraded_proc_count"] = SENTINEL

    # deleted executables
    if pslist:
        f["deleted_exe_count"] = sum(
            1 for p in pslist
            if isinstance(p, dict)
            and "(deleted)" in str(p.get("File", p.get("Executable", "")))
        )
    else:
        f["deleted_exe_count"] = SENTINEL

    # hooked syscalls
    if chk:
        def _is_hooked(r: dict) -> bool:
            sym = str(r.get("Handler Symbol", ""))
            return not any(sym.startswith(pfx) for pfx in (
                "__x64_sys_", "__ia32_sys_", "sys_", "do_",
                "__se_sys_", "__do_sys_", "ksys_",
            ))
        f["hooked_syscall_count"] = sum(
            1 for r in chk if isinstance(r, dict) and _is_hooked(r)
        )
    else:
        f["hooked_syscall_count"] = SENTINEL

    # hidden kernel modules
    f["hidden_module_count"] = len(hidden) if hidden else 0

    # netfilter hooks
    f["netfilter_hook_count"] = len(netfilter) if netfilter else 0

    # RWX anonymous regions
    if malfind:
        f["rwx_region_count"] = sum(
            1 for r in malfind
            if isinstance(r, dict)
            and "x" in str(r.get("Protection", r.get("Prot", ""))).lower()
        )
    else:
        f["rwx_region_count"] = SENTINEL

    # socket features
    if socks:
        f["total_sockets"] = len(socks)
        raw = foreign = high_port = 0
        for s in socks:
            if not isinstance(s, dict):
                continue
            family = str(s.get("Family",   "")).upper()
            proto  = str(s.get("Protocol", s.get("Proto", ""))).upper()
            state  = str(s.get("State",    "")).upper()
            dst    = str(s.get("Foreign Address", s.get("Dst", s.get("Remote Address", ""))))
            port   = s.get("Source Port", s.get("Local Port", s.get("Port", 0)))
            if "PACKET" in family or "RAW" in proto:
                raw += 1
            if state == "ESTABLISHED" and not _LOCAL_RE.match(dst):
                foreign += 1
            try:
                if int(port) > 1024 and state in ("LISTEN", ""):
                    high_port += 1
            except (ValueError, TypeError):
                pass
        f["raw_socket_count"]   = raw
        f["foreign_conn_count"] = foreign
        f["high_port_count"]    = high_port
    else:
        f["total_sockets"] = f["raw_socket_count"] = \
        f["foreign_conn_count"] = f["high_port_count"] = SENTINEL

    # unknown shared libraries (LD_PRELOAD indicator)
    if maps:
        known = ("/usr/lib", "/lib", "/usr/local/lib", "/usr/bin", "/usr/sbin")
        seen: set[str] = set()
        count = 0
        for row in maps:
            if not isinstance(row, dict):
                continue
            path = str(row.get("File Path", row.get("Path", row.get("File", ""))))
            if (
                ".so" in path
                and not any(path.startswith(k) for k in known)
                and path not in seen
                and path != ""
            ):
                seen.add(path)
                count += 1
        f["unknown_lib_count"] = count
    else:
        f["unknown_lib_count"] = SENTINEL

    return f


# ─────────────────────────────────────────────────────────────────────────────
# Output helpers
# ─────────────────────────────────────────────────────────────────────────────

def print_feature_vector(X: pd.DataFrame) -> None:
    print("\n[*] Feature vector:")
    for col in X.columns:
        print(f"    {col:30s}: {X[col].iloc[0]}")


def print_family_table(family_results: list[dict]) -> None:
    print("\n" + "=" * 56)
    print(f"{'MALWARE FAMILY':20s} {'STATUS':12s} {'CONFIDENCE':>12s}")
    print("=" * 56)

    detected = []
    for r in family_results:
        conf_str = f"{r['confidence']:>11.1%}" if r["confidence"] is not None else "    —"
        status   = "DETECTED" if r["detected"] else "clean"
        marker   = "[!]" if r["detected"] else "[+]"
        print(f"{marker} {r['family']:17s} {status:12s} {conf_str}")
        if r["detected"]:
            detected.append(r)

    print("=" * 56)

    if detected:
        print(f"\n[!] {len(detected)} malware family(s) flagged:")
        for r in detected:
            bar = "#" * int(r["confidence"] * 20) if r["confidence"] else ""
            print(f"    - {r['family']:15s} {r['confidence']:>6.1%}  {bar}")
    else:
        print("\n[+] No known malware families detected.")


def print_importances(clf: Any, features: list[str]) -> None:
    print("\n[*] Feature importances:")
    for feat, imp in sorted(
        zip(features, clf.feature_importances_), key=lambda x: -x[1]
    ):
        bar = "#" * int(imp * 40)
        print(f"  {feat:30s} {imp:.3f}  {bar}")


# ─────────────────────────────────────────────────────────────────────────────
# Checksum
# ─────────────────────────────────────────────────────────────────────────────

def compute_checksum(path: Path) -> str:
    """Return the SHA-256 hex digest of *path*, streaming in 1 MiB chunks.

    Handles arbitrarily large memory dumps without loading them into RAM.
    """
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
