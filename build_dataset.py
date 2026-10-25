#!/usr/bin/env python3

import argparse
import os
import shutil
import subprocess
import sys

import pandas as pd

from common import FEATURES, WINDOW, WindowAggregator, iter_records, tshark_read_cmd


def process_pcap(path):
    proc = subprocess.Popen(tshark_read_cmd(path), stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True)
    agg, wins = WindowAggregator(), []
    for rec in iter_records(proc.stdout):
        wins.extend(agg.add(rec))
    proc.wait()
    return wins[1:]        


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data")
    a = ap.parse_args()
    if not shutil.which("tshark"):
        sys.exit("tshark no está instalado (ver setup.sh)")
    labels = pd.read_csv(os.path.join(a.data, "labels.csv"))
    rows = []
    for run, r in labels.iterrows():
        wins = process_pcap(r.pcap)
        for t, (start, feats, _top) in enumerate(wins):
            mid = start + WINDOW / 2
            attack = r.kind != "normal" and r.attack_start <= mid < r.attack_end
            rows.append({"run": run, "kind": r.kind, "t": t, "window_start": start,
                         **feats, "label": r.kind if attack else "normal"})
        print(f"run {run:02d} {r.kind:<11} ventanas={len(wins)}")
    df = pd.DataFrame(rows, columns=["run", "kind", "t", "window_start"] + FEATURES + ["label"])
    out = os.path.join(a.data, "dataset.csv")
    df.to_csv(out, index=False)
    print(f"\nDataset guardado en {out}  ({len(df)} ventanas)")
    print(df["label"].value_counts().to_string())


if __name__ == "__main__":
    main()
