#!/usr/bin/env python3

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time

import numpy as np
import pandas as pd
from mininet.log import setLogLevel

from common import VICTIM_IP
from topology import HERE, build_net, ensure_controller, start_net, victim_iface
from traffic import (attack_duration, run_attack, start_normal_traffic, start_services,
                     stop_procs, stop_services)


def parse_ping(path):
    pat = re.compile(r"^\[(\d+\.\d+)\].*time=([\d.]+) ms")
    out = []
    for line in open(path):
        m = pat.match(line)
        if m:
            out.append((float(m.group(1)), float(m.group(2))))
    return out


def ping_stats(rx, t0, t1, interval=0.2):
    sel = [rtt for ts, rtt in rx if t0 <= ts < t1]
    expected = max(1.0, (t1 - t0) / interval)
    return {"rtt_avg_ms": round(float(np.mean(sel)), 1) if sel else None,
            "rtt_max_ms": round(float(np.max(sel)), 1) if sel else None,
            "loss_pct": round(max(0.0, 100 * (1 - len(sel) / expected)), 1)}


def run_one(attack, mitigate, a):
    tag = f"{attack}_{'on' if mitigate else 'off'}"
    res = os.path.join(HERE, "results")
    os.makedirs(res, exist_ok=True)
    ping_file, det_log = os.path.join(res, f"ping_{tag}.txt"), os.path.join(res, f"detector_{tag}.csv")

    net = build_net()
    start_net(net)
    services = start_services(net, os.path.join(HERE, "data"))
    det_cmd = [sys.executable, os.path.join(HERE, "detector.py"), "--iface", victim_iface(net),
               "--models", os.path.join(HERE, "models"), "--log", det_log]
    if mitigate:
        det_cmd.append("--mitigate")
    det = subprocess.Popen(det_cmd, cwd=HERE, stdout=open(os.path.join(res, f"detector_{tag}.log"), "w"),
                           stderr=subprocess.STDOUT)
    time.sleep(4)
    ping = net.get("h2").popen(["ping", "-D", "-i", "0.2", "-W", "1", VICTIM_IP],
                               stdout=open(ping_file, "w"), stderr=subprocess.DEVNULL)
    traffic = start_normal_traffic(net, with_ping=False)
    t_start = time.time()
    time.sleep(a.pre)
    a0, a1 = run_attack(net, attack, 100, a.stage, a.hold)
    time.sleep(a.post)
    t_end = time.time()

    ping.send_signal(signal.SIGINT)
    stop_procs(traffic)
    det.send_signal(signal.SIGINT)
    time.sleep(1)
    stop_services(services)
    net.stop()

    rx, d = parse_ping(ping_file), pd.read_csv(det_log)
    first = lambda act: (float(d[(d.action.fillna("").str.contains(act)) & (d.ts >= a0)].ts.min())
                         if ((d.action.fillna("").str.contains(act)) & (d.ts >= a0)).any() else None)
    t_warn, t_det, t_blk = first("EARLY_WARNING"), first("DETECTED"), first("BLOCK")
    rel = lambda t: None if t is None else round(t - a0, 1)
    pps = lambda t0, t1: round(float(d[(d.win_start >= t0) & (d.win_start < t1)].pkts.mean()), 0)
    out = {"attack": attack, "mitigation": mitigate,
           "false_alarms_before_attack": int(((d.ts < a0) & (d.pred != "normal")).sum()),
           "early_warning_s_after_start": rel(t_warn), "detection_s_after_start": rel(t_det),
           "block_s_after_start": rel(t_blk),
           "baseline": {**ping_stats(rx, t_start + 3, a0), "victim_pps": pps(t_start + 3, a0)},
           "attack_total": {**ping_stats(rx, a0, a1), "victim_pps": pps(a0, a1)}}
    if mitigate and t_blk:
        out["attack_after_block"] = {**ping_stats(rx, t_blk + 1, a1), "victim_pps": pps(t_blk + 1, a1)}
    json.dump(out, open(os.path.join(res, f"demo_{tag}.json"), "w"), indent=2)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", default="syn_flood", choices=["syn_flood", "udp_flood", "icmp_flood", "all"])
    ap.add_argument("--pre", type=int, default=15)
    ap.add_argument("--post", type=int, default=8)
    ap.add_argument("--stage", type=int, default=2)
    ap.add_argument("--hold", type=int, default=25)
    a = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("Ejecuta con sudo (Mininet requiere root).")
    if not os.path.exists(os.path.join(HERE, "models", "detector.joblib")):
        sys.exit("Faltan los modelos: ejecuta primero train_models.py")
    setLogLevel("warning")
    ctrl = ensure_controller()
    attacks = ["syn_flood", "udp_flood", "icmp_flood"] if a.attack == "all" else [a.attack]
    try:
        for atk in attacks:
            print(f"\n##### {atk} #####")
            for mit in (False, True):
                r = run_one(atk, mit, a)
                print(f"\n--- mitigación {'ON ' if mit else 'OFF'} ---")
                print(json.dumps(r, indent=2))
    finally:
        if ctrl:
            ctrl.terminate()
    print("\nResultados guardados en results/demo_*.json")


if __name__ == "__main__":
    main()
