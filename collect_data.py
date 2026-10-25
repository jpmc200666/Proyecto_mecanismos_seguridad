#!/usr/bin/env python3

import argparse
import csv
import os
import random
import signal
import subprocess
import sys
import time

from mininet.log import setLogLevel

from common import VICTIM_IP, VICTIM_IFACE
from topology import build_net, ensure_controller, start_net, victim_iface
from traffic import (attack_duration, run_attack, start_normal_traffic,
                     start_services, stop_procs, stop_services)


def one_run(net, kind, idx, a, writer, pcap_dir):
    pcap = os.path.join(pcap_dir, f"run{idx:02d}_{kind}.pcap")
    cap = subprocess.Popen(["tshark", "-i", victim_iface(net), "-f", f"dst host {VICTIM_IP}",
                            "-n", "-q", "-F", "pcap", "-w", pcap],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    traffic = start_normal_traffic(net)
    time.sleep(a.pre)
    if kind == "normal":
        time.sleep(attack_duration(a.stage, a.hold))
        t0 = t1 = 0
    else:
        final_us = random.choice([100, 250, 500])      
        t0, t1 = run_attack(net, kind, final_us, a.stage, a.hold)
    time.sleep(a.post)
    stop_procs(traffic)
    cap.send_signal(signal.SIGINT)
    cap.wait(timeout=15)
    writer.writerow([pcap, kind, f"{t0:.3f}", f"{t1:.3f}"])
    print(f"[run {idx}] {kind:<11} -> {pcap}")
    time.sleep(3)      


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=4, help="repeticiones por escenario (mínimo 2)")
    ap.add_argument("--out", default="data")
    ap.add_argument("--pre", type=int, default=12, help="segundos de tráfico normal antes del ataque")
    ap.add_argument("--post", type=int, default=8, help="segundos de tráfico normal después")
    ap.add_argument("--stage", type=int, default=2, help="duración de cada etapa de escalada")
    ap.add_argument("--hold", type=int, default=12, help="duración de la fase sostenida del ataque")
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("Ejecuta con sudo (Mininet requiere root).")
    random.seed(a.seed)
    setLogLevel("warning")

    pcap_dir = os.path.abspath(os.path.join(a.out, "pcap"))
    os.makedirs(pcap_dir, exist_ok=True)
    ctrl = ensure_controller()
    net = build_net()
    start_net(net)
    assert victim_iface(net) == VICTIM_IFACE, "la interfaz de la víctima no es s1-eth1"
    services = start_services(net, os.path.abspath(a.out))
    time.sleep(1)

    kinds = ["normal", "syn_flood", "udp_flood", "icmp_flood"]
    order = [k for _ in range(a.reps) for k in random.sample(kinds, len(kinds))]
    try:
        with open(os.path.join(a.out, "labels.csv"), "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["pcap", "kind", "attack_start", "attack_end"])
            for i, kind in enumerate(order):
                one_run(net, kind, i, a, w, pcap_dir)
                f.flush()
    finally:
        stop_services(services)
        net.stop()
        if ctrl:
            ctrl.terminate()
    print("Recolección terminada. Siguiente paso: python3 build_dataset.py")


if __name__ == "__main__":
    main()
