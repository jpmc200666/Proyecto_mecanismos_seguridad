#!/usr/bin/env python3

import argparse
import csv
import json
import signal
import subprocess
import time
import urllib.request
import warnings
from collections import deque

import joblib
import numpy as np

from common import CLASS_PROTO, FEATURES, VICTIM_IP, WindowAggregator, iter_records, tshark_live_cmd


def install_drop_rule(url, dpid, src, proto, timeout):
    body = {"dpid": dpid, "priority": 100, "hard_timeout": timeout,
            "match": {"eth_type": 2048, "ipv4_src": src, "ip_proto": proto}, "actions": []}
    req = urllib.request.Request(f"{url}/stats/flowentry/add", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    urllib.request.urlopen(req, timeout=2).read()


def main():
    warnings.filterwarnings("ignore", category=UserWarning)
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="s1-eth1")
    ap.add_argument("--models", default="models")
    ap.add_argument("--log", default="results/detector_log.csv")
    ap.add_argument("--mitigate", action="store_true", help="instala reglas de bloqueo")
    ap.add_argument("--controller", default="http://127.0.0.1:8080", help="API REST de Ryu")
    ap.add_argument("--dpid", type=int, default=1)
    ap.add_argument("--block-timeout", type=int, default=60, help="hard_timeout de la regla (s)")
    ap.add_argument("--confirm", type=int, default=2, help="ventanas consecutivas para confirmar")
    ap.add_argument("--early-conf", type=float, default=0.7, help="prob. mínima para alerta temprana")
    a = ap.parse_args()

    det = joblib.load(f"{a.models}/detector.joblib")
    fcls = joblib.load(f"{a.models}/forecast_cls.joblib")
    freg = joblib.load(f"{a.models}/forecast_reg.joblib")
    cfg = json.load(open(f"{a.models}/config.json"))
    L, H = cfg["history"], cfg["horizon"]

    proc = subprocess.Popen(tshark_live_cmd(a.iface), stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, bufsize=1)
    stop = lambda *_: proc.terminate()
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    logf = open(a.log, "w", newline="")
    log = csv.writer(logf)
    log.writerow(["ts", "win_start", "pkts", "bytes", "pred", "conf", "fc_class", "fc_conf", "fc_pkts", "action"])
    agg, hist, consec, blocked = WindowAggregator(), deque(maxlen=L), 0, {}
    print(f"[detector] escuchando en {a.iface} | mitigación={'ON' if a.mitigate else 'OFF'}", flush=True)

    for rec in iter_records(proc.stdout):
        for win_start, feats, top_src in agg.add(rec):
            vec = np.array([feats[f] for f in FEATURES], dtype=float)
            proba = det.predict_proba(vec.reshape(1, -1))[0]
            pred, conf = det.classes_[proba.argmax()], float(proba.max())
            hist.append(vec)
            fc_class, fc_conf, fc_pkts, actions = "", 0.0, 0.0, []
            if len(hist) == L:
                x = np.concatenate(hist).reshape(1, -1)
                fp = fcls.predict_proba(x)[0]
                fc_class, fc_conf = fcls.classes_[fp.argmax()], float(fp.max())
                fc_pkts = float(freg.predict(x)[0])
                if fc_class != "normal" and fc_conf >= a.early_conf and pred == "normal":
                    actions.append("EARLY_WARNING")
                    print(f"[ALERTA TEMPRANA] se pronostica {fc_class} en ~{H}s "
                          f"(p={fc_conf:.2f}, ~{fc_pkts:.0f} pkts/s)", flush=True)

            consec = consec + 1 if pred != "normal" else 0
            if pred != "normal":
                actions.append("DETECTED")
                print(f"[DETECCIÓN] {pred} (p={conf:.2f}) pkts={feats['pkts']:.0f} "
                      f"origen principal={top_src}", flush=True)
            if (a.mitigate and pred != "normal" and consec >= a.confirm and top_src
                    and top_src != VICTIM_IP and feats["top_src_share"] >= 0.5):
                key = (top_src, CLASS_PROTO[pred])
                if blocked.get(key, 0) < time.time():
                    try:
                        install_drop_rule(a.controller, a.dpid, top_src, CLASS_PROTO[pred], a.block_timeout)
                        blocked[key] = time.time() + a.block_timeout
                        actions.append("BLOCK")
                        print(f"[MITIGACIÓN] regla drop instalada: ip_src={top_src} proto={key[1]} "
                              f"({a.block_timeout}s)", flush=True)
                    except Exception as e:
                        print(f"[ERROR] no se pudo instalar la regla: {e}", flush=True)
            log.writerow([f"{time.time():.3f}", f"{win_start:.0f}", feats["pkts"], feats["bytes"], pred,
                          f"{conf:.3f}", fc_class, f"{fc_conf:.3f}", f"{fc_pkts:.1f}", "|".join(actions)])
            logf.flush()
    logf.close()


if __name__ == "__main__":
    main()
