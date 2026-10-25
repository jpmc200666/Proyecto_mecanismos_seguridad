#!/usr/bin/env python3
import os
import json
import numpy as np

def extraer_metricas():
    
    base_rtt, base_loss, base_pps = [], [], []
    off_rtt, off_loss, off_pps, off_det = [], [], [], []
    on_rtt, on_loss, on_pps, on_det, on_blk = [], [], [], [], []
    
    for i in range(1, 6):
        p_off = f"results/rep{i}/demo_syn_flood_off.json"
        p_on = f"results/rep{i}/demo_syn_flood_on.json"
        
        if os.path.exists(p_on):
            with open(p_on, 'r') as f:
                d = json.load(f)
                base_rtt.append(d['baseline'].get('rtt_avg_ms') or 0)
                base_loss.append(d['baseline'].get('loss_pct') or 0)
                base_pps.append(d['baseline'].get('victim_pps') or 0)
                
                on_rtt.append(d['attack_total'].get('rtt_avg_ms') or 0)
                on_loss.append(d['attack_total'].get('loss_pct') or 0)
                on_pps.append(d['attack_total'].get('victim_pps') or 0)
                if d.get('detection_s_after_start') is not None:
                    on_det.append(d['detection_s_after_start'])
                if d.get('block_s_after_start') is not None:
                    on_blk.append(d['block_s_after_start'])
                    
        if os.path.exists(p_off):
            with open(p_off, 'r') as f:
                d = json.load(f)
                off_rtt.append(d['attack_total'].get('rtt_avg_ms') or 0)
                off_loss.append(d['attack_total'].get('loss_pct') or 0)
                off_pps.append(d['attack_total'].get('victim_pps') or 0)
                if d.get('detection_s_after_start') is not None:
                    off_det.append(d['detection_s_after_start'])

    print("\n=======================================================")
    print("TABLA VI: VALORES PROMEDIO REALES PARA TU INFORME")
    print("=======================================================")
    print(f"Métrica                 | Línea Base | Sin Mitigac. | Tras Bloqueo")
    print(f"-------------------------------------------------------")
    print(f"RTT medio (ms)          | {np.mean(base_rtt):10.1f} | {np.mean(off_rtt):12.1f} | {np.mean(on_rtt):12.1f}")
    print(f"Pérdida de ping (%)     | {np.mean(base_loss):9.1f}% | {np.mean(off_loss):11.1f}% | {np.mean(on_loss):11.1f}%")
    print(f"Paquetes/s en víctima   | {np.mean(base_pps):10.0f} | {np.mean(off_pps):12.0f} | {np.mean(on_pps):12.0f}")
    print(f"Tiempo detección (s)    |      -     | {np.mean(off_det):12.2f} |      -")
    print(f"Tiempo bloqueo (s)      |      -     |      -       | {np.mean(on_blk):12.2f}")
    print("=======================================================\n")

if __name__ == "__main__":
    extraer_metricas()

