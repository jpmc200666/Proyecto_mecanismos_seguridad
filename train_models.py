#!/usr/bin/env python3
"""Fase 3 y 4 - Modelado y evaluación.

 1. Detección: clasifica la ventana actual (normal / syn_flood / udp_flood / icmp_flood).
 2. Pronóstico (alerta temprana): con las últimas L ventanas predice la clase H ventanas después.
 3. Pronóstico (serie de tiempo): predice los paquetes/s dentro de H ventanas.

La partición train/test es POR CORRIDAS completas para evitar fuga de información entre ventanas
contiguas.
"""
import argparse
import json
import os

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
from sklearn.metrics import (accuracy_score, confusion_matrix, mean_absolute_error,
                             mean_squared_error, precision_recall_fscore_support)
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier

from common import CLASSES, FEATURES, HISTORY, HORIZON


def split_runs(df, test_frac=0.25, seed=42):
    rng = np.random.RandomState(seed)
    test = []
    for _, g in df.groupby("kind"):
        runs = sorted(g["run"].unique())
        if len(runs) >= 2:
            test += list(rng.choice(runs, max(1, round(len(runs) * test_frac)), replace=False))
    if not test:
        raise SystemExit("Se necesitan al menos 2 corridas por escenario (usa --reps >= 2).")
    return set(test)


def metrics(y_true, y_pred):
    labels = [c for c in CLASSES if c in set(y_true)]
    p, r, f, _ = precision_recall_fscore_support(y_true, y_pred, labels=labels,
                                                 average="macro", zero_division=0)
    return {"accuracy": accuracy_score(y_true, y_pred), "precision": p, "recall": r, "f1": f}


def plot_cm(y_true, y_pred, title, path):
    labels = [c for c in CLASSES if c in set(y_true) | set(y_pred)]
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    fig, ax = plt.subplots(figsize=(5, 4.2))
    ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(len(labels)), labels, rotation=30, ha="right")
    ax.set_yticks(range(len(labels)), labels)
    for i in range(len(labels)):
        for j in range(len(labels)):
            ax.text(j, i, cm[i, j], ha="center", va="center")
    ax.set_xlabel("Predicho")
    ax.set_ylabel("Real")
    ax.set_title(title)
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


def make_sequences(df, L, H):
    X, y_now, y_fut, y_pk, runs = [], [], [], [], []
    for run, g in df.groupby("run"):
        g = g.sort_values("t")
        F, lab, pk = g[FEATURES].values, g["label"].values, g["pkts"].values
        for i in range(L - 1, len(g) - H):
            X.append(F[i - L + 1:i + 1].ravel())
            y_now.append(lab[i]); y_fut.append(lab[i + H]); y_pk.append(pk[i + H]); runs.append(run)
    return (np.array(X), np.array(y_now), np.array(y_fut), np.array(y_pk), np.array(runs))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/dataset.csv")
    ap.add_argument("--models", default="models")
    ap.add_argument("--results", default="results")
    a = ap.parse_args()
    os.makedirs(a.models, exist_ok=True)
    os.makedirs(a.results, exist_ok=True)
    df = pd.read_csv(a.data)
    test_runs = split_runs(df)
    is_test = df["run"].isin(test_runs)
    tr, te = df[~is_test], df[is_test]
    print(f"Corridas de prueba: {sorted(int(r) for r in test_runs)} | ventanas train={len(tr)} test={len(te)}")
    report = {}

    # ---------- 1. DETECCIÓN ----------
    candidates = {
        "RandomForest": RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42),
        "DecisionTree": DecisionTreeClassifier(class_weight="balanced", random_state=42),
        "SVM_RBF": make_pipeline(StandardScaler(), SVC(class_weight="balanced", random_state=42)),
    }
    report["deteccion"] = {}
    print("\n=== DETECCIÓN (ventana actual) ===")
    for name, model in candidates.items():
        model.fit(tr[FEATURES], tr["label"])
        pred = model.predict(te[FEATURES])
        m = metrics(te["label"], pred)
        report["deteccion"][name] = m
        print(f"{name:<13} " + "  ".join(f"{k}={v:.3f}" for k, v in m.items()))
    det = candidates["RandomForest"]          # modelo desplegado (da probabilidades, robusto)
    plot_cm(te["label"], det.predict(te[FEATURES]), "Detección - RandomForest",
            os.path.join(a.results, "cm_deteccion.png"))
    joblib.dump(det, os.path.join(a.models, "detector.joblib"))

    # ---------- 2 y 3. PRONÓSTICO ----------
    X, y_now, y_fut, y_pk, runs = make_sequences(df, HISTORY, HORIZON)
    mtr = ~np.isin(runs, list(test_runs))
    mte = ~mtr

    fc = RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42)
    fc.fit(X[mtr], y_fut[mtr])
    pred = fc.predict(X[mte])
    report["pronostico_clase"] = {"RandomForest": metrics(y_fut[mte], pred),
                                  "baseline_persistencia(oraculo)": metrics(y_fut[mte], y_now[mte])}
    print(f"\n=== PRONÓSTICO DE CLASE a +{HORIZON} s (alerta temprana) ===")
    for k, m in report["pronostico_clase"].items():
        print(f"{k:<32} " + "  ".join(f"{n}={v:.3f}" for n, v in m.items()))
    plot_cm(y_fut[mte], pred, f"Pronóstico +{HORIZON}s - RandomForest", os.path.join(a.results, "cm_pronostico.png"))

    reg = RandomForestRegressor(n_estimators=200, random_state=42)
    reg.fit(X[mtr], y_pk[mtr])
    p_reg = reg.predict(X[mte])
    last = X[mte][:, (HISTORY - 1) * len(FEATURES) + FEATURES.index("pkts")]
    rm = lambda t, p: float(np.sqrt(mean_squared_error(t, p)))
    report["pronostico_pkts"] = {
        "RandomForest": {"MAE": float(mean_absolute_error(y_pk[mte], p_reg)), "RMSE": rm(y_pk[mte], p_reg)},
        "baseline_persistencia": {"MAE": float(mean_absolute_error(y_pk[mte], last)), "RMSE": rm(y_pk[mte], last)}}
    print(f"\n=== PRONÓSTICO DE paquetes/s a +{HORIZON} s ===")
    for k, m in report["pronostico_pkts"].items():
        print(f"{k:<24} MAE={m['MAE']:.1f}  RMSE={m['RMSE']:.1f}")

    joblib.dump(fc, os.path.join(a.models, "forecast_cls.joblib"))
    joblib.dump(reg, os.path.join(a.models, "forecast_reg.joblib"))
    json.dump({"features": FEATURES, "history": HISTORY, "horizon": HORIZON, "classes": CLASSES},
              open(os.path.join(a.models, "config.json"), "w"), indent=2)
    json.dump(report, open(os.path.join(a.results, "metricas_modelos.json"), "w"), indent=2)
    print(f"\nModelos guardados en {a.models}/ y métricas en {a.results}/")


if __name__ == "__main__":
    main()
