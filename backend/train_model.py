"""
Entrena el clasificador de la Etapa 2 (Machine Learning clásico) que estima
la probabilidad de que una alerta de Wazuh sea un VERDADERO POSITIVO.

Como no se dispone (en este prototipo académico) de un dataset real
etiquetado por el SOC, se genera un dataset sintético cuya variable objetivo
se construye a partir de reglas de negocio conocidas + ruido aleatorio,
de manera que el problema sea realista y aprendible, pero no trivial.

Ejecutar:
    python train_model.py

Imprime Precision, Recall, F1-Score y la matriz de confusión sobre un
conjunto de prueba (holdout 20%), y guarda el modelo entrenado en
model/clasificador_falsos_positivos.joblib
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from joblib import dump
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

from config import CATEGORIAS_GRUPO, FEATURE_COLUMNS, MODEL_PATH

RNG = np.random.default_rng(42)
N_MUESTRAS = 4000


def generar_dataset(n: int = N_MUESTRAS) -> pd.DataFrame:
    rule_level = RNG.integers(1, 16, size=n)
    ip_en_lista_blanca = RNG.choice([0, 1], size=n, p=[0.85, 0.15])
    patron_frecuente = RNG.choice([0, 1], size=n, p=[0.7, 0.3])
    contains_attack_keyword = RNG.choice([0, 1], size=n, p=[0.75, 0.25])
    hour_of_day = RNG.integers(0, 24, size=n)
    grupo = RNG.choice(CATEGORIAS_GRUPO, size=n, p=[0.20, 0.20, 0.15, 0.15, 0.15, 0.10, 0.05])

    df = pd.DataFrame({
        "rule_level": rule_level,
        "ip_en_lista_blanca": ip_en_lista_blanca,
        "patron_frecuente": patron_frecuente,
        "contains_attack_keyword": contains_attack_keyword,
        "hour_of_day": hour_of_day,
        "rule_group": grupo,
    })
    for categoria in CATEGORIAS_GRUPO:
        df[f"group_{categoria}"] = (df["rule_group"] == categoria).astype(int)

    # --- Construcción de la variable objetivo con reglas de negocio + ruido ---
    prob_verdadero_positivo = np.full(n, 0.03)
    prob_verdadero_positivo += (df["rule_level"] >= 12) * 0.80
    prob_verdadero_positivo += (df["rule_level"].between(8, 11)) * 0.15
    prob_verdadero_positivo += df["contains_attack_keyword"] * 0.42
    prob_verdadero_positivo += df["rule_group"].isin(["malware", "ids", "recon"]) * 0.08
    prob_verdadero_positivo -= (df["ip_en_lista_blanca"] & df["patron_frecuente"]) * 0.75
    prob_verdadero_positivo -= df["patron_frecuente"] * 0.15
    # Horario fuera de oficina incrementa levemente la sospecha
    prob_verdadero_positivo += ((df["hour_of_day"] < 6) | (df["hour_of_day"] > 22)) * 0.04

    ruido = RNG.normal(0, 0.015, size=n)
    prob_final = np.clip(prob_verdadero_positivo + ruido, 0.01, 0.99)
    df["es_verdadero_positivo"] = RNG.binomial(1, prob_final)

    return df


def entrenar_y_evaluar() -> RandomForestClassifier:
    df = generar_dataset()
    X = df[FEATURE_COLUMNS]
    y = df["es_verdadero_positivo"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    modelo = RandomForestClassifier(
        n_estimators=300,
        max_depth=8,
        min_samples_leaf=5,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    modelo.fit(X_train, y_train)

    y_pred = modelo.predict(X_test)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    matriz = confusion_matrix(y_test, y_pred)

    print("=" * 60)
    print("EVALUACIÓN DEL MODELO — clasificador_falsos_positivos")
    print("=" * 60)
    print(f"Muestras de entrenamiento: {len(X_train)} | prueba: {len(X_test)}")
    print(f"Precisión (Precision) : {precision:.3f}")
    print(f"Recall               : {recall:.3f}")
    print(f"F1-Score             : {f1:.3f}")
    print("\nMatriz de confusión [ [VN, FP], [FN, VP] ]:")
    print(matriz)
    print("\nReporte completo:")
    print(classification_report(y_test, y_pred, target_names=["falso_positivo", "verdadero_positivo"]))

    importancias = sorted(
        zip(FEATURE_COLUMNS, modelo.feature_importances_), key=lambda t: -t[1]
    )
    print("Importancia de variables (top 5):")
    for nombre, imp in importancias[:5]:
        print(f"  {nombre:30s} {imp:.3f}")

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    dump({"modelo": modelo, "columnas": FEATURE_COLUMNS}, MODEL_PATH)
    print(f"\nModelo guardado en: {MODEL_PATH}")

    return modelo


if __name__ == "__main__":
    entrenar_y_evaluar()
