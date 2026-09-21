"""
Generador de dataset sintético compartido por los dos modelos del proyecto:

  1) Clasificador de falsos positivos (train_model.py)
  2) Estimador de tiempo de revisión manual (train_regression_model.py)

Se centraliza aquí para que ambos modelos se entrenen sobre exactamente
las mismas alertas simuladas y sean comparables entre sí.

No se usa un dataset real del SOC por confidencialidad (ver informe y
README); la variable objetivo de cada modelo se construye a partir de
reglas de negocio conocidas más ruido aleatorio, de manera que el
problema sea aprendible pero no trivial.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from config import CATEGORIAS_GRUPO, FEATURE_COLUMNS

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

    # ---- Variable objetivo 1: clasificación (verdadero/falso positivo) ----
    prob_verdadero_positivo = np.full(n, 0.03)
    prob_verdadero_positivo += (df["rule_level"] >= 12) * 0.80
    prob_verdadero_positivo += (df["rule_level"].between(8, 11)) * 0.15
    prob_verdadero_positivo += df["contains_attack_keyword"] * 0.42
    prob_verdadero_positivo += df["rule_group"].isin(["malware", "ids", "recon"]) * 0.08
    prob_verdadero_positivo -= (df["ip_en_lista_blanca"] & df["patron_frecuente"]) * 0.75
    prob_verdadero_positivo -= df["patron_frecuente"] * 0.15
    prob_verdadero_positivo += ((df["hour_of_day"] < 6) | (df["hour_of_day"] > 22)) * 0.04

    ruido_clf = RNG.normal(0, 0.015, size=n)
    prob_final = np.clip(prob_verdadero_positivo + ruido_clf, 0.01, 0.99)
    df["es_verdadero_positivo"] = RNG.binomial(1, prob_final)

    # ---- Variable objetivo 2: minutos que tardaría un analista humano ----
    # Alertas triviales (IP confiable + patrón frecuente) se descartan casi
    # de inmediato; alertas críticas con indicadores de ataque exigen
    # investigación más profunda (revisar histórico, correlacionar, decidir).
    tiempo = np.full(n, 1.4)
    tiempo += df["rule_level"] * 0.16
    tiempo += df["contains_attack_keyword"] * 2.1
    tiempo += df["rule_group"].isin(["malware", "ids", "recon"]) * 1.1
    tiempo += df["patron_frecuente"] * 0.3
    tiempo -= (df["ip_en_lista_blanca"] & df["patron_frecuente"]) * 1.3
    tiempo += df["es_verdadero_positivo"] * 1.4  # confirmar un VP toma más tiempo que descartarlo

    ruido_reg = RNG.normal(0, 0.35, size=n)
    df["tiempo_revision_minutos"] = np.clip(tiempo + ruido_reg, 0.3, None)

    return df
