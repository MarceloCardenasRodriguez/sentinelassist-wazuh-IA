"""
Entrena el modelo de regresión que estima cuántos MINUTOS tardaría un
analista humano en revisar manualmente una alerta, si tuviera que hacerlo
sin SentinelAssist.

Este modelo no participa en la decisión de la Etapa 2 (eso lo hace el
clasificador de train_model.py); su único propósito es cuantificar, por
cada alerta resuelta, el tiempo que el sistema le está ahorrando al
analista — el mismo indicador usado para el cálculo de ROI del informe
(sección 4.4).

Ejecutar:
    python train_regression_model.py

Imprime MAE, RMSE y WMAPE sobre un conjunto de prueba (holdout 20%), y
guarda el modelo en model/estimador_tiempo_revision.joblib
"""

from __future__ import annotations

import numpy as np
from joblib import dump
from sklearn.ensemble import GradientBoostingRegressor
from sklearn.metrics import mean_absolute_error, mean_squared_error
from sklearn.model_selection import train_test_split

from config import FEATURE_COLUMNS, REGRESSION_MODEL_PATH
from synthetic_data import generar_dataset


def wmape(y_true, y_pred) -> float:
    """Error Porcentual Absoluto Medio Ponderado:
    WMAPE = sum(|y - y_hat|) / sum(|y|)."""
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    return float(np.sum(np.abs(y_true - y_pred)) / np.sum(np.abs(y_true)))


def entrenar_y_evaluar() -> GradientBoostingRegressor:
    df = generar_dataset()
    X = df[FEATURE_COLUMNS]
    y = df["tiempo_revision_minutos"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42
    )

    modelo = GradientBoostingRegressor(
        n_estimators=300,
        max_depth=3,
        learning_rate=0.05,
        min_samples_leaf=10,
        random_state=42,
    )
    modelo.fit(X_train, y_train)

    y_pred = modelo.predict(X_test)
    mae = mean_absolute_error(y_test, y_pred)
    rmse = mean_squared_error(y_test, y_pred) ** 0.5
    wmape_val = wmape(y_test, y_pred)

    print("=" * 60)
    print("EVALUACIÓN DEL MODELO — estimador_tiempo_revision")
    print("=" * 60)
    print(f"Muestras de entrenamiento: {len(X_train)} | prueba: {len(X_test)}")
    print(f"MAE (Error Absoluto Medio)              : {mae:.3f} minutos")
    print(f"RMSE (Raíz del Error Cuadrático Medio)   : {rmse:.3f} minutos")
    print(f"WMAPE (Error Porcentual Ponderado)       : {wmape_val*100:.2f}%")
    print(f"\nTiempo real promedio en el set de prueba : {y_test.mean():.2f} minutos")
    print(f"Tiempo predicho promedio                  : {y_pred.mean():.2f} minutos")

    importancias = sorted(
        zip(FEATURE_COLUMNS, modelo.feature_importances_), key=lambda t: -t[1]
    )
    print("\nImportancia de variables (top 5):")
    for nombre, imp in importancias[:5]:
        print(f"  {nombre:30s} {imp:.3f}")

    REGRESSION_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    dump({"modelo": modelo, "columnas": FEATURE_COLUMNS}, REGRESSION_MODEL_PATH)
    print(f"\nModelo guardado en: {REGRESSION_MODEL_PATH}")

    return modelo


if __name__ == "__main__":
    entrenar_y_evaluar()
