"""
Entrena el clasificador de la Etapa 2 (Machine Learning clásico) que estima
la probabilidad de que una alerta de Wazuh sea un VERDADERO POSITIVO.

Ejecutar:
    python train_model.py

Imprime Precision, Recall, F1-Score y la matriz de confusión sobre un
conjunto de prueba (holdout 20%), y guarda el modelo entrenado en
model/clasificador_falsos_positivos.joblib
"""

from __future__ import annotations

from joblib import dump
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

from config import FEATURE_COLUMNS, MODEL_PATH
from synthetic_data import generar_dataset


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
