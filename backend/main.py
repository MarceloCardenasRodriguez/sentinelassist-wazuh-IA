"""
SentinelAssist API — Backend FastAPI

Expone el endpoint /api/v1/analyze que implementa la arquitectura de
decisión en cascada descrita en el informe (sección 2.2):

    Etapa 1 (reglas lógicas) -> Etapa 2 (Machine Learning) -> Etapa 3 (LLM)

Ejecutar en desarrollo:
    uvicorn main:app --reload --port 8000

Documentación interactiva autogenerada disponible en /docs (Swagger UI)
y /redoc, cumpliendo el requisito de una API "bien documentada".
"""

from __future__ import annotations

import csv
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from joblib import load

import llm_client
import rules_engine
from config import (
    FEEDBACK_LOG_PATH,
    MAPA_ATTCK,
    MODEL_PATH,
    ZONA_GRIS_MAX,
    ZONA_GRIS_MIN,
)
from feature_extraction import extraer_caracteristicas, vector_para_modelo
from schemas import AlertInput, AnalysisResult, FeedbackInput

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sentinelassist")

_modelo_bundle: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not MODEL_PATH.exists():
        raise RuntimeError(
            f"No se encontró el modelo entrenado en {MODEL_PATH}. "
            "Ejecuta 'python train_model.py' antes de iniciar la API."
        )
    bundle = load(MODEL_PATH)
    _modelo_bundle["modelo"] = bundle["modelo"]
    _modelo_bundle["columnas"] = bundle["columnas"]
    logger.info("Modelo cargado correctamente desde %s", MODEL_PATH)
    yield
    _modelo_bundle.clear()


app = FastAPI(
    title="SentinelAssist API",
    description=(
        "API de apoyo al triage de alertas de seguridad de Wazuh mediante "
        "un motor de reglas lógicas, un modelo de Machine Learning y, "
        "opcionalmente, un modelo de lenguaje (LLM) para casos ambiguos."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _construir_explicacion_ml(proba: float, features: dict) -> str:
    variables_relevantes = []
    if features["rule_level"] >= 12:
        variables_relevantes.append(f"severidad alta (rule.level={features['rule_level']})")
    if features["contains_attack_keyword"]:
        variables_relevantes.append("presencia de patrones de comando/ataque conocidos")
    if features["patron_frecuente"] and not features["ip_en_lista_blanca"]:
        variables_relevantes.append("patrón frecuente pero sin IP confiable asociada")
    detalle = "; ".join(variables_relevantes) if variables_relevantes else "combinación de variables de bajo riesgo"
    return (
        f"El modelo de Machine Learning estimó una probabilidad de "
        f"{proba:.2f} de que la alerta sea un verdadero positivo, "
        f"considerando principalmente: {detalle}."
    )


@app.get("/api/v1/health")
def health():
    return {
        "status": "ok",
        "modelo_cargado": "modelo" in _modelo_bundle,
        "llm_disponible": llm_client.llm_disponible(),
    }


@app.get("/api/v1/example", response_model=AlertInput)
def example():
    return AlertInput(**AlertInput.model_config["json_schema_extra"]["example"])


@app.post("/api/v1/analyze", response_model=AnalysisResult)
def analyze_alert(alert: AlertInput):
    if "modelo" not in _modelo_bundle:
        raise HTTPException(status_code=503, detail="El modelo aún no ha sido cargado.")

    alert_dict = alert.model_dump()
    features = extraer_caracteristicas(alert_dict)

    # ---- Etapa 1: motor de reglas lógicas ----
    resultado_reglas = rules_engine.evaluar(features)
    if resultado_reglas.veredicto is not None:
        return AnalysisResult(
            veredicto=resultado_reglas.veredicto,
            confianza=1.0,
            etapa="logic",
            requiere_escalamiento=False,
            explicacion=(
                "Alerta resuelta de forma determinística por el motor de reglas "
                "lógicas, sin necesidad de invocar al modelo de Machine Learning."
            ),
            regla_aplicada=resultado_reglas.regla_aplicada,
            tecnica_attck=None,
            caracteristicas_extraidas=features,
        )

    # ---- Etapa 2: modelo de Machine Learning ----
    import pandas as pd

    modelo = _modelo_bundle["modelo"]
    columnas = _modelo_bundle["columnas"]
    vector_df = pd.DataFrame([[features[c] for c in columnas]], columns=columnas)
    proba_verdadero = float(modelo.predict_proba(vector_df)[0][1])

    en_zona_gris = ZONA_GRIS_MIN <= proba_verdadero <= ZONA_GRIS_MAX

    # ---- Etapa 3: LLM (solo si está en zona gris y hay API key configurada) ----
    if en_zona_gris and llm_client.llm_disponible():
        resultado_llm = llm_client.analizar(alert_dict, features, proba_verdadero)
        return AnalysisResult(
            veredicto=resultado_llm.veredicto,
            confianza=resultado_llm.confianza,
            etapa="llm",
            requiere_escalamiento=resultado_reglas.requiere_escalamiento or resultado_llm.veredicto == "verdadero_positivo",
            explicacion=resultado_llm.explicacion,
            regla_aplicada=None,
            tecnica_attck=resultado_llm.tecnica_attck,
            caracteristicas_extraidas=features,
        )

    veredicto = "verdadero_positivo" if proba_verdadero >= 0.5 else "falso_positivo"
    return AnalysisResult(
        veredicto=veredicto,
        confianza=proba_verdadero if veredicto == "verdadero_positivo" else 1 - proba_verdadero,
        etapa="ml",
        requiere_escalamiento=resultado_reglas.requiere_escalamiento or veredicto == "verdadero_positivo" and features["rule_level"] >= 12,
        explicacion=_construir_explicacion_ml(proba_verdadero, features),
        regla_aplicada=None,
        tecnica_attck=MAPA_ATTCK.get(features["rule_group"]),
        caracteristicas_extraidas=features,
    )


@app.post("/api/v1/feedback")
def registrar_feedback(feedback: FeedbackInput):
    """Registra la retroalimentación del analista (correcto/incorrecto) para
    alimentar el reentrenamiento periódico del modelo (ver sección 'Conclusión'
    del informe: cierre del ciclo de retroalimentación)."""
    FEEDBACK_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    existe = FEEDBACK_LOG_PATH.exists() and FEEDBACK_LOG_PATH.stat().st_size > 0
    with open(FEEDBACK_LOG_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not existe:
            writer.writerow(["timestamp", "veredicto_sistema", "veredicto_correcto", "comentario"])
        writer.writerow([
            datetime.now(timezone.utc).isoformat(),
            feedback.veredicto_sistema,
            feedback.veredicto_correcto,
            feedback.comentario or "",
        ])
    return {"status": "registrado"}
