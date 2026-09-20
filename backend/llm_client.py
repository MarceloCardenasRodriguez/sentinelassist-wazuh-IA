"""
Etapa 3 — Razonamiento contextual mediante LLM (opcional).

Se invoca únicamente cuando la Etapa 2 (Machine Learning) entrega una
probabilidad en la "zona gris" (ver config.ZONA_GRIS_MIN/MAX). Si no hay
una API key configurada, el pipeline degrada de forma segura y resuelve
con el resultado del modelo de ML, dejando registrado que el LLM no
estuvo disponible en esa consulta.

La llamada se realiza siempre desde el backend (nunca desde el navegador
del analista), por lo que la clave nunca se expone al cliente.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

import requests

from config import MAPA_ATTCK

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6")
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"


@dataclass
class ResultadoLLM:
    veredicto: str          # "falso_positivo" | "verdadero_positivo"
    confianza: float
    explicacion: str
    tecnica_attck: str | None


def llm_disponible() -> bool:
    return bool(ANTHROPIC_API_KEY)


def _construir_contexto(features: dict) -> str:
    """Recuperación de contexto (RAG simplificado): en producción esto
    consulta una base vectorial con documentación de reglas Wazuh e
    incidentes históricos; aquí se arma un contexto determinístico
    equivalente para el prototipo."""
    tecnica = MAPA_ATTCK.get(features["rule_group"])
    contexto = [
        f"Nivel de severidad Wazuh (rule.level): {features['rule_level']}.",
        f"Grupo de regla: {features['rule_group']}.",
        f"IP de origen en lista blanca corporativa: {'sí' if features['ip_en_lista_blanca'] else 'no'}.",
        f"Patrón con alta frecuencia histórica sin incidentes: {'sí' if features['patron_frecuente'] else 'no'}.",
        f"Contiene palabras clave de ataque conocidas: {'sí' if features['contains_attack_keyword'] else 'no'}.",
    ]
    if tecnica:
        contexto.append(f"Técnica MITRE ATT&CK asociada al grupo de regla: {tecnica}.")
    return "\n".join(contexto)


def analizar(alert_raw: dict, features: dict, proba_ml: float) -> ResultadoLLM | None:
    if not llm_disponible():
        return None

    contexto = _construir_contexto(features)
    prompt = (
        "Eres un analista senior de un SOC revisando una alerta de Wazuh. "
        "Con el siguiente contexto, determina si es un FALSO_POSITIVO o un "
        "VERDADERO_POSITIVO, entrega una confianza entre 0 y 1 y una explicación breve.\n\n"
        f"Contexto:\n{contexto}\n\n"
        f"Probabilidad estimada por el modelo de Machine Learning (verdadero positivo): {proba_ml:.2f}\n\n"
        f"Log original:\n{alert_raw.get('full_log', '(sin log crudo)')}\n\n"
        "Responde ÚNICAMENTE con un JSON con las claves: veredicto "
        "('falso_positivo' o 'verdadero_positivo'), confianza (float 0-1), explicacion (string)."
    )

    try:
        response = requests.post(
            ANTHROPIC_URL,
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": ANTHROPIC_MODEL,
                "max_tokens": 400,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()
        texto = "".join(block.get("text", "") for block in data.get("content", []))
        texto_limpio = texto.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        payload = json.loads(texto_limpio)

        return ResultadoLLM(
            veredicto=payload["veredicto"],
            confianza=float(payload["confianza"]),
            explicacion=payload["explicacion"],
            tecnica_attck=MAPA_ATTCK.get(features["rule_group"]),
        )
    except Exception as exc:  # noqa: BLE001 - degradar de forma segura ante cualquier falla de red/parseo
        return ResultadoLLM(
            veredicto="verdadero_positivo" if proba_ml >= 0.5 else "falso_positivo",
            confianza=proba_ml,
            explicacion=(
                "No se pudo obtener una respuesta válida del modelo de lenguaje "
                f"({exc.__class__.__name__}); se utilizó el resultado del modelo de "
                "Machine Learning como respaldo."
            ),
            tecnica_attck=MAPA_ATTCK.get(features["rule_group"]),
        )
