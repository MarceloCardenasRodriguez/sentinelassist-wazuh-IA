"""
Preprocesamiento: convierte una alerta de Wazuh (estructurada o texto crudo)
en el vector de características tabulares que consumen el motor de reglas
y el modelo de Machine Learning.
"""

from __future__ import annotations

import csv
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from config import (
    CATEGORIAS_GRUPO,
    FEATURE_COLUMNS,
    FREQUENCY_TABLE_PATH,
    IP_LISTA_BLANCA,
    PALABRAS_CLAVE_ATAQUE,
    UMBRAL_FRECUENCIA,
)

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
LEVEL_REGEX = re.compile(r"rule\.level[\"']?\s*[:=]\s*(\d+)", re.IGNORECASE)


def _cargar_tabla_frecuencia() -> dict[str, int]:
    """Carga la tabla histórica de frecuencia por rule_id (simula el
    histórico de ocurrencias que en producción vendría de Elasticsearch/OpenSearch)."""
    tabla: dict[str, int] = {}
    if Path(FREQUENCY_TABLE_PATH).exists():
        with open(FREQUENCY_TABLE_PATH, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                tabla[str(row["rule_id"])] = int(row["ocurrencias"])
    return tabla


_TABLA_FRECUENCIA = _cargar_tabla_frecuencia()


def _detectar_ip_origen(alert: dict[str, Any]) -> str | None:
    for campo in ("srcip", "src_ip", "source_ip"):
        if alert.get(campo):
            return str(alert[campo])
    full_log = alert.get("full_log", "") or ""
    match = IP_REGEX.search(full_log)
    return match.group(0) if match else None


def _detectar_nivel(alert: dict[str, Any]) -> int:
    if alert.get("rule_level") is not None:
        try:
            return int(alert["rule_level"])
        except (TypeError, ValueError):
            pass
    full_log = alert.get("full_log", "") or ""
    match = LEVEL_REGEX.search(full_log)
    return int(match.group(1)) if match else 3  # nivel por defecto conservador


def _detectar_grupo(alert: dict[str, Any]) -> str:
    grupos = alert.get("rule_groups") or []
    if isinstance(grupos, str):
        grupos = [g.strip() for g in grupos.split(",")]
    for g in grupos:
        g_norm = str(g).lower()
        for categoria in CATEGORIAS_GRUPO:
            if categoria in g_norm:
                return categoria
    return "other"


def extraer_caracteristicas(alert: dict[str, Any]) -> dict[str, Any]:
    """Recibe la alerta (dict ya sea estructurada tipo Wazuh o con 'full_log'
    en texto libre) y retorna un diccionario con todas las variables
    utilizadas por el motor de reglas lógicas y por el modelo de ML."""

    rule_id = str(alert.get("rule_id", "0"))
    rule_level = _detectar_nivel(alert)
    ip_origen = _detectar_ip_origen(alert)
    grupo = _detectar_grupo(alert)
    full_log = (alert.get("full_log") or "").lower()

    ip_en_lista_blanca = bool(ip_origen and ip_origen in IP_LISTA_BLANCA)
    ocurrencias = _TABLA_FRECUENCIA.get(rule_id, 0)
    patron_frecuente = ocurrencias >= UMBRAL_FRECUENCIA

    contains_attack_keyword = any(kw in full_log for kw in PALABRAS_CLAVE_ATAQUE)

    timestamp = alert.get("timestamp")
    try:
        hour_of_day = (
            datetime.fromisoformat(timestamp).hour
            if timestamp
            else datetime.now(UTC).hour
        )
    except (ValueError, TypeError):
        hour_of_day = datetime.now(UTC).hour

    features: dict[str, Any] = {
        "rule_id": rule_id,
        "rule_level": rule_level,
        "ip_origen": ip_origen,
        "ip_en_lista_blanca": int(ip_en_lista_blanca),
        "patron_frecuente": int(patron_frecuente),
        "ocurrencias_historicas": ocurrencias,
        "contains_attack_keyword": int(contains_attack_keyword),
        "hour_of_day": hour_of_day,
        "rule_group": grupo,
    }
    for categoria in CATEGORIAS_GRUPO:
        features[f"group_{categoria}"] = int(grupo == categoria)

    return features


def vector_para_modelo(features: dict[str, Any]) -> list[float]:
    """Ordena las características según FEATURE_COLUMNS para alimentar al modelo."""
    return [float(features[col]) for col in FEATURE_COLUMNS]
