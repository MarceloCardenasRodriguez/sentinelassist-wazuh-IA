from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class AlertInput(BaseModel):
    """Entrada flexible: acepta tanto una alerta Wazuh estructurada como
    un log crudo pegado por el analista (full_log)."""

    full_log: Optional[str] = Field(
        default=None,
        description="Texto crudo del log/alerta, tal como lo copiaría el analista desde Wazuh.",
    )
    rule_id: Optional[int] = Field(default=None, description="rule.id de Wazuh")
    rule_level: Optional[int] = Field(default=None, description="rule.level (severidad) de Wazuh")
    rule_groups: Optional[list[str]] = Field(default=None, description="rule.groups de Wazuh")
    agent_name: Optional[str] = Field(default=None, description="agent.name")
    srcip: Optional[str] = Field(default=None, description="IP de origen del evento")
    timestamp: Optional[str] = Field(default=None, description="Timestamp ISO8601 del evento")

    model_config = {
        "json_schema_extra": {
            "example": {
                "full_log": "sshd: Failed password for invalid user admin from 45.13.200.10 port 51422 ssh2",
                "rule_id": 5710,
                "rule_level": 10,
                "rule_groups": ["authentication_failed", "syslog"],
                "agent_name": "web-prod-01",
                "srcip": "45.13.200.10",
                "timestamp": "2026-09-17T03:14:00",
            }
        }
    }


class AnalysisResult(BaseModel):
    veredicto: str = Field(description="'falso_positivo' | 'verdadero_positivo'")
    confianza: float = Field(description="Confianza del veredicto, entre 0 y 1")
    etapa: str = Field(description="Etapa que resolvió la alerta: 'logic' | 'ml' | 'llm'")
    requiere_escalamiento: bool
    explicacion: str
    regla_aplicada: Optional[str] = None
    tecnica_attck: Optional[str] = None
    tiempo_estimado_manual_minutos: float = Field(
        description="Minutos que un analista humano habría tardado en revisar esta alerta manualmente, "
                     "según el modelo de regresión (estimador_tiempo_revision). Es el indicador base del ROI."
    )
    caracteristicas_extraidas: dict[str, Any]


class FeedbackInput(BaseModel):
    veredicto_sistema: str
    veredicto_correcto: bool
    comentario: Optional[str] = None
    caracteristicas: dict[str, Any]
