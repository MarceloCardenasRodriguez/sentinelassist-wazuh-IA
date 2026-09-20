"""
Motor de reglas de la Etapa 1 (filtro determinístico).

Implementa, como código ejecutable, los axiomas de lógica de primer orden
formalizados en la sección 2.3 del informe:

  Axioma 1 (falso positivo por confianza + frecuencia):
    forall x [ Alerta(x) ^ (exists i (OrigenIP(x,i) ^ IPConfiable(i))) ^ Frecuente(x)
               -> FalsoPositivo(x) ]

  Axioma 2 (escalamiento por severidad):
    forall x [ Alerta(x) ^ Severidad(x,s) ^ (s >= 12) ^ ~FalsoPositivo(x)
               -> RequiereEscalamiento(x) ]

Si el motor de reglas resuelve la alerta (Axioma 1), el pipeline no invoca
al modelo de Machine Learning ni al LLM, ahorrando cómputo y costo.
"""

from __future__ import annotations

from dataclasses import dataclass

from config import UMBRAL_SEVERIDAD_ESCALAMIENTO


@dataclass
class ResultadoReglas:
    veredicto: str | None          # "falso_positivo" | None (None = no resuelto, sigue el pipeline)
    regla_aplicada: str | None
    requiere_escalamiento: bool


def evaluar(features: dict) -> ResultadoReglas:
    ip_confiable = bool(features["ip_en_lista_blanca"])
    frecuente = bool(features["patron_frecuente"])
    severidad = int(features["rule_level"])

    # Axioma 1: IPConfiable(i) ^ Frecuente(x) -> FalsoPositivo(x)
    if ip_confiable and frecuente:
        return ResultadoReglas(
            veredicto="falso_positivo",
            regla_aplicada=(
                "Axioma 1: origen en IPConfiable y patron Frecuente "
                "(forall x [Alerta(x) ^ IPConfiable ^ Frecuente(x) -> FalsoPositivo(x)])"
            ),
            requiere_escalamiento=False,
        )

    # Axioma 2: severidad alta y no resuelto como falso positivo -> escalar
    requiere_escalamiento = severidad >= UMBRAL_SEVERIDAD_ESCALAMIENTO

    return ResultadoReglas(
        veredicto=None,
        regla_aplicada=None,
        requiere_escalamiento=requiere_escalamiento,
    )
