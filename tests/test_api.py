"""
Pruebas de la API de SentinelAssist.

Ejecutar desde la carpeta backend/ (o con PYTHONPATH=backend):
    pytest ../tests -v
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402


def test_health():
    with TestClient(app) as client:
        r = client.get("/api/v1/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert body["modelo_cargado"] is True


def test_analyze_resuelto_por_reglas_falso_positivo():
    """IP en lista blanca + patrón frecuente -> debe resolverse por el motor
    de reglas (Etapa 1), sin pasar por el modelo de ML."""
    payload = {
        "full_log": "Integrity checksum changed for '/etc/passwd'",
        "rule_id": 5501,          # tiene 120 ocurrencias históricas en la tabla de frecuencia (>= umbral 30)
        "rule_level": 7,
        "rule_groups": ["syscheck"],
        "srcip": "10.0.0.5",      # IP en lista blanca
    }
    with TestClient(app) as client:
        r = client.post("/api/v1/analyze", json=payload)
        assert r.status_code == 200
        body = r.json()
        assert body["veredicto"] == "falso_positivo"
        assert body["etapa"] == "logic"
        assert body["confianza"] == 1.0
        assert body["regla_aplicada"] is not None


def test_analyze_alta_severidad_resuelto_por_ml():
    """Severidad alta y sin IP confiable -> debe pasar por Etapa 2 (ML) y
    marcar requiere_escalamiento."""
    payload = {
        "full_log": "powershell -enc JAB... invoke-expression download attacker.exe",
        "rule_id": 100010,
        "rule_level": 15,
        "rule_groups": ["malware"],
        "srcip": "203.0.113.77",
    }
    with TestClient(app) as client:
        r = client.post("/api/v1/analyze", json=payload)
        assert r.status_code == 200
        body = r.json()
        assert body["etapa"] in ("ml", "llm")
        assert body["veredicto"] in ("falso_positivo", "verdadero_positivo")
        assert 0.0 <= body["confianza"] <= 1.0


def test_analyze_log_crudo_sin_campos_estructurados():
    """La API debe funcionar aunque sólo se pegue el log crudo, replicando
    el flujo actual del analista (copiar y pegar el texto)."""
    payload = {
        "full_log": "sshd[2211]: Failed password for invalid user test from 45.13.200.10 port 51422 ssh2 rule.level:10"
    }
    with TestClient(app) as client:
        r = client.post("/api/v1/analyze", json=payload)
        assert r.status_code == 200
        body = r.json()
        assert body["caracteristicas_extraidas"]["rule_level"] == 10
        assert body["caracteristicas_extraidas"]["ip_origen"] == "45.13.200.10"


def test_example_endpoint():
    with TestClient(app) as client:
        r = client.get("/api/v1/example")
        assert r.status_code == 200
        assert "full_log" in r.json()


def test_feedback_endpoint():
    payload = {
        "veredicto_sistema": "falso_positivo",
        "veredicto_correcto": True,
        "comentario": "Confirmado por analista de turno.",
        "caracteristicas": {"rule_level": 7},
    }
    with TestClient(app) as client:
        r = client.post("/api/v1/feedback", json=payload)
        assert r.status_code == 200
        assert r.json()["status"] == "registrado"
