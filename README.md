# SentinelAssist — Triage Automatizado de Alertas de Wazuh con Machine Learning e IA

Prototipo funcional desarrollado para la actividad evaluativa **"Diseño,
Implementación y Evaluación de una Aplicación Web con Machine Learning en un
Entorno Empresarial Real"**.

## 1. Problema que resuelve

Hoy, cuando surge una alerta ambigua en Wazuh, el analista copia el log y lo
pega manualmente en una IA conversacional externa para decidir si es un
falso positivo. Eso es lento, no queda trazabilidad, y expone información
interna a un servicio de terceros. **SentinelAssist** automatiza ese mismo
razonamiento dentro de una aplicación propia, auditable y sin fuga de datos.

## 2. Arquitectura (cascada de 3 etapas)

```
Alerta Wazuh (JSON o log crudo)
        │
        ▼
 Etapa 1 — Motor de reglas lógicas (rules_engine.py)
   Implementa los axiomas FOL del informe (IPConfiable ∧ Frecuente → FalsoPositivo)
        │  (si no resuelve)
        ▼
 Etapa 2 — Modelo de Machine Learning (RandomForestClassifier)
   Probabilidad de verdadero positivo a partir de features tabulares
        │  (si la probabilidad cae en la "zona gris" 0.35–0.65 y hay API key)
        ▼
 Etapa 3 — LLM con contexto (llm_client.py)
   Explicación en lenguaje natural + técnica MITRE ATT&CK
        │
        ▼
 Veredicto + confianza + explicación + trazabilidad (API + interfaz web)
```

Esto es exactamente lo diseñado en la sección 2.2 del informe, ahora
implementado como código ejecutable.

## 3. Estructura del proyecto

```
sentinelassist/
├── backend/
│   ├── main.py              API FastAPI (orquesta las 3 etapas)
│   ├── config.py            Lista blanca de IPs, categorías, keywords, umbrales
│   ├── rules_engine.py      Motor de reglas (axiomas lógicos ejecutables)
│   ├── feature_extraction.py Preprocesamiento de la alerta Wazuh
│   ├── synthetic_data.py    Generador de dataset sintético compartido por ambos modelos
│   ├── train_model.py       Entrena el clasificador de falsos positivos (Precision/Recall/F1)
│   ├── train_regression_model.py Entrena el estimador de tiempo de revisión (MAE/RMSE/WMAPE)
│   ├── llm_client.py        Integración opcional con la API de Anthropic (RAG simplificado)
│   ├── schemas.py           Modelos Pydantic de entrada/salida
│   ├── model/                 2 modelos entrenados (.joblib) — se generan al entrenar
│   ├── data/                 Tabla de frecuencia histórica + log de feedback
│   └── Dockerfile
├── frontend/
│   ├── app.py                Interfaz Streamlit
│   └── Dockerfile
├── tests/
│   └── test_api.py           Pruebas automatizadas (pytest) de la API
├── sample_logs/ejemplos.json Alertas de ejemplo para probar manualmente
├── docker-compose.yml
└── requirements-dev.txt
```

## 4. Cómo ejecutarlo

### Opción A — Docker Compose (recomendada)

```bash
docker compose up --build
```

- API: http://localhost:8000 (documentación interactiva en `/docs`)
- Interfaz web: http://localhost:8501

Para activar la Etapa 3 (LLM real) exporta tu clave antes de levantar los
contenedores:

```bash
export ANTHROPIC_API_KEY="tu-api-key"
docker compose up --build
```

Sin esta variable, el sistema funciona igual: simplemente resuelve todos
los casos con el motor de reglas y el modelo de Machine Learning (Etapas 1
y 2), que en la práctica cubren la gran mayoría de las alertas.

### Opción B — Entorno local (sin Docker)

```bash
# 1) Crear entorno virtual
python3 -m venv venv
source venv/bin/activate        # En Windows: venv\Scripts\activate

# 2) Backend
cd backend
pip install -r requirements.txt
python train_model.py             # entrena el clasificador e imprime Precision/Recall/F1
python train_regression_model.py  # entrena el estimador de tiempo e imprime MAE/RMSE/WMAPE
uvicorn main:app --reload --port 8000

# 3) En otra terminal: Frontend
cd frontend
pip install -r requirements.txt
streamlit run app.py
```

Luego abre http://localhost:8501 y prueba con los ejemplos de
`sample_logs/ejemplos.json` o pegando un log real de Wazuh.

### Ejecutar las pruebas automatizadas

```bash
pip install -r requirements-dev.txt
cd backend && pytest ../tests -v
```

### Probar la API directamente (sin interfaz)

```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
        "full_log": "sshd: Failed password for invalid user admin from 45.13.200.10 port 51422 ssh2",
        "rule_id": 5710,
        "rule_level": 10,
        "rule_groups": ["authentication_failed"],
        "srcip": "45.13.200.10"
      }'
```

## 5. Métricas obtenidas (dataset sintético del prototipo)

`train_model.py` genera un dataset sintético (la organización no puede
compartir logs reales del SOC por razones de confidencialidad) cuya
variable objetivo se construye a partir de las mismas reglas de negocio
descritas en el informe, más ruido aleatorio. Al ejecutarlo se obtiene,
sobre un 20% de datos de prueba (holdout):

| Métrica (clase verdadero_positivo) | Resultado obtenido |
|---|---|
| Precisión | ≈ 0.77 |
| Recall | ≈ 0.82 |
| F1-Score | ≈ 0.80 |
| Exactitud global | ≈ 0.84 |

> **Nota metodológica:** las cifras objetivo presentadas en el informe
> (Precisión 0.93 / Recall 0.89 / F1 0.91) corresponden a la meta de diseño
> una vez el modelo se reentrene con datos reales, etiquetados por analistas
> senior del SOC, tal como describe el ciclo de retroalimentación de la
> sección "Conclusión". El endpoint `/api/v1/feedback` ya está implementado
> específicamente para recolectar esas etiquetas reales en producción y
> cerrar esa brecha.

## 5bis. Modelo de regresión: tiempo de revisión manual estimado

Además del clasificador, `train_regression_model.py` entrena un
`GradientBoostingRegressor` que estima **cuántos minutos tardaría un
analista humano** en revisar manualmente cada alerta si no existiera
SentinelAssist. Este valor es el que sustenta el cálculo de horas-analista
ahorradas y el ROI del informe (sección 4.4), y se devuelve en cada
respuesta de `/api/v1/analyze` en el campo `tiempo_estimado_manual_minutos`
(también visible en la interfaz Streamlit como una métrica ⏱️).

Métricas reales obtenidas sobre el 20% de datos de prueba (holdout):

| Métrica | Resultado obtenido |
|---|---|
| MAE (Error Absoluto Medio) | ≈ 0.47 minutos |
| RMSE (Raíz del Error Cuadrático Medio) | ≈ 0.61 minutos |
| WMAPE (Error Porcentual Absoluto Medio Ponderado) | ≈ 11.2% |

Estas cifras son reproducibles ejecutando `python train_regression_model.py`
y sí corresponden a un modelo real entrenado y evaluado (no son una
proyección, a diferencia de las métricas de clasificación de la sección
anterior, que sí distinguen entre resultado actual y meta de diseño).

## 6. Componentes tecnológicos utilizados

| Componente | Herramienta |
|---|---|
| Backend / API RESTful | FastAPI + Uvicorn |
| Frontend interactivo | Streamlit |
| Machine Learning (clasificación) | Scikit-learn (RandomForestClassifier) |
| Machine Learning (regresión) | Scikit-learn (GradientBoostingRegressor) |
| IA generativa (Etapa 3, opcional) | API de Anthropic (Claude) vía `requests` |
| Contenerización | Docker / Docker Compose |
| Pruebas | Pytest + FastAPI TestClient (7 pruebas) |

## 7. Próximos pasos (fuera del alcance de este prototipo académico)

- Conector real hacia la API/Filebeat de Wazuh (actualmente se simula con
  la tabla `data/frecuencia_reglas.csv` y la lista blanca de `config.py`).
- Base vectorial real (ChromaDB/FAISS) para el RAG de la Etapa 3.
- Reentrenamiento automático a partir de `data/feedback_log.csv`.
- Despliegue en un proveedor cloud (AWS/GCP/Heroku), contemplado como
  opcional tanto en la pauta de la actividad como en el informe.
