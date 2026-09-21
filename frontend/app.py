"""
SentinelAssist — Frontend Streamlit

Interfaz web para que el analista pegue un log/alerta de Wazuh (tal como
hoy lo hace en una IA conversacional genérica) y reciba, en segundos,
un veredicto explicado, trazable y sin exponer datos a terceros.

Ejecutar:
    streamlit run app.py
"""

import json
import os

import requests
import streamlit as st

st.set_page_config(page_title="SentinelAssist", page_icon="🛡️", layout="centered")

API_URL_DEFAULT = os.environ.get("API_URL", "http://localhost:8000")

COLOR_VEREDICTO = {
    "falso_positivo": ("#1e8e3e", "🟢 FALSO POSITIVO"),
    "verdadero_positivo": ("#d93025", "🔴 VERDADERO POSITIVO"),
}
ETIQUETA_ETAPA = {
    "logic": "Motor de reglas lógicas (Etapa 1)",
    "ml": "Modelo de Machine Learning (Etapa 2)",
    "llm": "Modelo de lenguaje / LLM (Etapa 3)",
}

EJEMPLOS = {
    "-- Selecciona un ejemplo --": None,
    "Falso positivo evidente (IP interna conocida)": {
        "full_log": "syscheck: Integrity checksum changed for '/etc/passwd' by scheduled job",
        "rule_id": 5501,
        "rule_level": 7,
        "rule_groups": ["syscheck"],
        "srcip": "10.0.0.5",
        "timestamp": "2026-09-17T10:00:00",
    },
    "Fuerza bruta SSH desde IP externa": {
        "full_log": "sshd: Failed password for invalid user admin from 45.13.200.10 port 51422 ssh2",
        "rule_id": 5710,
        "rule_level": 10,
        "rule_groups": ["authentication_failed"],
        "srcip": "45.13.200.10",
        "timestamp": "2026-09-17T03:14:00",
    },
    "Alerta crítica de malware / ejecución remota": {
        "full_log": "powershell -enc JABjAGwAaQBlAG4AdAA... invoke-expression, descarga desde 203.0.113.77",
        "rule_id": 100010,
        "rule_level": 15,
        "rule_groups": ["malware"],
        "srcip": "203.0.113.77",
        "timestamp": "2026-09-17T02:40:00",
    },
}

if "alerta_texto" not in st.session_state:
    st.session_state.alerta_texto = json.dumps(EJEMPLOS["Fuerza bruta SSH desde IP externa"], indent=2, ensure_ascii=False)
if "resultado" not in st.session_state:
    st.session_state.resultado = None

st.title("🛡️ SentinelAssist")
st.caption(
    "Triage automatizado de alertas de Wazuh: reglas lógicas + Machine Learning + IA generativa, "
    "sin copiar y pegar datos sensibles en herramientas externas."
)

with st.sidebar:
    st.header("Configuración")
    api_url = st.text_input("URL de la API backend", value=API_URL_DEFAULT)
    st.markdown("---")
    try:
        estado = requests.get(f"{api_url}/api/v1/health", timeout=3).json()
        st.success("API conectada ✅")
        st.write(f"Modelo cargado: {'sí' if estado['modelo_cargado'] else 'no'}")
        st.write(f"Modelo de tiempo cargado: {'sí' if estado.get('modelo_tiempo_cargado') else 'no'}")
        st.write(f"LLM (Etapa 3) disponible: {'sí' if estado['llm_disponible'] else 'no (se usará ML como respaldo)'}")
    except requests.exceptions.RequestException:
        st.error("No se pudo conectar con la API. ¿Está corriendo `uvicorn main:app`?")
    st.markdown("---")
    st.caption("Documentación interactiva de la API: agrega `/docs` a la URL de la API en tu navegador.")

ejemplo_sel = st.selectbox("Cargar un ejemplo rápido:", list(EJEMPLOS.keys()))
if ejemplo_sel != "-- Selecciona un ejemplo --" and EJEMPLOS[ejemplo_sel]:
    st.session_state.alerta_texto = json.dumps(EJEMPLOS[ejemplo_sel], indent=2, ensure_ascii=False)

texto_alerta = st.text_area(
    "Pega aquí el log o la alerta de Wazuh (JSON estructurado o texto plano):",
    value=st.session_state.alerta_texto,
    height=220,
)

col1, col2 = st.columns([1, 1])
analizar = col1.button("🔍 Analizar alerta", type="primary", use_container_width=True)
limpiar = col2.button("🧹 Limpiar", use_container_width=True)

if limpiar:
    st.session_state.alerta_texto = ""
    st.session_state.resultado = None
    st.rerun()

if analizar:
    try:
        payload = json.loads(texto_alerta)
    except json.JSONDecodeError:
        payload = {"full_log": texto_alerta}

    try:
        with st.spinner("Analizando alerta..."):
            r = requests.post(f"{api_url}/api/v1/analyze", json=payload, timeout=30)
        if r.status_code == 200:
            st.session_state.resultado = r.json()
        else:
            st.error(f"Error de la API ({r.status_code}): {r.text}")
            st.session_state.resultado = None
    except requests.exceptions.RequestException as e:
        st.error(f"No se pudo contactar a la API: {e}")
        st.session_state.resultado = None

resultado = st.session_state.resultado
if resultado:
    color, etiqueta = COLOR_VEREDICTO.get(resultado["veredicto"], ("#666", resultado["veredicto"]))
    st.markdown(
        f"<div style='padding:16px;border-radius:10px;background-color:{color}20;"
        f"border:2px solid {color};'>"
        f"<h3 style='color:{color};margin:0;'>{etiqueta}</h3>"
        f"<p style='margin:4px 0 0 0;'>Confianza: <b>{resultado['confianza']*100:.1f}%</b> · "
        f"Resuelto por: <b>{ETIQUETA_ETAPA.get(resultado['etapa'], resultado['etapa'])}</b></p>"
        f"</div>",
        unsafe_allow_html=True,
    )

    st.progress(min(max(resultado["confianza"], 0.0), 1.0))

    if resultado["requiere_escalamiento"]:
        st.warning("⚠️ Esta alerta requiere escalamiento a un analista senior.")

    st.subheader("Explicación")
    st.write(resultado["explicacion"])

    if resultado.get("regla_aplicada"):
        st.info(f"**Regla aplicada:** {resultado['regla_aplicada']}")

    if resultado.get("tecnica_attck"):
        st.info(f"**Técnica MITRE ATT&CK asociada:** {resultado['tecnica_attck']}")

    tiempo_manual = resultado.get("tiempo_estimado_manual_minutos")
    if tiempo_manual is not None:
        st.metric(
            "⏱️ Tiempo estimado de revisión manual (sin SentinelAssist)",
            f"{tiempo_manual:.1f} min",
            help="Estimado por el modelo de regresión (estimador_tiempo_revision) a partir de alertas históricas similares.",
        )

    with st.expander("Ver características extraídas por el sistema"):
        st.json(resultado["caracteristicas_extraidas"])

    st.subheader("¿El veredicto fue correcto?")
    fb_col1, fb_col2 = st.columns(2)

    def _enviar_feedback(correcto: bool):
        try:
            requests.post(
                f"{api_url}/api/v1/feedback",
                json={
                    "veredicto_sistema": resultado["veredicto"],
                    "veredicto_correcto": correcto,
                    "caracteristicas": resultado["caracteristicas_extraidas"],
                },
                timeout=5,
            )
            st.toast("Gracias, tu retroalimentación fue registrada para el reentrenamiento del modelo.")
        except requests.exceptions.RequestException:
            st.toast("No se pudo registrar la retroalimentación (API no disponible).")

    if fb_col1.button("👍 Sí, correcto", use_container_width=True):
        _enviar_feedback(True)
    if fb_col2.button("👎 No, incorrecto", use_container_width=True):
        _enviar_feedback(False)

st.markdown("---")
st.caption(
    "SentinelAssist — Prototipo académico desarrollado para la actividad evaluativa "
    "'Diseño, Implementación y Evaluación de una Aplicación Web con Machine Learning "
    "en un Entorno Empresarial Real'."
)
