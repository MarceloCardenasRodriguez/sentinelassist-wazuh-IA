"""
Configuración del dominio para SentinelAssist.

Estos valores representan el conocimiento del analista que, en el informe,
se formalizó como predicados y axiomas de lógica de primer orden
(IPConfiable(i), Frecuente(x), TécnicaATT&CK(x,t), etc.). Aquí se traducen
a estructuras de datos concretas que el motor de reglas y el modelo de
Machine Learning consumen en tiempo de ejecución.
"""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "model" / "clasificador_falsos_positivos.joblib"
REGRESSION_MODEL_PATH = BASE_DIR / "model" / "estimador_tiempo_revision.joblib"
FEEDBACK_LOG_PATH = BASE_DIR / "data" / "feedback_log.csv"
FREQUENCY_TABLE_PATH = BASE_DIR / "data" / "frecuencia_reglas.csv"

# IPConfiable(i): lista blanca corporativa (ej. escáneres de vulnerabilidad
# internos, balanceadores de carga, IPs de monitoreo autorizado).
IP_LISTA_BLANCA = {
    "10.0.0.5",     # Scanner de vulnerabilidades interno
    "10.0.0.10",    # Servidor de monitoreo (Zabbix/Nagios)
    "192.168.1.1",  # Gateway corporativo
    "192.168.1.254",
    "172.16.0.9",   # Balanceador de carga
}

# Umbral de ocurrencias históricas para considerar Frecuente(x) = verdadero.
UMBRAL_FRECUENCIA = 30

# Categorías de rule.groups utilizadas como variable categórica del modelo.
CATEGORIAS_GRUPO = [
    "authentication_failed",
    "web",
    "firewall",
    "ids",
    "malware",
    "recon",
    "other",
]

# Palabras/patrones que, de aparecer en full_log, incrementan la probabilidad
# de que la alerta sea un verdadero positivo (heurística de contenido).
PALABRAS_CLAVE_ATAQUE = [
    "powershell -enc", "mimikatz", "wget http", "curl http", "base64 -d",
    "union select", "or 1=1", "cat /etc/passwd", "cat /etc/shadow", "nc -e",
    "invoke-expression", "certutil -urlcache", "nmap", "sqlmap", ".exe http",
    "rm -rf /",
]

# Mapeo simplificado de rule.groups -> técnica MITRE ATT&CK más probable,
# usado únicamente como enriquecimiento informativo de la respuesta.
MAPA_ATTCK = {
    "authentication_failed": "T1110 - Brute Force",
    "web": "T1190 - Exploit Public-Facing Application",
    "firewall": "T1046 - Network Service Discovery",
    "ids": "T1071 - Application Layer Protocol",
    "malware": "T1204 - User Execution",
    "recon": "T1595 - Active Scanning",
    "other": None,
}

# Umbral de severidad Wazuh (rule.level) a partir del cual se exige
# escalamiento salvo que el motor de reglas ya haya resuelto falso positivo.
UMBRAL_SEVERIDAD_ESCALAMIENTO = 12

# Zona de incertidumbre del clasificador ML que gatilla la Etapa 3 (LLM).
ZONA_GRIS_MIN = 0.35
ZONA_GRIS_MAX = 0.65

FEATURE_COLUMNS = [
    "rule_level",
    "ip_en_lista_blanca",
    "patron_frecuente",
    "contains_attack_keyword",
    "hour_of_day",
] + [f"group_{g}" for g in CATEGORIAS_GRUPO]
