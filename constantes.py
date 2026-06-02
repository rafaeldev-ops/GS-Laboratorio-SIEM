"""
constantes.py — SecuraPy
========================
Fonte única de verdade para configurações e constantes compartilhadas entre módulos.

Centraliza a BLACKLIST que antes estava duplicada em main.py e detector.py,
eliminando risco de divergência entre os dois conjuntos.

Uso:
    from constantes import BLACKLIST, PASTA_LOGS, ARQUIVO_REGRAS
"""

# ---------------------------------------------------------------------------
# Caminhos padrão
# ---------------------------------------------------------------------------
PASTA_LOGS = "logs"
ARQUIVO_REGRAS = "config/regras.json"
PASTA_SAIDA = "saida"

# ---------------------------------------------------------------------------
# Blacklist de IPs maliciosos conhecidos
# ---------------------------------------------------------------------------
# 185.220.101.1 — nó de saída Tor (bloco 185.220.101.x/DE, projeto Tor)
# 45.33.32.156  — host associado a atividade de reconhecimento (Shodan: "scanme.nmap.org")
# 91.240.118.172 — host com histórico de varreduras e brute force (feeds de threat intel)
# 23.94.5.100   — host associado a atividade de spam/scanning (ARIN: AS36352)
BLACKLIST: set[str] = {
    "185.220.101.1",
    "45.33.32.156",
    "91.240.118.172",
    "23.94.5.100",
}
