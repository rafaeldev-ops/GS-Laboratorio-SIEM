
"""
Módulo 1 — Coletor de Logs (coletor.py)
Responsável por ler e parsear os arquivos de log das três fontes,
normalizando cada linha em um dicionário padronizado.
"""
 
import os
import re
 
 
# ── Regex compiladas para performance ────────────────────────────────────────
 
# auth.log — formato real do sshd
# Ex: Jun  1 02:10:01 server sshd[1234]: Failed password for root from 185.220.101.1 port 54321 ssh2
# Ex: Jun  1 02:10:05 server sshd[1234]: Accepted password for rafael from 10.0.0.5 port 22 ssh2
_RE_AUTH_FAIL = re.compile(
    r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+Failed\s+\w+\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)"
)
_RE_AUTH_OK = re.compile(
    r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+Accepted\s+\S+\s+for\s+(\S+)\s+from\s+(\S+)"
)
 
# auth.log — sudo privilege escalation
# Ex: Jun  1 02:13:45 server sudo[1300]: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash
_RE_AUTH_SUDO = re.compile(
    r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sudo\[\d+\]:\s+(\S+)\s+:.*USER=(\S+)\s+;\s+COMMAND=(.+)"
)
 
# firewall.log — formato real do UFW
# Ex: Jun  1 02:10:00 fw kernel: [UFW BLOCK] IN=eth0 OUT= ... SRC=45.33.32.156 DST=10.0.0.1 ... PROTO=TCP DPT=22 SPT=60001
_RE_FW_BLOCK = re.compile(
    r"(\w+\s+\d+\s+\d+:\d+:\d+).*\[UFW\s+(BLOCK|ALLOW)\].*SRC=(\S+).*DST=(\S+).*PROTO=(\S+).*DPT=(\d+)"
)
 
# web_access.log — formato Apache combined log
# Ex: 185.220.101.1 - - [01/Jun/2025:02:10:00 +0000] "GET /admin/../../../etc/passwd HTTP/1.1" 403 512 "-" "Mozilla/5.0"
_RE_WEB = re.compile(
    r'(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"(\S+)\s+(.+?)\s+HTTP/[\d.]+"\s+(\d+)\s+\S+(?:\s+"[^"]*")?\s+"([^"]*)"'
)
 
 
def parsear_linha_auth(linha):
    """
    Parseia uma linha do auth.log (formato real do sshd) e retorna dict normalizado.
 
    Formatos suportados:
      Jun  1 02:10:01 server sshd[1234]: Failed password for root from 185.220.101.1 port 54321 ssh2
      Jun  1 02:10:05 server sshd[1234]: Accepted password for rafael from 10.0.0.5 port 22 ssh2
    """
    try:
        linha = linha.strip()
        if not linha:
            return None
 
        m = _RE_AUTH_FAIL.search(linha)
        if m:
            return {
                "timestamp": m.group(1),
                "fonte": "auth",
                "tipo": "FAIL",
                "ip": m.group(3),
                "detalhes": f"usuario={m.group(2)}",
                "linha_original": linha
            }
 
        m = _RE_AUTH_OK.search(linha)
        if m:
            return {
                "timestamp": m.group(1),
                "fonte": "auth",
                "tipo": "OK",
                "ip": m.group(3),
                "detalhes": f"usuario={m.group(2)}",
                "linha_original": linha
            }
 
        m = _RE_AUTH_SUDO.search(linha)
        if m:
            return {
                "timestamp": m.group(1),
                "fonte": "auth",
                "tipo": "PRIVILEGE_ESCALATION",
                "ip": "local",
                "detalhes": f"usuario={m.group(2)} elevado_para={m.group(3)} comando={m.group(4).strip()}",
                "linha_original": linha
            }
 
        return None
 
    except Exception:
        return None
 
 
def parsear_linha_firewall(linha):
    """
    Parseia uma linha do firewall.log (formato real do UFW) e retorna dict normalizado.
 
    Formato suportado:
      Jun  1 02:10:00 fw kernel: [UFW BLOCK] IN=eth0 ... SRC=45.33.32.156 DST=10.0.0.1 PROTO=TCP DPT=22 SPT=60001
    """
    try:
        linha = linha.strip()
        if not linha:
            return None
 
        m = _RE_FW_BLOCK.search(linha)
        if m:
            timestamp = m.group(1)
            acao      = m.group(2)   # BLOCK ou ALLOW
            src       = m.group(3)
            dst       = m.group(4)
            proto     = m.group(5)
            dport     = m.group(6)
 
            tipo = "BLOCK" if acao == "BLOCK" else "ALLOW"
 
            return {
                "timestamp": timestamp,
                "fonte": "firewall",
                "tipo": tipo,
                "ip": src,
                "detalhes": f"proto={proto} dst={dst} dport={dport}",
                "linha_original": linha
            }
 
        return None
 
    except Exception:
        return None
 
 
def parsear_linha_web(linha):
    """
    Parseia uma linha do web_access.log (formato Apache combined) e retorna dict normalizado.
 
    Formato suportado:
      185.220.101.1 - - [01/Jun/2025:02:10:00 +0000] "GET /admin/../../../etc/passwd HTTP/1.1" 403 512 "-" "Mozilla/5.0"
    """
    try:
        linha = linha.strip()
        if not linha:
            return None
 
        m = _RE_WEB.match(linha)
        if m:
            ip         = m.group(1)
            timestamp  = m.group(2)
            metodo     = m.group(3)
            url        = m.group(4)
            status     = m.group(5)
            user_agent = m.group(6)
 
            # Tipo baseado no status HTTP
            if status.startswith("4") or status.startswith("5"):
                tipo = "FAIL"
            elif status.startswith("2"):
                tipo = "OK"
            else:
                tipo = "REQUEST"
 
            return {
                "timestamp": timestamp,
                "fonte": "web",
                "tipo": tipo,
                "ip": ip,
                "detalhes": f"metodo={metodo} url={url} status={status}",
                "url": url,
                "status": status,
                "user_agent": user_agent,
                "linha_original": linha
            }
 
        return None
 
    except Exception:
        return None
 
 
def carregar_log(caminho_arquivo, fonte):
    """
    Lê um arquivo de log e retorna lista de eventos normalizados.
 
    Parâmetros:
        caminho_arquivo (str): caminho para o arquivo de log
        fonte (str): tipo da fonte — "auth", "firewall" ou "web"
 
    Retorna:
        list[dict]: lista de eventos normalizados
    """
    eventos = []
 
    parsers = {
        "auth":     parsear_linha_auth,
        "firewall": parsear_linha_firewall,
        "web":      parsear_linha_web
    }
 
    if fonte not in parsers:
        print(f"[AVISO] Fonte desconhecida: '{fonte}'. Use: auth, firewall ou web.")
        return eventos
 
    try:
        with open(caminho_arquivo, "r", encoding="utf-8") as f:
            linhas = f.readlines()
 
        if not linhas:
            print(f"[INFO] Arquivo vazio: {caminho_arquivo}")
            return eventos
 
        parser = parsers[fonte]
        for numero, linha in enumerate(linhas, start=1):
            linha = linha.strip()
            if not linha:
                continue
 
            evento = parser(linha)
            if evento:
                eventos.append(evento)
            else:
                print(f"[AVISO] Linha {numero} ignorada (formato inválido) em {caminho_arquivo}: '{linha}'")
 
        print(f"[OK] Carregados {len(eventos)} eventos de {caminho_arquivo}")
 
    except FileNotFoundError:
        print(f"[ERRO] Arquivo não encontrado: {caminho_arquivo}")
    except PermissionError:
        print(f"[ERRO] Sem permissão para ler: {caminho_arquivo}")
    except Exception as e:
        print(f"[ERRO] Falha inesperada ao ler {caminho_arquivo}: {e}")
 
    return eventos
 
 
def carregar_todos_os_logs(pasta_logs):
    """
    Lê todos os arquivos de log conhecidos na pasta e retorna lista unificada.
 
    Parâmetros:
        pasta_logs (str): caminho para a pasta com os arquivos de log
 
    Retorna:
        list[dict]: lista unificada de todos os eventos normalizados
    """
    todos_os_eventos = []
 
    mapa_arquivos = {
        "auth.log":       "auth",
        "firewall.log":   "firewall",
        "web_access.log": "web"
    }
 
    if not os.path.isdir(pasta_logs):
        print(f"[ERRO] Pasta de logs não encontrada: {pasta_logs}")
        return todos_os_eventos
 
    arquivos_na_pasta = os.listdir(pasta_logs)
    for nome_arquivo, fonte in mapa_arquivos.items():
        if nome_arquivo in arquivos_na_pasta:
            caminho = os.path.join(pasta_logs, nome_arquivo)
            eventos = carregar_log(caminho, fonte)
            todos_os_eventos.extend(eventos)
        else:
            print(f"[AVISO] Arquivo esperado não encontrado na pasta: {nome_arquivo}")
 
    print(f"\n[RESUMO] Total de eventos carregados: {len(todos_os_eventos)}")
    return todos_os_eventos
 
 
# ─── Testes isolados do módulo ───────────────────────────────────────────────
 
if __name__ == "__main__":
    print("=== Teste do Módulo 1 — Coletor de Logs ===\n")
 
    # Testa linhas individuais nos formatos reais
    print("--- Teste parsers com linhas reais ---")
 
    linha_auth_fail = 'Jun  1 02:10:01 server sshd[1234]: Failed password for root from 185.220.101.1 port 54321 ssh2'
    linha_auth_ok   = 'Jun  1 02:10:05 server sshd[999]: Accepted password for rafael from 10.0.0.5 port 22 ssh2'
    linha_fw        = 'Jun  1 02:10:00 fw kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=45.33.32.156 DST=10.0.0.1 PROTO=TCP DPT=22 SPT=60001'
    linha_web       = '185.220.101.1 - - [01/Jun/2025:02:10:00 +0000] "GET /admin/../../../etc/passwd HTTP/1.1" 403 512 "-" "Mozilla/5.0"'
 
    print("auth FAIL:", parsear_linha_auth(linha_auth_fail))
    print("auth OK:  ", parsear_linha_auth(linha_auth_ok))
    print("firewall: ", parsear_linha_firewall(linha_fw))
    print("web:      ", parsear_linha_web(linha_web))
 
    print("\n--- Carregar todos os logs ---")
    eventos = carregar_todos_os_logs("logs")
 
    print("\n--- Primeiros 3 eventos ---")
    for ev in eventos[:3]:
        print(ev)
 
    print("\n--- Teste com arquivo inexistente ---")
    carregar_log("logs/naoexiste.log", "auth")
 
    print("\n--- Teste com fonte inválida ---")
    carregar_log("logs/auth.log", "invalida")
