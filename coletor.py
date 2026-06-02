"""
Módulo 1 — Coletor de Logs (coletor.py)
Responsável por ler e parsear os arquivos de log das três fontes,
normalizando cada linha em um dicionário padronizado.
"""

import os


def parsear_linha_auth(linha):
    """
    Parseia uma linha do auth.log e retorna dict normalizado.
    Formato esperado: TIMESTAMP TIPO usuario=NOME ip=IP
    Exemplo: 2025-02-20 08:15:01 FAIL usuario=admin ip=185.220.101.1
    """
    try:
        partes = linha.strip().split()
        if len(partes) < 5:
            return None

        timestamp = f"{partes[0]} {partes[1]}"
        tipo = partes[2]
        usuario = partes[3].split("=")[1] if "=" in partes[3] else partes[3]
        ip = partes[4].split("=")[1] if "=" in partes[4] else partes[4]

        return {
            "timestamp": timestamp,
            "fonte": "auth",
            "tipo": tipo,
            "ip": ip,
            "detalhes": f"usuario={usuario}",
            "linha_original": linha.strip()
        }
    except (IndexError, ValueError):
        return None


def parsear_linha_firewall(linha):
    """
    Parseia uma linha do firewall.log e retorna dict normalizado.
    Formato esperado: TIMESTAMP ACAO proto=PROTO src=IP dst=IP dport=PORTA
    Exemplo: 2025-02-20 08:10:02 BLOCK proto=TCP src=185.220.101.1 dst=10.0.0.1 dport=22
    """
    try:
        partes = linha.strip().split()
        if len(partes) < 7:
            return None

        timestamp = f"{partes[0]} {partes[1]}"
        tipo = partes[2]

        campos = {}
        for parte in partes[3:]:
            if "=" in parte:
                chave, valor = parte.split("=", 1)
                campos[chave] = valor

        ip = campos.get("src", "desconhecido")
        proto = campos.get("proto", "desconhecido")
        dport = campos.get("dport", "desconhecido")
        dst = campos.get("dst", "desconhecido")

        return {
            "timestamp": timestamp,
            "fonte": "firewall",
            "tipo": tipo,
            "ip": ip,
            "detalhes": f"proto={proto} dst={dst} dport={dport}",
            "linha_original": linha.strip()
        }
    except (IndexError, ValueError):
        return None


def parsear_linha_web(linha):
    """
    Parseia uma linha do web_access.log e retorna dict normalizado.
    Formato esperado: TIMESTAMP METODO url=URL ip=IP status=CODIGO
    Exemplo: 2025-02-20 08:20:01 GET url=/index.html ip=192.168.1.10 status=200
    """
    try:
        partes = linha.strip().split()
        if len(partes) < 6:
            return None

        timestamp = f"{partes[0]} {partes[1]}"
        metodo = partes[2]

        campos = {}
        for parte in partes[3:]:
            if "=" in parte:
                chave, valor = parte.split("=", 1)
                campos[chave] = valor

        url = campos.get("url", "desconhecido")
        ip = campos.get("ip", "desconhecido")
        status = campos.get("status", "desconhecido")

        # Determina o tipo com base no status HTTP
        if status and status.startswith("4"):
            tipo = "FAIL"
        elif status and status.startswith("2"):
            tipo = "OK"
        else:
            tipo = "REQUEST"

        return {
            "timestamp": timestamp,
            "fonte": "web",
            "tipo": tipo,
            "ip": ip,
            "detalhes": f"metodo={metodo} url={url} status={status}",
            "linha_original": linha.strip()
        }
    except (IndexError, ValueError):
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

    # Mapeia fonte para função de parse correspondente
    parsers = {
        "auth": parsear_linha_auth,
        "firewall": parsear_linha_firewall,
        "web": parsear_linha_web
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
                continue  # ignora linhas em branco

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

    # Mapeamento: nome do arquivo → fonte
    mapa_arquivos = {
        "auth.log": "auth",
        "firewall.log": "firewall",
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

    eventos = carregar_todos_os_logs("logs")

    print("\n--- Primeiros 3 eventos ---")
    for ev in eventos[:3]:
        print(ev)

    print("\n--- Teste com arquivo inexistente ---")
    carregar_log("logs/naoexiste.log", "auth")

    print("\n--- Teste com fonte inválida ---")
    carregar_log("logs/auth.log", "invalida")
