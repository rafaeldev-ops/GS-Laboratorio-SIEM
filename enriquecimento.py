"""
Módulo 5 — Enriquecimento de IPs (enriquecimento.py)
Consulta a API pública do ipinfo.io para obter geolocalização
e informações de cada IP suspeito. Usa cache para evitar
chamadas repetidas à API.
"""

import requests


def eh_ip_privado(ip):
    """
    Verifica se um IP pertence a um range de rede privada (RFC 1918).
    Ranges privados: 10.x.x.x | 172.16-31.x.x | 192.168.x.x | 127.x.x.x

    Parâmetros:
        ip (str): endereço IP a verificar

    Retorna:
        bool: True se privado, False se público
    """
    try:
        partes = ip.strip().split(".")
        if len(partes) != 4:
            return False

        primeiro = int(partes[0])
        segundo = int(partes[1])

        # 10.0.0.0/8
        if primeiro == 10:
            return True
        # 172.16.0.0/12
        if primeiro == 172 and 16 <= segundo <= 31:
            return True
        # 192.168.0.0/16
        if primeiro == 192 and segundo == 168:
            return True
        # 127.0.0.0/8 (loopback)
        if primeiro == 127:
            return True

        return False

    except (ValueError, AttributeError):
        return False


def consultar_ip(ip, cache):
    """
    Consulta o ipinfo.io para obter dados de geolocalização do IP.
    Usa cache (dicionário) para evitar consultas repetidas.

    Parâmetros:
        ip (str): endereço IP a consultar
        cache (dict): dicionário usado como cache de consultas anteriores

    Retorna:
        dict: {ip, cidade, regiao, pais, org, hostname, privado}
    """
    # Verifica se IP é privado — sem consulta externa
    if eh_ip_privado(ip):
        resultado = {
            "ip": ip,
            "cidade": "N/A",
            "regiao": "N/A",
            "pais": "N/A",
            "org": "N/A",
            "hostname": "N/A",
            "privado": True,
            "descricao": "Rede Interna (IP Privado)"
        }
        cache[ip] = resultado
        return resultado

    # Verifica o cache antes de fazer a requisição
    if ip in cache:
        print(f"[CACHE] IP {ip} retornado do cache")
        return cache[ip]

    url = f"https://ipinfo.io/{ip}/json"

    try:
        resposta = requests.get(url, timeout=5)

        if resposta.status_code == 200:
            dados = resposta.json()
            resultado = {
                "ip": ip,
                "cidade": dados.get("city", "Desconhecida"),
                "regiao": dados.get("region", "Desconhecida"),
                "pais": dados.get("country", "Desconhecido"),
                "org": dados.get("org", "Desconhecida"),
                "hostname": dados.get("hostname", "N/A"),
                "privado": False,
                "descricao": f"{dados.get('city', '?')}, {dados.get('country', '?')} — {dados.get('org', '?')}"
            }
            cache[ip] = resultado
            print(f"[OK] IP {ip} enriquecido: {resultado['descricao']}")
            return resultado

        elif resposta.status_code == 429:
            print(f"[AVISO] Limite de requisições atingido na API para o IP {ip}")
            return _resultado_vazio(ip, "Limite de API atingido")

        else:
            print(f"[AVISO] API retornou status {resposta.status_code} para {ip}")
            return _resultado_vazio(ip, f"Erro HTTP {resposta.status_code}")

    except requests.exceptions.ConnectionError:
        print(f"[ERRO] Sem conexão com a internet ao consultar {ip}")
        return _resultado_vazio(ip, "Sem conexão")

    except requests.exceptions.Timeout:
        print(f"[ERRO] Timeout ao consultar {ip} — API demorou demais")
        return _resultado_vazio(ip, "Timeout na requisição")

    except requests.exceptions.RequestException as e:
        print(f"[ERRO] Falha ao consultar {ip}: {e}")
        return _resultado_vazio(ip, "Erro de requisição")


def _resultado_vazio(ip, motivo="Dados indisponíveis"):
    """
    Retorna um dict padronizado quando a consulta falha.

    Parâmetros:
        ip (str): endereço IP
        motivo (str): motivo da falha

    Retorna:
        dict: resultado vazio com motivo
    """
    return {
        "ip": ip,
        "cidade": "N/A",
        "regiao": "N/A",
        "pais": "N/A",
        "org": "N/A",
        "hostname": "N/A",
        "privado": False,
        "descricao": motivo
    }


def enriquecer_alertas(alertas, cache):
    """
    Percorre a lista de alertas e adiciona informações de geolocalização
    a cada um, pulando IPs privados e usando cache para eficiência.

    Parâmetros:
        alertas (list[dict]): lista de alertas gerados pelo motor de regras
        cache (dict): dicionário de cache (modificado in-place)

    Retorna:
        list[dict]: alertas com campo "geo" adicionado
    """
    alertas_enriquecidos = []

    for alerta in alertas:
        ip = alerta.get("ip", "")
        if ip and ip not in cache:
            info_geo = consultar_ip(ip, cache)
        elif ip:
            info_geo = cache[ip]
        else:
            info_geo = _resultado_vazio("desconhecido", "IP não disponível")

        alerta_enriquecido = dict(alerta)
        alerta_enriquecido["geo"] = info_geo
        alertas_enriquecidos.append(alerta_enriquecido)

    return alertas_enriquecidos


def exibir_enriquecimento(dados_ip):
    """
    Exibe as informações de um IP de forma formatada no terminal.

    Parâmetros:
        dados_ip (dict): resultado de consultar_ip()
    """
    ip = dados_ip.get("ip", "?")

    if dados_ip.get("privado"):
        print(f"\n  IP: {ip}")
        print(f"  Tipo: Rede Interna (privado — sem consulta externa)")
        return

    print(f"\n  IP       : {ip}")
    print(f"  Cidade   : {dados_ip.get('cidade', 'N/A')}")
    print(f"  Região   : {dados_ip.get('regiao', 'N/A')}")
    print(f"  País     : {dados_ip.get('pais', 'N/A')}")
    print(f"  Org/ISP  : {dados_ip.get('org', 'N/A')}")
    print(f"  Hostname : {dados_ip.get('hostname', 'N/A')}")


# ─── Testes isolados do módulo ───────────────────────────────────────────────
if __name__ == "__main__":
    cache_teste = {}

    print("=== Teste do Módulo 5 — Enriquecimento de IPs ===\n")

    print("--- Teste 1: IP público (8.8.8.8) ---")
    resultado = consultar_ip("8.8.8.8", cache_teste)
    exibir_enriquecimento(resultado)

    print("\n--- Teste 2: IP privado (192.168.1.10) ---")
    resultado = consultar_ip("192.168.1.10", cache_teste)
    exibir_enriquecimento(resultado)

    print("\n--- Teste 3: Segunda consulta ao 8.8.8.8 (deve usar cache) ---")
    resultado = consultar_ip("8.8.8.8", cache_teste)
    exibir_enriquecimento(resultado)

    print("\n--- Teste 4: IP suspeito do trabalho ---")
    resultado = consultar_ip("185.220.101.1", cache_teste)
    exibir_enriquecimento(resultado)

    print(f"\n--- Cache possui {len(cache_teste)} entradas ---")
