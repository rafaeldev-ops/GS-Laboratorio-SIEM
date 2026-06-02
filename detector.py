"""
Módulo 3 — Detector de Anomalias (detector.py)
Analisa o conjunto completo de eventos para identificar padrões
de ataque que só ficam visíveis ao correlacionar múltiplos eventos:
brute force, port scan e IPs em blacklist.
"""


def detectar_brute_force(eventos, threshold=5):
    """
    Conta tentativas de login FAIL por IP nos eventos de autenticação.
    Severidade escala com a quantidade de tentativas.

    Parâmetros:
        eventos (list[dict]): lista de eventos normalizados
        threshold (int): número mínimo de falhas para considerar brute force

    Retorna:
        dict: {ip: {"tentativas": N, "usuarios": [...], "severidade": "..."}}
    """
    contagem_por_ip = {}

    for evento in eventos:
        if evento.get("fonte") != "auth":
            continue
        if evento.get("tipo") != "FAIL":
            continue

        ip = evento.get("ip", "desconhecido")
        detalhes = evento.get("detalhes", "")

        # Extrai o nome do usuário
        usuario = "desconhecido"
        if "usuario=" in detalhes:
            usuario = detalhes.split("usuario=")[1].split()[0]

        if ip not in contagem_por_ip:
            contagem_por_ip[ip] = {"tentativas": 0, "usuarios": set()}

        contagem_por_ip[ip]["tentativas"] += 1
        contagem_por_ip[ip]["usuarios"].add(usuario)

    # Filtra pelos IPs que ultrapassaram o threshold e define severidade
    resultado = {}
    for ip, dados in contagem_por_ip.items():
        n = dados["tentativas"]
        if n >= threshold:
            if n > 20:
                severidade = "CRITICA"
            elif n > 10:
                severidade = "ALTA"
            elif n > 5:
                severidade = "MEDIA"
            else:
                severidade = "BAIXA"

            resultado[ip] = {
                "tentativas": n,
                "usuarios": list(dados["usuarios"]),
                "severidade": severidade
            }

    if resultado:
        print(f"[DETECTOR] Brute Force: {len(resultado)} IP(s) suspeito(s) detectado(s)")
    else:
        print("[DETECTOR] Brute Force: nenhum IP suspeito encontrado")

    return resultado


def detectar_port_scan(eventos, threshold=3):
    """
    Conta portas únicas bloqueadas por IP nos eventos de firewall.
    Usa set para garantir que cada porta só conta uma vez por IP.

    Parâmetros:
        eventos (list[dict]): lista de eventos normalizados
        threshold (int): número mínimo de portas distintas para considerar port scan

    Retorna:
        dict: {ip: {"portas": set(...), "quantidade": N, "severidade": "..."}}
    """
    portas_por_ip = {}

    for evento in eventos:
        if evento.get("fonte") != "firewall":
            continue
        if evento.get("tipo") != "BLOCK":
            continue

        ip = evento.get("ip", "desconhecido")
        detalhes = evento.get("detalhes", "")

        porta = None
        if "dport=" in detalhes:
            try:
                porta = int(detalhes.split("dport=")[1].split()[0])
            except (ValueError, IndexError):
                porta = None

        if porta is None:
            continue

        if ip not in portas_por_ip:
            portas_por_ip[ip] = set()

        portas_por_ip[ip].add(porta)

    # Filtra pelos IPs que escanearam portas suficientes
    resultado = {}
    for ip, portas in portas_por_ip.items():
        quantidade = len(portas)
        if quantidade >= threshold:
            if quantidade >= 7:
                severidade = "ALTA"
            elif quantidade >= 5:
                severidade = "MEDIA"
            else:
                severidade = "BAIXA"

            resultado[ip] = {
                "portas": portas,
                "quantidade": quantidade,
                "severidade": severidade
            }

    if resultado:
        print(f"[DETECTOR] Port Scan: {len(resultado)} IP(s) suspeito(s) detectado(s)")
    else:
        print("[DETECTOR] Port Scan: nenhum IP suspeito encontrado")

    return resultado


def verificar_blacklist(eventos, blacklist):
    """
    Cruza IPs dos eventos com uma blacklist usando operações de set.

    Parâmetros:
        eventos (list[dict]): lista de eventos normalizados
        blacklist (set): conjunto de IPs maliciosos conhecidos

    Retorna:
        tuple: (set de IPs encontrados, dict com contagem por IP)
    """
    # Coleta todos os IPs que aparecem nos eventos
    ips_dos_eventos = {evento.get("ip") for evento in eventos if evento.get("ip")}

    # Interseção: IPs que estão nos eventos E na blacklist
    ips_maliciosos = ips_dos_eventos & blacklist

    # Conta quantos eventos cada IP malicioso gerou
    contagem = {}
    for ip in ips_maliciosos:
        contagem[ip] = sum(1 for evento in eventos if evento.get("ip") == ip)

    if ips_maliciosos:
        print(f"[DETECTOR] Blacklist: {len(ips_maliciosos)} IP(s) malicioso(s) nos logs")
    else:
        print("[DETECTOR] Blacklist: nenhum IP da blacklist encontrado nos logs")

    return ips_maliciosos, contagem


def gerar_resumo_ameacas(brute_force, port_scan, ips_blacklist):
    """
    Consolida todas as detecções em um resumo unificado.
    IPs que aparecem em múltiplas detecções têm severidade aumentada.

    Parâmetros:
        brute_force (dict): resultado de detectar_brute_force()
        port_scan (dict): resultado de detectar_port_scan()
        ips_blacklist (set): conjunto de IPs da blacklist encontrados

    Retorna:
        list[dict]: lista de ameaças ordenada por pontuação (mais graves primeiro)
    """
    # Mapa de severidade para pontuação numérica (para ordenação)
    peso_severidade = {"CRITICA": 4, "ALTA": 3, "MEDIA": 2, "BAIXA": 1, "INFO": 0}

    todos_os_ips = set(brute_force.keys()) | set(port_scan.keys()) | ips_blacklist

    resumo = []

    for ip in todos_os_ips:
        motivos = []
        pontuacao_total = 0

        if ip in brute_force:
            dados = brute_force[ip]
            motivos.append(f"Brute Force ({dados['tentativas']} tentativas)")
            pontuacao_total += peso_severidade.get(dados["severidade"], 0)

        if ip in port_scan:
            dados = port_scan[ip]
            portas_str = ",".join(str(p) for p in sorted(dados["portas"]))
            motivos.append(f"Port Scan ({dados['quantidade']} portas: {portas_str})")
            pontuacao_total += peso_severidade.get(dados["severidade"], 0)

        if ip in ips_blacklist:
            motivos.append("IP em Blacklist")
            pontuacao_total += 3  # peso fixo para blacklist

        # Recalcula severidade consolidada com base na pontuação total
        if pontuacao_total >= 8:
            severidade_final = "CRITICA"
        elif pontuacao_total >= 5:
            severidade_final = "ALTA"
        elif pontuacao_total >= 3:
            severidade_final = "MEDIA"
        elif pontuacao_total >= 1:
            severidade_final = "BAIXA"
        else:
            severidade_final = "INFO"

        resumo.append({
            "ip": ip,
            "motivos": motivos,
            "pontuacao": pontuacao_total,
            "severidade": severidade_final
        })

    # Ordena do mais grave para o menos grave
    resumo.sort(key=lambda x: x["pontuacao"], reverse=True)

    print(f"[DETECTOR] Resumo: {len(resumo)} IP(s) ameaçador(es) identificado(s)")
    return resumo


# ─── Testes isolados do módulo ───────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")
    from coletor import carregar_todos_os_logs

    BLACKLIST = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}

    print("=== Teste do Módulo 3 — Detector de Anomalias ===\n")

    eventos = carregar_todos_os_logs("logs")

    print("\n--- Brute Force ---")
    bf = detectar_brute_force(eventos)
    for ip, dados in bf.items():
        print(f"  {ip}: {dados['tentativas']} tentativas — {dados['severidade']}")

    print("\n--- Port Scan ---")
    ps = detectar_port_scan(eventos)
    for ip, dados in ps.items():
        print(f"  {ip}: {dados['quantidade']} portas — {dados['severidade']}")

    print("\n--- Blacklist ---")
    ips_bl, contagem_bl = verificar_blacklist(eventos, BLACKLIST)
    for ip in ips_bl:
        print(f"  {ip}: {contagem_bl[ip]} evento(s) nos logs")

    print("\n--- Resumo Consolidado ---")
    resumo = gerar_resumo_ameacas(bf, ps, ips_bl)
    for ameaca in resumo:
        print(f"  [{ameaca['severidade']}] {ameaca['ip']} — {'; '.join(ameaca['motivos'])}")
