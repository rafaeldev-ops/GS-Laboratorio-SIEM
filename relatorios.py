"""
Módulo 6 — Dashboard CLI e Relatórios (relatorios.py)
Fornece o menu interativo, filtros, buscas, exibição de tabelas
e exportação de relatórios em JSON.
"""

import json
import os
from datetime import datetime


def exibir_menu():
    """
    Exibe o menu principal formatado e retorna a opção escolhida (validada).

    Retorna:
        int: número da opção selecionada pelo usuário
    """
    print("\n╔══════════════════════════════════════════╗")
    print("║         SecuraPy SIEM — Menu             ║")
    print("╠══════════════════════════════════════════╣")
    print("║  1. Carregar e processar logs            ║")
    print("║  2. Resumo geral                         ║")
    print("║  3. Filtrar eventos                      ║")
    print("║  4. Buscar IP                            ║")
    print("║  5. Top 10 IPs suspeitos                 ║")
    print("║  6. Ver alertas por severidade           ║")
    print("║  7. Enriquecer IPs suspeitos             ║")
    print("║  8. Exportar relatório JSON              ║")
    print("║  9. Iniciar servidor de alertas          ║")
    print("║  0. Sair                                 ║")
    print("╚══════════════════════════════════════════╝")

    while True:
        try:
            opcao = int(input("\nEscolha uma opção: ").strip())
            if 0 <= opcao <= 9:
                return opcao
            else:
                print("[AVISO] Opção inválida. Digite um número entre 0 e 9.")
        except ValueError:
            print("[AVISO] Entrada inválida. Digite apenas números.")


def resumo_geral(eventos, alertas):
    """
    Exibe contadores gerais: eventos por fonte e alertas por severidade.

    Parâmetros:
        eventos (list[dict]): lista de eventos normalizados
        alertas (list[dict]): lista de alertas gerados
    """
    if not eventos:
        print("[INFO] Nenhum evento carregado. Use a opção 1 primeiro.")
        return

    print("\n╔══════════════════════════════════════════╗")
    print("║            RESUMO GERAL                  ║")
    print("╚══════════════════════════════════════════╝")

    # Conta eventos por fonte
    contagem_fonte = {}
    for evento in eventos:
        fonte = evento.get("fonte", "desconhecido")
        contagem_fonte[fonte] = contagem_fonte.get(fonte, 0) + 1

    print(f"\n  📋 EVENTOS ({len(eventos)} total):")
    for fonte, qtd in sorted(contagem_fonte.items()):
        print(f"     {fonte:<12}: {qtd} eventos")

    # Conta alertas por severidade
    contagem_sev = {}
    for alerta in alertas:
        sev = alerta.get("severidade", "INFO")
        contagem_sev[sev] = contagem_sev.get(sev, 0) + 1

    print(f"\n  🚨 ALERTAS ({len(alertas)} total):")
    ordem = ["CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO"]
    icones = {"CRITICA": "🔴", "ALTA": "🟠", "MEDIA": "🟡", "BAIXA": "🟢", "INFO": "⚪"}
    for nivel in ordem:
        qtd = contagem_sev.get(nivel, 0)
        if qtd > 0:
            print(f"     {icones.get(nivel, '')} {nivel:<8}: {qtd}")


def filtrar_eventos(eventos, fonte=None, tipo=None, ip=None):
    """
    Retorna eventos filtrados pelos critérios fornecidos.
    Critérios com valor None são ignorados (sem filtro).

    Parâmetros:
        eventos (list[dict]): lista completa de eventos
        fonte (str|None): "auth", "firewall" ou "web"
        tipo (str|None): "FAIL", "BLOCK", "OK", etc.
        ip (str|None): endereço IP específico

    Retorna:
        list[dict]: eventos que atendem a todos os critérios
    """
    resultado = eventos

    if fonte:
        resultado = [e for e in resultado if e.get("fonte") == fonte.lower()]
    if tipo:
        resultado = [e for e in resultado if e.get("tipo") == tipo.upper()]
    if ip:
        resultado = [e for e in resultado if e.get("ip") == ip]

    return resultado


def buscar_ip(ip, eventos, alertas, cache_enriquecimento):
    """
    Exibe relatório completo de um IP: eventos, alertas e geolocalização.

    Parâmetros:
        ip (str): endereço IP a pesquisar
        eventos (list[dict]): lista de eventos normalizados
        alertas (list[dict]): lista de alertas
        cache_enriquecimento (dict): cache com dados de geolocalização
    """
    eventos_do_ip = [e for e in eventos if e.get("ip") == ip]
    alertas_do_ip = [a for a in alertas if a.get("ip") == ip]
    geo = cache_enriquecimento.get(ip)

    print(f"\n╔══════════════════════════════════════════╗")
    print(f"║  Relatório do IP: {ip:<23}║")
    print(f"╚══════════════════════════════════════════╝")

    # Geolocalização
    if geo:
        print("\n  🌍 GEOLOCALIZAÇÃO:")
        if geo.get("privado"):
            print("     Rede Interna (IP Privado)")
        else:
            print(f"     {geo.get('cidade', '?')}, {geo.get('regiao', '?')}, {geo.get('pais', '?')}")
            print(f"     Org: {geo.get('org', '?')}")
    else:
        print("\n  🌍 GEOLOCALIZAÇÃO: não consultada (use opção 7)")

    # Resumo de eventos
    print(f"\n  📋 EVENTOS ({len(eventos_do_ip)}):")
    if eventos_do_ip:
        for ev in eventos_do_ip[:10]:
            print(f"     [{ev.get('fonte','?')}] {ev.get('timestamp','')} — {ev.get('tipo','')} — {ev.get('detalhes','')}")
        if len(eventos_do_ip) > 10:
            print(f"     ... e mais {len(eventos_do_ip) - 10} evento(s)")
    else:
        print("     Nenhum evento encontrado para este IP.")

    # Alertas relacionados
    print(f"\n  🚨 ALERTAS ({len(alertas_do_ip)}):")
    if alertas_do_ip:
        for al in alertas_do_ip:
            print(f"     [{al.get('severidade','?')}] {al.get('regra_nome','?')} — {al.get('descricao','')}")
    else:
        print("     Nenhum alerta gerado para este IP.")


def top_ips(eventos, n=10):
    """
    Retorna os N IPs com mais eventos, com contagem e classificação.

    Parâmetros:
        eventos (list[dict]): lista de eventos normalizados
        n (int): quantidade de IPs a retornar

    Retorna:
        list[tuple]: [(ip, quantidade), ...] ordenado do maior para menor
    """
    contagem = {}
    for evento in eventos:
        ip = evento.get("ip", "desconhecido")
        contagem[ip] = contagem.get(ip, 0) + 1

    # Ordena do mais ativo para o menos ativo
    ordenados = sorted(contagem.items(), key=lambda x: x[1], reverse=True)
    return ordenados[:n]


def exibir_top_ips(eventos, alertas):
    """
    Exibe o Top 10 de IPs mais ativos com indicadores de ameaça.

    Parâmetros:
        eventos (list[dict]): lista de eventos normalizados
        alertas (list[dict]): lista de alertas
    """
    if not eventos:
        print("[INFO] Nenhum evento carregado.")
        return

    ranking = top_ips(eventos)
    ips_com_alerta = {a.get("ip") for a in alertas}

    print(f"\n{'#':<4} {'IP':<20} {'Eventos':>8}  {'Ameaça'}")
    print("-" * 50)
    for i, (ip, qtd) in enumerate(ranking, start=1):
        indicador = "🚨 SIM" if ip in ips_com_alerta else "  OK"
        print(f"{i:<4} {ip:<20} {qtd:>8}  {indicador}")


def exportar_relatorio_json(dados, pasta_saida="saida"):
    """
    Salva um relatório completo em JSON formatado em disco.

    Parâmetros:
        dados (dict): dados do relatório a exportar
        pasta_saida (str): pasta onde salvar o arquivo

    Retorna:
        str: caminho do arquivo gerado, ou None em caso de erro
    """
    try:
        os.makedirs(pasta_saida, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        nome_arquivo = f"relatorio_{timestamp}.json"
        caminho = os.path.join(pasta_saida, nome_arquivo)

        # Prepara os dados para serialização (sets não são serializáveis em JSON)
        dados_serializaveis = _preparar_para_json(dados)

        with open(caminho, "w", encoding="utf-8") as f:
            json.dump(dados_serializaveis, f, indent=2, ensure_ascii=False)

        print(f"[OK] Relatório exportado: {caminho}")
        return caminho

    except PermissionError:
        print(f"[ERRO] Sem permissão para escrever em {pasta_saida}")
        return None
    except Exception as e:
        print(f"[ERRO] Falha ao exportar relatório: {e}")
        return None


def _preparar_para_json(obj):
    """
    Converte sets e outros tipos não serializáveis para listas/strings.

    Parâmetros:
        obj: qualquer objeto Python

    Retorna:
        objeto compatível com json.dump
    """
    if isinstance(obj, set):
        return sorted(list(obj))
    elif isinstance(obj, dict):
        return {k: _preparar_para_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_preparar_para_json(item) for item in obj]
    else:
        return obj


def exibir_tabela(dados, colunas):
    """
    Exibe uma lista de dicts como tabela formatada no terminal.

    Parâmetros:
        dados (list[dict]): lista de dicionários
        colunas (list[str]): chaves a exibir como colunas
    """
    if not dados:
        print("  (nenhum dado para exibir)")
        return

    # Calcula largura de cada coluna
    larguras = {}
    for col in colunas:
        larguras[col] = max(len(col), max(len(str(linha.get(col, ""))) for linha in dados))

    # Cabeçalho
    cabecalho = "  ".join(f"{col:<{larguras[col]}}" for col in colunas)
    separador = "  ".join("-" * larguras[col] for col in colunas)
    print(cabecalho)
    print(separador)

    # Linhas
    for linha in dados:
        linha_str = "  ".join(f"{str(linha.get(col, '')):<{larguras[col]}}" for col in colunas)
        print(linha_str)
