"""
SecuraPy — SIEM Simplificado
main.py — Ponto de entrada que integra todos os módulos do sistema.

Disciplina: Coding for Security
"""

import threading

from coletor import carregar_todos_os_logs
from regras import carregar_regras, aplicar_regras
from detector import (
    detectar_brute_force,
    detectar_port_scan,
    verificar_blacklist,
    gerar_resumo_ameacas
)
from enriquecimento import consultar_ip, enriquecer_alertas, exibir_enriquecimento
from relatorios import (
    exibir_menu,
    resumo_geral,
    filtrar_eventos,
    buscar_ip,
    exibir_top_ips,
    exportar_relatorio_json,
    exibir_tabela
)
from servidor_alertas import iniciar_servidor, broadcast_alerta

# ── Configurações globais ─────────────────────────────────────────────────────
PASTA_LOGS = "logs"
ARQUIVO_REGRAS = "config/regras.json"
BLACKLIST = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}


def main():
    """
    Função principal que controla o fluxo do programa via menu interativo.
    """
    print("\n╔══════════════════════════════════════════╗")
    print("║     Bem-vindo ao SecuraPy SIEM v1.0      ║")
    print("║     Sistema de Detecção de Ameaças       ║")
    print("╚══════════════════════════════════════════╝")

    # ── Estado da sessão ──────────────────────────────────────────────────────
    eventos = []
    alertas = []
    resumo_ameacas = []
    cache_enriquecimento = {}
    regras = []
    servidor_ativo = False

    while True:
        opcao = exibir_menu()

        # ── Opção 1: Carregar e processar logs ────────────────────────────────
        if opcao == 1:
            print("\n[INFO] Carregando e processando logs...\n")

            # 1. Carrega os eventos dos três arquivos de log
            eventos = carregar_todos_os_logs(PASTA_LOGS)

            if not eventos:
                print("[AVISO] Nenhum evento foi carregado. Verifique a pasta 'logs/'.")
                continue

            # 2. Carrega as regras do arquivo JSON
            regras = carregar_regras(ARQUIVO_REGRAS)

            # 3. Aplica as regras a todos os eventos
            alertas = aplicar_regras(eventos, regras)

            # 4. Detecta anomalias: brute force, port scan, blacklist
            print("\n[INFO] Executando detecção de anomalias...")
            brute_force = detectar_brute_force(eventos)
            port_scan = detectar_port_scan(eventos)
            ips_blacklist, _ = verificar_blacklist(eventos, BLACKLIST)

            # 5. Gera resumo consolidado de ameaças
            resumo_ameacas = gerar_resumo_ameacas(brute_force, port_scan, ips_blacklist)

            print("\n✅ Processamento concluído!")
            print(f"   {len(eventos)} eventos | {len(alertas)} alertas | {len(resumo_ameacas)} IPs suspeitos")

        # ── Opção 2: Resumo geral ─────────────────────────────────────────────
        elif opcao == 2:
            if not eventos:
                print("\n[AVISO] Carregue os logs primeiro (opção 1).")
                continue
            resumo_geral(eventos, alertas)

        # ── Opção 3: Filtrar eventos ──────────────────────────────────────────
        elif opcao == 3:
            if not eventos:
                print("\n[AVISO] Carregue os logs primeiro (opção 1).")
                continue

            print("\n--- Filtrar Eventos ---")
            print("Deixe em branco para ignorar o filtro.\n")

            fonte_input = input("Fonte (auth / firewall / web): ").strip() or None
            tipo_input = input("Tipo (FAIL / BLOCK / OK / REQUEST): ").strip() or None
            ip_input = input("IP (ex: 185.220.101.1): ").strip() or None

            resultado = filtrar_eventos(eventos, fonte=fonte_input, tipo=tipo_input, ip=ip_input)

            print(f"\n{len(resultado)} evento(s) encontrado(s):\n")
            if resultado:
                colunas = ["timestamp", "fonte", "tipo", "ip", "detalhes"]
                exibir_tabela(resultado[:20], colunas)
                if len(resultado) > 20:
                    print(f"\n... e mais {len(resultado) - 20} eventos.")

        # ── Opção 4: Buscar IP ────────────────────────────────────────────────
        elif opcao == 4:
            if not eventos:
                print("\n[AVISO] Carregue os logs primeiro (opção 1).")
                continue

            ip_busca = input("\nDigite o IP a buscar: ").strip()
            if not ip_busca:
                print("[AVISO] IP inválido.")
                continue

            buscar_ip(ip_busca, eventos, alertas, cache_enriquecimento)

        # ── Opção 5: Top 10 IPs suspeitos ─────────────────────────────────────
        elif opcao == 5:
            if not eventos:
                print("\n[AVISO] Carregue os logs primeiro (opção 1).")
                continue
            print("\n  🏆 TOP 10 IPs MAIS ATIVOS")
            exibir_top_ips(eventos, alertas)

        # ── Opção 6: Ver alertas por severidade ───────────────────────────────
        elif opcao == 6:
            if not alertas:
                print("\n[AVISO] Carregue os logs primeiro (opção 1).")
                continue

            print("\n--- Alertas por Severidade ---")
            ordem = ["CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO"]

            for nivel in ordem:
                alertas_nivel = [a for a in alertas if a.get("severidade") == nivel]
                if not alertas_nivel:
                    continue

                print(f"\n  [{nivel}] — {len(alertas_nivel)} alerta(s)")
                for al in alertas_nivel[:5]:
                    print(f"    {al.get('timestamp','')} | {al.get('regra_nome','')} | IP: {al.get('ip','')}")
                if len(alertas_nivel) > 5:
                    print(f"    ... e mais {len(alertas_nivel) - 5} alerta(s)")

        # ── Opção 7: Enriquecer IPs suspeitos ─────────────────────────────────
        elif opcao == 7:
            if not resumo_ameacas:
                print("\n[AVISO] Carregue os logs primeiro (opção 1).")
                continue

            print("\n[INFO] Consultando ipinfo.io para cada IP suspeito...")
            print("[INFO] IPs privados não serão consultados na internet.\n")

            ips_suspeitos = list({a.get("ip") for a in alertas if a.get("ip")})

            for ip in ips_suspeitos:
                dados = consultar_ip(ip, cache_enriquecimento)
                exibir_enriquecimento(dados)

            print(f"\n[OK] {len(cache_enriquecimento)} IP(s) no cache de enriquecimento.")

        # ── Opção 8: Exportar relatório JSON ──────────────────────────────────
        elif opcao == 8:
            if not eventos:
                print("\n[AVISO] Carregue os logs primeiro (opção 1).")
                continue

            dados_relatorio = {
                "gerado_em": __import__("datetime").datetime.now().isoformat(),
                "total_eventos": len(eventos),
                "total_alertas": len(alertas),
                "eventos": eventos,
                "alertas": alertas,
                "resumo_ameacas": resumo_ameacas,
                "enriquecimento": cache_enriquecimento
            }

            exportar_relatorio_json(dados_relatorio)

        # ── Opção 9: Iniciar servidor de alertas ──────────────────────────────
        elif opcao == 9:
            if servidor_ativo:
                print("\n[INFO] Servidor já está em execução na porta 9999.")
                print("[DICA] Abra outro terminal e execute: python cliente_alertas.py")
                continue

            print("\n[INFO] Iniciando servidor de alertas em background...")
            print("[INFO] Clientes podem conectar com: python cliente_alertas.py")
            print("[INFO] O servidor ficará ativo enquanto o programa estiver rodando.\n")

            thread_servidor = threading.Thread(
                target=iniciar_servidor,
                daemon=True
            )
            thread_servidor.start()
            servidor_ativo = True

            # Envia os alertas existentes para o broadcast quando o servidor subir
            if alertas:
                import time
                time.sleep(1)  # aguarda o servidor iniciar
                print(f"[INFO] Enviando {len(alertas)} alertas existentes...")
                for alerta in alertas:
                    broadcast_alerta(alerta)

        # ── Opção 0: Sair ─────────────────────────────────────────────────────
        elif opcao == 0:
            print("\nEncerrando SecuraPy. Até logo! 🛡️")
            break


if __name__ == "__main__":
    main()
