"""
Módulo 4 — Servidor de Alertas TCP (servidor_alertas.py)
Aceita múltiplas conexões simultâneas de clientes (analistas)
e faz broadcast de alertas em tempo real para todos conectados.
"""

import socket
import threading
from datetime import datetime

# ── Estado global compartilhado ───────────────────────────────────────────────
clientes = {}          # {socket: endereco}
historico_alertas = [] # lista dos últimos alertas enviados
lock = threading.Lock()

HOST = "0.0.0.0"
PORTA = 9999
MAX_HISTORICO = 50


def formatar_alerta(alerta_dict):
    """
    Converte um dicionário de alerta em string formatada para exibição.

    Formato: [TIMESTAMP] [SEVERIDADE] REGRA — IP — Descrição

    Parâmetros:
        alerta_dict (dict): dicionário com os dados do alerta

    Retorna:
        str: alerta formatado como string
    """
    timestamp = alerta_dict.get("timestamp", "??:??:??")
    severidade = alerta_dict.get("severidade", "INFO")
    nome = alerta_dict.get("regra_nome", alerta_dict.get("nome", "Alerta"))
    ip = alerta_dict.get("ip", "desconhecido")
    descricao = alerta_dict.get("descricao", "")

    return f"[{timestamp}] [{severidade}] {nome} — {ip} — {descricao}"


def broadcast_alerta(alerta):
    """
    Envia um alerta formatado para todos os clientes conectados.

    Parâmetros:
        alerta (str ou dict): alerta a ser enviado
    """
    global historico_alertas

    if isinstance(alerta, dict):
        mensagem = formatar_alerta(alerta)
    else:
        mensagem = str(alerta)

    # Salva no histórico
    with lock:
        historico_alertas.append(mensagem)
        if len(historico_alertas) > MAX_HISTORICO:
            historico_alertas = historico_alertas[-MAX_HISTORICO:]

    # Envia para todos os clientes conectados
    clientes_desconectados = []

    with lock:
        lista_clientes = list(clientes.items())

    for cliente_socket, endereco in lista_clientes:
        try:
            cliente_socket.sendall((mensagem + "\n").encode("utf-8"))
        except (ConnectionResetError, BrokenPipeError, OSError):
            clientes_desconectados.append(cliente_socket)

    # Remove clientes que caíram
    with lock:
        for cs in clientes_desconectados:
            if cs in clientes:
                print(f"[SERVIDOR] Cliente removido por falha de envio: {clientes[cs]}")
                del clientes[cs]

    print(f"[SERVIDOR] Alerta enviado para {len(lista_clientes) - len(clientes_desconectados)} cliente(s): {mensagem[:60]}...")


def tratar_cliente(conexao, endereco):
    """
    Gerencia a comunicação com um cliente individual.
    Cada cliente roda nesta função em uma thread separada.

    Parâmetros:
        conexao (socket): socket do cliente
        endereco (tuple): (ip, porta) do cliente
    """
    endereco_str = f"{endereco[0]}:{endereco[1]}"

    # Registra o cliente
    with lock:
        clientes[conexao] = endereco_str

    print(f"[SERVIDOR] Cliente conectado: {endereco_str}")

    boas_vindas = (
        "╔══════════════════════════════════════════╗\n"
        "║   Conectado ao SecuraPy SIEM             ║\n"
        "║   Comandos: /status  /historico  /sair   ║\n"
        "╚══════════════════════════════════════════╝\n"
    )

    try:
        conexao.sendall(boas_vindas.encode("utf-8"))

        while True:
            try:
                dados = conexao.recv(1024)
            except (ConnectionResetError, OSError):
                break

            if not dados:
                break

            comando = dados.decode("utf-8", errors="ignore").strip().lower()

            if comando == "/sair":
                conexao.sendall("Até logo! Desconectando...\n".encode("utf-8"))
                break

            elif comando == "/status":
                with lock:
                    num_clientes = len(clientes)
                    num_alertas = len(historico_alertas)
                resposta = f"Clientes conectados: {num_clientes} | Alertas na sessão: {num_alertas}\n"
                conexao.sendall(resposta.encode("utf-8"))

            elif comando == "/historico":
                with lock:
                    ultimos = list(historico_alertas[-10:])
                if ultimos:
                    resposta = "--- Últimos alertas ---\n" + "\n".join(ultimos) + "\n-----------------------\n"
                else:
                    resposta = "Nenhum alerta registrado ainda.\n"
                conexao.sendall(resposta.encode("utf-8"))

            elif comando:
                conexao.sendall(f"Comando desconhecido: '{comando}'. Use /status, /historico ou /sair\n".encode("utf-8"))

    except Exception as e:
        print(f"[SERVIDOR] Erro com cliente {endereco_str}: {e}")
    finally:
        with lock:
            if conexao in clientes:
                del clientes[conexao]
        try:
            conexao.close()
        except OSError:
            pass
        print(f"[SERVIDOR] Cliente desconectado: {endereco_str}")


def iniciar_servidor(host=HOST, porta=PORTA):
    """
    Inicia o servidor TCP e fica aguardando conexões.
    Cada nova conexão é tratada em uma thread separada.

    Parâmetros:
        host (str): endereço para escutar (padrão: 0.0.0.0 = todas as interfaces)
        porta (int): porta TCP (padrão: 9999)
    """
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        servidor.bind((host, porta))
        servidor.listen(10)

        print("╔══════════════════════════════════════════╗")
        print("║     Servidor de Alertas SecuraPy         ║")
        print(f"║     Rodando em {host}:{porta}           ║")
        print("║     Pressione Ctrl+C para encerrar       ║")
        print("╚══════════════════════════════════════════╝")

        while True:
            try:
                conexao, endereco = servidor.accept()
                thread = threading.Thread(
                    target=tratar_cliente,
                    args=(conexao, endereco),
                    daemon=True
                )
                thread.start()
            except OSError:
                break

    except KeyboardInterrupt:
        print("\n[SERVIDOR] Encerrando servidor...")
    except OSError as e:
        print(f"[ERRO] Não foi possível iniciar o servidor: {e}")
    finally:
        # Avisa todos os clientes que o servidor está encerrando
        with lock:
            for cs in list(clientes.keys()):
                try:
                    cs.sendall("Servidor encerrado. Até logo!\n".encode("utf-8"))
                    cs.close()
                except OSError:
                    pass
        servidor.close()
        print("[SERVIDOR] Encerrado com sucesso.")


if __name__ == "__main__":
    iniciar_servidor()
