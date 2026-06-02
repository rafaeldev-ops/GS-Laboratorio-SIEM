"""
Módulo 4 — Cliente de Alertas TCP (cliente_alertas.py)
Conecta ao servidor de alertas e exibe os alertas em tempo real.
Pode ser executado em múltiplos terminais simultaneamente.
"""

import socket
import threading
import sys

HOST_PADRAO = "127.0.0.1"
PORTA_PADRAO = 9999

# Flag para controlar o loop de recepção
rodando = True


def receber_alertas(cliente):
    """
    Thread que fica recebendo e exibindo mensagens do servidor.

    Parâmetros:
        cliente (socket): socket conectado ao servidor
    """
    global rodando

    while rodando:
        try:
            dados = cliente.recv(4096)
            if not dados:
                print("\n[CLIENTE] Servidor encerrou a conexão.")
                rodando = False
                break
            mensagem = dados.decode("utf-8", errors="ignore")
            # Exibe a mensagem sem quebrar o prompt do usuário
            print(mensagem, end="", flush=True)
        except (ConnectionResetError, OSError):
            if rodando:
                print("\n[CLIENTE] Conexão com o servidor perdida.")
            rodando = False
            break


def conectar_servidor(host=HOST_PADRAO, porta=PORTA_PADRAO):
    """
    Conecta ao servidor de alertas e gerencia a interação do usuário.

    Parâmetros:
        host (str): IP ou hostname do servidor
        porta (int): porta TCP do servidor
    """
    global rodando

    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        cliente.connect((host, porta))
        print(f"[CLIENTE] Conectado ao SecuraPy SIEM ({host}:{porta})")
        print("[CLIENTE] Digite /status, /historico ou /sair\n")
    except ConnectionRefusedError:
        print(f"[ERRO] Não foi possível conectar ao servidor em {host}:{porta}")
        print("[DICA] Certifique-se de que o servidor está rodando (python servidor_alertas.py)")
        return
    except Exception as e:
        print(f"[ERRO] Falha de conexão: {e}")
        return

    # Inicia thread de recepção em paralelo
    thread_recepcao = threading.Thread(
        target=receber_alertas,
        args=(cliente,),
        daemon=True
    )
    thread_recepcao.start()

    # Loop principal: lê comandos do usuário
    try:
        while rodando:
            try:
                comando = input(">> ").strip()
            except EOFError:
                break

            if not rodando:
                break

            if not comando:
                continue

            try:
                cliente.sendall(comando.encode("utf-8"))
            except (BrokenPipeError, OSError):
                print("[CLIENTE] Conexão perdida ao enviar comando.")
                break

            if comando.lower() == "/sair":
                rodando = False
                break

    except KeyboardInterrupt:
        print("\n[CLIENTE] Encerrando...")
    finally:
        rodando = False
        try:
            cliente.close()
        except OSError:
            pass
        print("[CLIENTE] Desconectado.")


if __name__ == "__main__":
    # Permite passar host e porta como argumentos: python cliente_alertas.py 192.168.1.5 9999
    host = sys.argv[1] if len(sys.argv) > 1 else HOST_PADRAO
    try:
        porta = int(sys.argv[2]) if len(sys.argv) > 2 else PORTA_PADRAO
    except ValueError:
        print("[ERRO] Porta inválida. Usando porta padrão 9999.")
        porta = PORTA_PADRAO

    conectar_servidor(host, porta)
