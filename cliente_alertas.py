"""
MÓDULO 4 — Cliente TCP de Alertas em Tempo Real
SecuraPy SIEM
"""

import socket
import threading


# ─── Recepção de alertas (thread separada) ────────────────────────────────────

def receber_alertas(cliente):
    """
    Thread que fica ouvindo o servidor e exibe cada alerta recebido.
    Encerra sozinha quando o servidor fecha a conexão.
    """
    while True:
        try:
            dados = cliente.recv(4096)
            if not dados:
                print("\n[!] Servidor encerrou a conexão.")
                break
            mensagem = dados.decode().strip()
            # Imprime acima do prompt atual
            print(f"\n{mensagem}\n>> ", end="", flush=True)
        except (ConnectionResetError, BrokenPipeError, OSError):
            print("\n[!] Conexão perdida com o servidor.")
            break


# ─── Conexão e loop principal ─────────────────────────────────────────────────

def conectar_servidor(host="127.0.0.1", porta=9999):
    """
    Conecta ao servidor e fica recebendo alertas.
    O usuário pode digitar comandos enquanto alertas chegam em paralelo.
    """
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        cliente.connect((host, porta))
    except ConnectionRefusedError:
        print(f"[ERRO] Não foi possível conectar em {host}:{porta}.")
        print("Verifique se o servidor está rodando.")
        return

    print(f"Conectado ao SecuraPy SIEM ({host}:{porta})")
    print("Comandos: /status, /historico, /sair\n")

    # Thread de recepção roda em paralelo com o loop de input
    thread_recv = threading.Thread(target=receber_alertas, args=(cliente,), daemon=True)
    thread_recv.start()

    # Loop de envio de comandos
    try:
        while thread_recv.is_alive():
            try:
                comando = input(">> ").strip()
            except EOFError:
                break

            if not comando:
                continue

            try:
                cliente.sendall(comando.encode())
            except (BrokenPipeError, OSError):
                print("[!] Erro ao enviar comando. Conexão encerrada.")
                break

            if comando == "/sair":
                break

    except KeyboardInterrupt:
        print("\n[!] Cliente encerrado pelo usuário.")

    finally:
        cliente.close()
        print("Desconectado.")


# ─── Execução direta ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    conectar_servidor()
