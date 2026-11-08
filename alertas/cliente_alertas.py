"""
alertas/cliente_alertas.py — Console cliente de alertas (1º semestre)

Uso:  python -m alertas.cliente_alertas [host] [porta]
"""

import socket
import sys
import threading

HOST = "127.0.0.1"
PORTA = 9999


def receber_alertas(cliente):
    while True:
        try:
            dados = cliente.recv(4096)
        except OSError:
            break
        if not dados:
            print("\n[!] Servidor desconectou.")
            break
        print(dados.decode(errors="replace"), end="", flush=True)


def conectar_servidor(host=HOST, porta=PORTA):
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        cliente.connect((host, porta))
    except (ConnectionRefusedError, OSError) as erro:
        print(f"[ERRO] Nao foi possivel conectar em {host}:{porta}: {erro}")
        return

    threading.Thread(target=receber_alertas, args=(cliente,), daemon=True).start()
    try:
        while True:
            comando = input()
            if not comando.strip():
                continue
            cliente.sendall(comando.encode())
            if comando.strip().lower() == "/sair":
                break
    except (KeyboardInterrupt, EOFError):
        pass
    except OSError:
        print("[ERRO] Conexao perdida.")
    finally:
        cliente.close()


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    porta = int(sys.argv[2]) if len(sys.argv) > 2 else PORTA
    conectar_servidor(host, porta)
