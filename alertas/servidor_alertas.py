"""
MÓDULO 4 — Servidor TCP de Alertas em Tempo Real
SecuraPy SIEM
"""

import socket
import threading
from datetime import datetime

# ─── Estado global do servidor ───────────────────────────────────────────────
clientes = {}           # {conexao: endereco} — clientes conectados
historico = []          # lista dos últimos alertas enviados
lock = threading.Lock() # lock para evitar condição de corrida no dicionário


# ─── Formatação ──────────────────────────────────────────────────────────────

def formatar_alerta(alerta_dict):
    """
    Converte dict de alerta em string formatada para exibição.
    Formato: [HH:MM:SS] [SEVERIDADE] REGRA — IP — Descrição
    Exemplo:  [08:15:01] [CRITICA] Brute Force — 185.220.101.1 — 10 tentativas em 30s
    """
    timestamp = datetime.now().strftime("%H:%M:%S")
    severidade = alerta_dict.get("severidade", "INFO").upper()
    regra      = alerta_dict.get("regra", "Desconhecida")
    ip         = alerta_dict.get("ip", "0.0.0.0")
    descricao  = alerta_dict.get("descricao", "")

    return f"[{timestamp}] [{severidade}] {regra} — {ip} — {descricao}"


# ─── Broadcast ───────────────────────────────────────────────────────────────

def broadcast_alerta(alerta):
    """
    Envia um alerta formatado para todos os clientes conectados.
    Remove automaticamente clientes que caíram.
    """
    mensagem = formatar_alerta(alerta) if isinstance(alerta, dict) else alerta

    # Guarda no histórico (máximo 10 entradas)
    with lock:
        historico.append(mensagem)
        if len(historico) > 10:
            historico.pop(0)
        conexoes = list(clientes.keys())   # cópia para iterar fora do lock

    caidos = []
    for conexao in conexoes:
        try:
            conexao.sendall((mensagem + "\n").encode())
        except (ConnectionResetError, BrokenPipeError, OSError):
            caidos.append(conexao)

    # Remove clientes que caíram durante o broadcast
    for conexao in caidos:
        _remover_cliente(conexao)

    with lock:
        qtd = len(clientes)
    severidade = alerta.get("severidade", "?") if isinstance(alerta, dict) else "?"
    regra      = alerta.get("regra", "?")      if isinstance(alerta, dict) else "?"
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Alerta enviado para {qtd} cliente(s): [{severidade}] {regra}")


# ─── Gerenciamento de clientes ────────────────────────────────────────────────

def _remover_cliente(conexao):
    """Remove um cliente do dicionário e fecha a conexão."""
    with lock:
        endereco = clientes.pop(conexao, None)
    if endereco:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Cliente desconectado: {endereco[0]}:{endereco[1]}")
    try:
        conexao.close()
    except OSError:
        pass


def tratar_cliente(conexao, endereco):
    """
    Gerencia comunicação com um cliente individual.
    Roda em thread separada para cada conexão.
    """
    boas_vindas = (
        "Conectado ao SecuraPy SIEM\n"
        f"Seu endereço: {endereco[0]}:{endereco[1]}\n"
        "Comandos disponíveis: /status  /historico  /sair\n"
    )
    try:
        conexao.sendall(boas_vindas.encode())
    except OSError:
        _remover_cliente(conexao)
        return

    while True:
        try:
            dados = conexao.recv(1024)
            if not dados:           # cliente fechou a conexão normalmente
                break

            comando = dados.decode().strip()

            if comando == "/sair":
                conexao.sendall("Até logo! Desconectando...\n".encode())
                break

            elif comando == "/status":
                with lock:
                    qtd_clientes = len(clientes)
                    qtd_alertas  = len(historico)
                resposta = f"Clientes conectados: {qtd_clientes} | Alertas na sessão: {qtd_alertas}\n"
                conexao.sendall(resposta.encode())

            elif comando == "/historico":
                with lock:
                    snap = list(historico)   # cópia segura
                if snap:
                    resposta = "=== Últimos alertas ===\n" + "\n".join(snap) + "\n"
                else:
                    resposta = "Nenhum alerta registrado ainda.\n"
                conexao.sendall(resposta.encode())

            else:
                conexao.sendall(f"Comando desconhecido: '{comando}'\n".encode())

        except (ConnectionResetError, BrokenPipeError, OSError):
            break

    _remover_cliente(conexao)


# ─── Entrada do servidor ─────────────────────────────────────────────────────

def iniciar_servidor(host="0.0.0.0", porta=9999):
    """
    Inicia o servidor TCP e fica aguardando conexões.
    Cada cliente recebe uma thread dedicada.
    """
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind((host, porta))
    servidor.listen(10)

    print("=== Servidor de Alertas SecuraPy ===")
    print(f"Rodando em {host}:{porta}")
    print("Aguardando conexões...\n")

    try:
        while True:
            conexao, endereco = servidor.accept()
            with lock:
                clientes[conexao] = endereco
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Cliente conectado: {endereco[0]}:{endereco[1]}")

            thread = threading.Thread(
                target=tratar_cliente,
                args=(conexao, endereco),
                daemon=True
            )
            thread.start()

    except KeyboardInterrupt:
        print("\n[!] Servidor encerrado pelo operador.")
        # Avisa todos os clientes antes de fechar
        with lock:
            conexoes = list(clientes.keys())
        for conexao in conexoes:
            try:
                conexao.sendall("Servidor encerrado. Desconectando...\n".encode())
                conexao.close()
            except OSError:
                pass
    finally:
        servidor.close()


# ─── Execução direta ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    iniciar_servidor()
