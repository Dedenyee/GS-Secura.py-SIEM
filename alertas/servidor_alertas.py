"""
alertas/servidor_alertas.py — Servidor TCP de alertas em tempo real (1º semestre)

Aceita varios consoles (clientes) e faz broadcast de alertas para todos.
Comandos do cliente: /status, /historico, /sair

Novidade 2º sem: iniciar_em_background() permite que a API/pipeline suba o
servidor numa thread e chame broadcast_alerta() quando detectar algo critico.
"""

import os
import socket
import threading

HOST = os.environ.get("ALERTAS_HOST", "0.0.0.0")
PORTA = int(os.environ.get("ALERTAS_PORTA", "9999"))
MAX_CLIENTES = 10
TAMANHO_HISTORICO = 100

clientes = {}            # {conexao: endereco}
lock = threading.Lock()
historico_alertas = []   # strings ja formatadas


def formatar_alerta(alerta_dict):
    """'[08:15:01] [CRITICA] Brute Force - 185.220.101.1 - descricao'."""
    timestamp = str(alerta_dict.get("timestamp", ""))
    hora = timestamp.split()[-1] if timestamp else "--:--:--"
    return (f"[{hora}] [{alerta_dict.get('severidade', '?')}] "
            f"{alerta_dict.get('regra_nome', 'Alerta')} - {alerta_dict.get('ip', '?')} - "
            f"{alerta_dict.get('descricao', '')}")


def broadcast_alerta(alerta):
    """Envia o alerta (dict ou str) a todos os clientes; remove os desconectados."""
    mensagem = formatar_alerta(alerta) if isinstance(alerta, dict) else str(alerta)
    dados = (mensagem + "\n").encode()

    with lock:
        historico_alertas.append(mensagem)
        del historico_alertas[:-TAMANHO_HISTORICO]
        destinos = list(clientes.keys())

    mortos = []
    for conexao in destinos:
        try:
            conexao.sendall(dados)
        except OSError:
            mortos.append(conexao)
    for conexao in mortos:
        remover_cliente(conexao)
    return len(destinos) - len(mortos)


def remover_cliente(conexao):
    with lock:
        endereco = clientes.pop(conexao, None)
    try:
        conexao.close()
    except OSError:
        pass
    if endereco:
        print(f"[SERVIDOR] Cliente desconectado: {endereco}")


def _enviar(conexao, texto):
    try:
        conexao.sendall((texto + "\n").encode())
        return True
    except OSError:
        return False


def tratar_cliente(conexao, endereco):
    with lock:
        if len(clientes) >= MAX_CLIENTES:
            lotado = True
        else:
            lotado = False
            clientes[conexao] = endereco
    if lotado:
        _enviar(conexao, "Servidor lotado. Tente mais tarde.")
        conexao.close()
        return

    print(f"[SERVIDOR] Cliente conectado: {endereco}")
    _enviar(conexao, "Bem-vindo ao SecuraPy Alertas! Comandos: /status /historico /sair")

    try:
        while True:
            dados = conexao.recv(1024)
            if not dados:
                break
            comando = dados.decode(errors="replace").strip().lower()
            if comando == "/status":
                with lock:
                    texto = f"Clientes conectados: {len(clientes)} | Alertas na sessao: {len(historico_alertas)}"
                _enviar(conexao, texto)
            elif comando == "/historico":
                with lock:
                    ultimos = historico_alertas[-10:]
                _enviar(conexao, "\n".join(ultimos) if ultimos else "Nenhum alerta ainda.")
            elif comando == "/sair":
                _enviar(conexao, "Ate logo!")
                break
            else:
                _enviar(conexao, "Comando desconhecido. Use /status, /historico ou /sair")
    except (ConnectionResetError, ConnectionAbortedError, OSError):
        pass
    finally:
        remover_cliente(conexao)


def _loop_aceitar(servidor):
    while True:
        try:
            conexao, endereco = servidor.accept()
        except OSError:
            break
        threading.Thread(target=tratar_cliente, args=(conexao, endereco), daemon=True).start()


def criar_socket_servidor(host=HOST, porta=PORTA):
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind((host, porta))
    servidor.listen(MAX_CLIENTES)
    return servidor


def iniciar_em_background(host=HOST, porta=PORTA):
    """Sobe o servidor numa thread daemon e devolve o socket (para fechar depois)."""
    servidor = criar_socket_servidor(host, porta)
    threading.Thread(target=_loop_aceitar, args=(servidor,), daemon=True).start()
    print(f"[SERVIDOR] Alertas ouvindo em {host}:{porta} (background)")
    return servidor


def iniciar_servidor(host=HOST, porta=PORTA):
    """Modo bloqueante (CLI). Ctrl+C encerra."""
    try:
        servidor = criar_socket_servidor(host, porta)
    except OSError as erro:
        print(f"[ERRO] Nao foi possivel abrir {host}:{porta}: {erro}")
        return
    print(f"[SERVIDOR] Alertas ouvindo em {host}:{porta}. Ctrl+C para sair.")
    try:
        _loop_aceitar(servidor)
    except KeyboardInterrupt:
        print("\n[SERVIDOR] Encerrando...")
    finally:
        with lock:
            conexoes = list(clientes.keys())
        for c in conexoes:
            remover_cliente(c)
        servidor.close()


if __name__ == "__main__":
    iniciar_servidor()
