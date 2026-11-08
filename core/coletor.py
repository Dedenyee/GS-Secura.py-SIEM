"""
core/coletor.py — Coletor de Logs (reaproveitado do 1º semestre)

Le os arquivos de log (auth, firewall, web), parseia cada linha e normaliza
em eventos com formato padronizado (o "contrato" de evento entre os modulos):

{
    "timestamp": "2025-02-20 08:15:01",
    "fonte": "auth",              # auth | firewall | web
    "tipo": "FAIL",               # OK | FAIL | BLOCK | ALLOW | GET | POST | DELETE
    "ip": "185.220.101.1",
    "detalhes": "usuario=admin",
    "linha_original": "..."
}
"""

import os

FONTES_VALIDAS = ("auth", "firewall", "web")


def _extrair_campos(partes):
    """Transforma ['chave=valor', ...] em dict {chave: valor}."""
    campos = {}
    for parte in partes:
        if "=" in parte:
            chave, valor = parte.split("=", 1)
            campos[chave] = valor
    return campos


def _cabecalho(linha):
    """Separa timestamp (data + hora), tipo e o restante da linha.

    Retorna (timestamp, tipo, partes_restantes) ou None se invalida.
    """
    if not isinstance(linha, str):
        return None
    partes = linha.strip().split()
    if len(partes) < 4:
        return None
    data, hora, tipo = partes[0], partes[1], partes[2]
    if data.count("-") != 2 or hora.count(":") != 2:
        return None
    return f"{data} {hora}", tipo, partes[3:]


def _montar_evento(timestamp, fonte, tipo, ip, detalhes, linha):
    return {
        "timestamp": timestamp,
        "fonte": fonte,
        "tipo": tipo,
        "ip": ip,
        "detalhes": detalhes,
        "linha_original": linha.strip(),
    }


def parsear_linha_auth(linha):
    """'2025-02-20 08:15:01 FAIL usuario=admin ip=185.220.101.1' -> evento."""
    cab = _cabecalho(linha)
    if cab is None:
        return None
    timestamp, tipo, resto = cab
    if tipo not in ("OK", "FAIL"):
        return None
    campos = _extrair_campos(resto)
    if "ip" not in campos or "usuario" not in campos:
        return None
    return _montar_evento(timestamp, "auth", tipo, campos["ip"],
                          f"usuario={campos['usuario']}", linha)


def parsear_linha_firewall(linha):
    """'... BLOCK proto=TCP src=1.2.3.4 dst=10.0.0.1 dport=22' -> evento (ip = src)."""
    cab = _cabecalho(linha)
    if cab is None:
        return None
    timestamp, tipo, resto = cab
    if tipo not in ("BLOCK", "ALLOW"):
        return None
    campos = _extrair_campos(resto)
    if not {"src", "dst", "dport"} <= campos.keys():
        return None
    detalhes = f"proto={campos.get('proto', '?')} dst={campos['dst']} dport={campos['dport']}"
    return _montar_evento(timestamp, "firewall", tipo, campos["src"], detalhes, linha)


def parsear_linha_web(linha):
    """'... GET url=/index.html ip=192.168.1.10 status=200' -> evento.

    A URL pode conter espacos/caracteres especiais (ex: <script>), entao
    tudo entre 'url=' e ' ip=' eh considerado URL.
    """
    cab = _cabecalho(linha)
    if cab is None:
        return None
    timestamp, metodo, resto = cab
    if not metodo.isalpha() or not metodo.isupper():
        return None
    texto = " ".join(resto)
    if not texto.startswith("url=") or " ip=" not in texto:
        return None
    url, depois = texto[4:].rsplit(" ip=", 1)
    campos = _extrair_campos(depois.split())
    ip = depois.split()[0] if depois.split() else ""
    if not ip or "status" not in campos:
        return None
    return _montar_evento(timestamp, "web", metodo, ip,
                          f"url={url} status={campos['status']}", linha)


PARSERS = {
    "auth": parsear_linha_auth,
    "firewall": parsear_linha_firewall,
    "web": parsear_linha_web,
}


def carregar_log(caminho_arquivo, fonte):
    """Le um arquivo de log e retorna lista de eventos normalizados.

    Arquivo inexistente -> []. Linha malformada -> aviso e segue (nao trava).
    """
    parser = PARSERS.get(fonte)
    if parser is None:
        print(f"[ERRO] Fonte desconhecida: {fonte}")
        return []

    eventos = []
    try:
        with open(caminho_arquivo, "r", encoding="utf-8", errors="replace") as f:
            for numero, linha in enumerate(f, start=1):
                if not linha.strip():
                    continue
                evento = parser(linha)
                if evento is None:
                    print(f"[AVISO] {os.path.basename(caminho_arquivo)}:{numero} linha invalida ignorada")
                    continue
                eventos.append(evento)
    except FileNotFoundError:
        print(f"[ERRO] Arquivo nao encontrado: {caminho_arquivo}")
        return []
    except OSError as erro:
        print(f"[ERRO] Falha ao ler {caminho_arquivo}: {erro}")
        return []
    return eventos


def identificar_fonte(nome_arquivo):
    """auth.log -> 'auth', firewall.log -> 'firewall', web_access.log -> 'web'."""
    for fonte in FONTES_VALIDAS:
        if fonte in nome_arquivo:
            return fonte
    return None


def carregar_todos_os_logs(pasta_logs):
    """Le todos os .log da pasta e retorna lista unificada de eventos."""
    try:
        arquivos = sorted(os.listdir(pasta_logs))
    except (FileNotFoundError, NotADirectoryError):
        print(f"[ERRO] Pasta de logs nao encontrada: {pasta_logs}")
        return []

    todos = []
    for arquivo in arquivos:
        if not arquivo.endswith(".log"):
            continue
        fonte = identificar_fonte(arquivo)
        if fonte is None:
            print(f"[AVISO] Fonte nao identificada para {arquivo}, ignorando")
            continue
        eventos = carregar_log(os.path.join(pasta_logs, arquivo), fonte)
        print(f"[INFO] {arquivo}: {len(eventos)} eventos carregados")
        todos.extend(eventos)
    return todos
