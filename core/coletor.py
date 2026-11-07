"""
Modulo 1 - Coletor de Logs
Responsavel por ler arquivos de log de diferentes fontes (auth, firewall, web),
parsear cada linha e normalizar os eventos em um formato padronizado de dicionario.

Formato padronizado de evento:
{
    "timestamp": "2025-02-20 08:15:01",
    "fonte": "auth",              # auth | firewall | web
    "tipo": "FAIL",               # OK | FAIL | BLOCK | ALLOW | GET | POST | DELETE
    "ip": "185.220.101.1",
    "detalhes": "usuario=admin",  # informacoes extras dependendo da fonte
    "linha_original": "..."       # linha crua do log
}


"""

import os



def parsear_linha_auth(linha):
    """
    Parseia uma linha do auth.log e retorna um dicionario normalizado.

    Formato esperado:
        "2025-02-20 08:15:01 FAIL usuario=admin ip=185.220.101.1"

    Retorna dict normalizado ou None se o formato for invalido.
    """
    linha = linha.strip()           
    if not linha:                   # ignora linhas em branco
        return None

    partes = linha.split()          

    # Precisamos de pelo menos: data hora tipo campo_extra
    if len(partes) < 4:
        return None

    # As duas primeiras partes formam o timestamp 
    timestamp = partes[0] + " " + partes[1]
    tipo = partes[2]                # FAIL ou OK

    # Validacao simples do tipo (Aula 4 — condicionais)
    if tipo not in ("FAIL", "OK"):
        return None

    # Percorre o restante procurando campos chave=valor 
    ip = ""
    usuario = ""
    for parte in partes[3:]:
        if "=" in parte:
            chave, valor = parte.split("=", 1)  # split com limite evita problemas
            if chave == "ip":
                ip = valor
            elif chave == "usuario":
                usuario = valor

    # Se nao encontrou IP, linha esta incompleta
    if not ip:
        return None

    # Monta o dicionario padronizado 
    evento = {
        "timestamp": timestamp,
        "fonte": "auth",
        "tipo": tipo,
        "ip": ip,
        "detalhes": "usuario=" + usuario,
        "linha_original": linha
    }
    return evento


def parsear_linha_firewall(linha):
    """
    Parseia uma linha do firewall.log e retorna um dicionario normalizado.

    Formato esperado:
        "2025-02-20 08:10:02 BLOCK proto=TCP src=185.220.101.1 dst=10.0.0.1 dport=22"

    Retorna dict normalizado ou None se o formato for invalido.
    """
    linha = linha.strip()
    if not linha:
        return None

    partes = linha.split()

    if len(partes) < 4:
        return None

    timestamp = partes[0] + " " + partes[1]
    tipo = partes[2]                # BLOCK ou ALLOW

    if tipo not in ("BLOCK", "ALLOW"):
        return None

    # Percorre campos chave=valor
    ip_origem = ""
    proto = ""
    dst = ""
    dport = ""
    for parte in partes[3:]:
        if "=" in parte:
            chave, valor = parte.split("=", 1)
            if chave == "src":
                ip_origem = valor
            elif chave == "proto":
                proto = valor
            elif chave == "dst":
                dst = valor
            elif chave == "dport":
                dport = valor

    if not ip_origem:
        return None

    # Campo detalhes agrupa info relevante do firewall
    detalhes = "proto=" + proto + " dst=" + dst + " dport=" + dport

    evento = {
        "timestamp": timestamp,
        "fonte": "firewall",
        "tipo": tipo,
        "ip": ip_origem,
        "detalhes": detalhes,
        "linha_original": linha
    }
    return evento


def parsear_linha_web(linha):
    """
    Parseia uma linha do web_access.log e retorna um dicionario normalizado.

    Formato esperado:
        "2025-02-20 08:20:01 GET url=/index.html ip=192.168.1.10 status=200"

    Retorna dict normalizado ou None se o formato for invalido.

    Atencao: a URL pode conter caracteres especiais (<script>, ../).
    Usamos split() com limite para nao quebrar a URL no meio.
    """
    linha = linha.strip()
    if not linha:
        return None

    partes = linha.split()

    if len(partes) < 4:
        return None

    timestamp = partes[0] + " " + partes[1]
    metodo = partes[2]              # GET, POST, DELETE, etc.

    ip = ""
    url = ""
    status = ""
    for parte in partes[3:]:
        if "=" in parte:
            chave, valor = parte.split("=", 1)  # limite 1 preserva URLs com "="
            if chave == "ip":
                ip = valor
            elif chave == "url":
                url = valor
            elif chave == "status":
                status = valor

    if not ip:
        return None

    detalhes = "url=" + url + " status=" + status

    evento = {
        "timestamp": timestamp,
        "fonte": "web",
        "tipo": metodo,
        "ip": ip,
        "detalhes": detalhes,
        "linha_original": linha
    }
    return evento



# FUNCOES DE CARREGAMENTO


def carregar_log(caminho_arquivo, fonte):
    """
    Le um arquivo de log e retorna lista de eventos normalizados.

    Parametros:
        caminho_arquivo (str): caminho do arquivo
        fonte (str): "auth", "firewall" ou "web"

    Retorna:
        list[dict] — lista de eventos; lista vazia em caso de erro.

    """
    eventos = []    # lista que acumula os eventos

    try:                            # tratamento de excecoes
        with open(caminho_arquivo, "r", encoding="utf-8") as arquivo:   # Aula 12
            linhas = arquivo.readlines()

        # Arquivo vazio 
        if len(linhas) == 0:
            print("[AVISO] Arquivo vazio:", caminho_arquivo)
            return []

        numero = 0
        for linha in linhas:      
            numero += 1
            linha = linha.strip()
            if not linha:           # pula linhas em branco silenciosamente
                continue

            # Escolhe o parser correto baseado na fonte 
            if fonte == "auth":
                evento = parsear_linha_auth(linha)
            elif fonte == "firewall":
                evento = parsear_linha_firewall(linha)
            elif fonte == "web":
                evento = parsear_linha_web(linha)
            else:
                print("[ERRO] Fonte desconhecida:", fonte)
                return []

            # Se o parser retornou None, a linha estava mal formatada
            if evento is None:
                print("[AVISO] Linha " + str(numero) + " ignorada (formato invalido): " + linha)
            else:
                eventos.append(evento)  #append na lista

    except FileNotFoundError:       # tratamento de excecoes
        print("[ERRO] Arquivo nao encontrado:", caminho_arquivo)
        return []
    except Exception as erro:       # tratamento de excecoes
        print("[ERRO] Falha ao ler arquivo:", str(erro))
        return []

    return eventos


def carregar_todos_os_logs(pasta_logs):
    """
    Le todos os arquivos .log da pasta e retorna lista unificada de eventos.

    Parametros:
        pasta_logs (str): caminho da pasta com os logs

    Retorna:
        list[dict] — eventos de todas as fontes combinados.

    """
    todos_eventos = []  # lista que vai acumular tudo

    try:
        arquivos = os.listdir(pasta_logs)   
    except FileNotFoundError:
        print("[ERRO] Pasta de logs nao encontrada:", pasta_logs)
        return []

    for arquivo in arquivos:        
        
        if not arquivo.endswith(".log"):
            continue

        # Identifica a fonte pelo nome do arquivo
        if "auth" in arquivo:
            fonte = "auth"
        elif "firewall" in arquivo:
            fonte = "firewall"
        elif "web" in arquivo:
            fonte = "web"
        else:
            print("[AVISO] Arquivo sem fonte reconhecida, ignorado:", arquivo)
            continue

        caminho_completo = os.path.join(pasta_logs, arquivo)   
        eventos = carregar_log(caminho_completo, fonte)

        print("[OK] " + arquivo + " — " + str(len(eventos)) + " eventos carregados")

        #extend adiciona todos os eventos da lista parcial na principal
        todos_eventos.extend(eventos)

    return todos_eventos


# BLOCO DE TESTE RAPIDO (executado apenas ao rodar este arquivo diretamente)

if __name__ == "__main__":
    print("=" * 50)
    print("TESTE DO MODULO COLETOR")
    print("=" * 50)

    # Teste 1: carregar um arquivo especifico
    print("\n[TESTE 1] Carregando auth.log...")
    eventos_auth = carregar_log("logs/auth.log", "auth")
    print("Total de eventos:", len(eventos_auth))
    if eventos_auth:
        print("Primeiro evento:", eventos_auth[0])

    # Teste 2: arquivo inexistente
    print("\n[TESTE 2] Tentando arquivo inexistente...")
    resultado = carregar_log("logs/naoexiste.log", "auth")
    print("Retornou lista vazia?", resultado == [])

    # Teste 3: todos os logs
    print("\n[TESTE 3] Carregando todos os logs...")
    todos = carregar_todos_os_logs("logs")
    print("Total geral de eventos:", len(todos))
