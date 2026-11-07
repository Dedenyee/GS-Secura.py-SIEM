"""
Modulo 2 - Motor de Regras
Responsavel por carregar regras de deteccao de um arquivo JSON,
avaliar cada evento contra as regras ativas e gerar alertas
quando uma regra eh violada.

Formato de um alerta gerado:
{
    "timestamp": "2025-02-20 08:15:01",
    "regra_id": "R001",
    "regra_nome": "Login com Usuario Privilegiado",
    "severidade": "MEDIA",
    "ip": "185.220.101.1",
    "descricao": "Tentativa de login com usuario admin"
}

Niveis de severidade (baseados na pontuacao):
    >= 9: CRITICA
    >= 7: ALTA
    >= 5: MEDIA
    >= 3: BAIXA
     < 3: INFO

"""

import json  # modulo para trabalhar com JSON


# CARREGAMENTO DAS REGRAS

def carregar_regras(caminho_config):
    """
    Le o arquivo regras.json e retorna a lista de regras ATIVAS.

    Parametros:
        caminho_config (str): caminho para o arquivo JSON

    Retorna:
        list[dict]: regras ativas; lista vazia em caso de erro.

    """
    try:                                            #tratamento de excecoes
        with open(caminho_config, "r", encoding="utf-8") as arquivo:
            dados = json.load(arquivo)              #le e converte JSON

        # Pega a lista de regras dentro da chave "regras" 
        todas_regras = dados.get("regras", [])

        # Filtra apenas regras com "ativa": true (list comprehension)
        regras_ativas = [r for r in todas_regras if r.get("ativa", False)]

        print("[OK] Regras carregadas:", len(regras_ativas), "ativas de", len(todas_regras), "total")
        return regras_ativas

    except FileNotFoundError:                       #arquivo nao existe
        print("[ERRO] Arquivo de regras nao encontrado:", caminho_config)
        return []

    except json.JSONDecodeError as erro:            # JSON malformado
        print("[ERRO] JSON invalido em", caminho_config, "—", str(erro))
        return []

    except Exception as erro:                       #outros erros
        print("[ERRO] Falha ao carregar regras:", str(erro))
        return []



# CLASSIFICACAO DE SEVERIDADE

def classificar_severidade(pontuacao):
    """
    Converte pontuacao numerica em nivel de severidade textual.

    Parametros:
        pontuacao (int | float): valor da severidade

    Retorna:
        str: "CRITICA", "ALTA", "MEDIA", "BAIXA" ou "INFO"

    """
    # Tupla de limiares — imutavel por ser configuracao 
    LIMIARES = (9, 7, 5, 3)    # CRITICA, ALTA, MEDIA, BAIXA

    # Condicionais do maior para o menor 
    if pontuacao >= LIMIARES[0]:
        return "CRITICA"
    elif pontuacao >= LIMIARES[1]:
        return "ALTA"
    elif pontuacao >= LIMIARES[2]:
        return "MEDIA"
    elif pontuacao >= LIMIARES[3]:
        return "BAIXA"
    else:
        return "INFO"


# AVALIACAO DE UMA REGRA CONTRA UM EVENTO

def avaliar_regra(regra, evento):
    """
    Avalia se um evento viola uma regra especifica.

    Parametros:
        regra  (dict): dicionario de uma regra (do JSON)
        evento (dict): evento normalizado (do coletor)

    Retorna:
        dict: alerta gerado, ou None se a regra nao foi violada.


    """
    # Verifica se a fonte do evento bate com a da regra 
    if evento.get("fonte") != regra.get("fonte"):
        return None

    condicao = regra.get("condicao", "")
    detalhes = evento.get("detalhes", "")
    ip = evento.get("ip", "")
    violou = False          # flag — indica se a regra foi violada
    descricao_extra = ""    # mensagem detalhada para o alerta

    #Avalia cada tipo de condicao 

    if condicao == "usuario_privilegiado":
        # Extrai o nome do usuario de "usuario=admin" -> "admin"
        usuario = ""
        for campo in detalhes.split():          # for nos campos
            if campo.startswith("usuario="):
                usuario = campo.split("=", 1)[1]    # split com limite

        # Verifica se o usuario esta na lista de alvos (in na lista)
        if usuario in regra.get("usuarios_alvo", []):
            violou = True
            descricao_extra = "Tentativa de login com usuario " + usuario

    elif condicao == "porta_critica":
        # Extrai o numero da porta de "dport=22" -> 22
        porta = 0
        for campo in detalhes.split():          # for
            if campo.startswith("dport="):
                try:
                    porta = int(campo.split("=", 1)[1])   # int pode falhar
                except ValueError:
                    porta = 0

        # Verifica se a acao eh BLOCK e a porta esta na lista critica
        if evento.get("tipo") == "BLOCK" and porta in regra.get("portas_criticas", []):
            violou = True
            descricao_extra = "Porta critica " + str(porta) + " bloqueada"

    elif condicao == "path_traversal":
        # Extrai a URL do campo detalhes ("url=/../../etc/passwd status=400")
        url = ""
        for campo in detalhes.split():          # Aula 6 — for
            if campo.startswith("url="):
                url = campo.split("=", 1)[1]

        # Verifica se algum padrao perigoso esta na URL 
        padroes = regra.get("padroes", [])
        if any(padrao in url for padrao in padroes):    
            violou = True
            descricao_extra = "Path traversal detectado na URL: " + url

    elif condicao == "xss":
        # Mesma logica: extrai URL e verifica padroes de XSS
        url = ""
        for campo in detalhes.split():
            if campo.startswith("url="):
                url = campo.split("=", 1)[1]

        padroes = regra.get("padroes", [])
        if any(padrao in url for padrao in padroes):    
            violou = True
            descricao_extra = "Possivel XSS detectado na URL: " + url

    elif condicao == "reconhecimento":
        # Verifica se a URL esta na lista de URLs suspeitas de reconhecimento
        url = ""
        for campo in detalhes.split():
            if campo.startswith("url="):
                url = campo.split("=", 1)[1]

        urls_suspeitas = regra.get("urls_suspeitas", [])
        # Verifica correspondencia exata ou prefixo 
        if any(url == suspeita or url.startswith(suspeita) for suspeita in urls_suspeitas):
            violou = True
            descricao_extra = "Reconhecimento detectado: acesso a " + url

    #Se violou, monta e retorna o alerta 
    if violou:
        severidade = classificar_severidade(regra.get("severidade_base", 0))
        alerta = {
            "timestamp": evento.get("timestamp", ""),
            "regra_id": regra.get("id", ""),
            "regra_nome": regra.get("nome", ""),
            "severidade": severidade,
            "ip": ip,
            "descricao": descricao_extra
        }
        return alerta

    return None     # regra nao foi violada


# APLICAR TODAS AS REGRAS EM TODOS OS EVENTOS

def aplicar_regras(eventos, regras):
    """
    Aplica todas as regras a todos os eventos e retorna os alertas gerados.

    Parametros:
        eventos (list[dict]): lista de eventos normalizados
        regras  (list[dict]): lista de regras ativas

    Retorna:
        list[dict]: todos os alertas gerados.

    """
    alertas = []    # lista que acumula alertas

    for evento in eventos:
        for regra in regras:
            resultado = avaliar_regra(regra, evento)
            if resultado is not None:           #— condicional
                alertas.append(resultado)       #— append

    return alertas


# BLOCO DE TESTE RAPIDO

if __name__ == "__main__":
    # Importa o coletor para ter eventos reais 
    from coletor import carregar_todos_os_logs

    print("=" * 50)
    print("TESTE DO MODULO REGRAS")
    print("=" * 50)

    # Carrega regras
    print("\n[PASSO 1] Carregando regras...")
    regras = carregar_regras("Regras/regras.json")

    # Testa classificacao de severidade
    print("\n[PASSO 2] Testando classificacao de severidade:")
    for pontuacao in (10, 8, 6, 4, 1):
        nivel = classificar_severidade(pontuacao)
        print("  Pontuacao", pontuacao, "->", nivel)

    # Carrega eventos reais
    print("\n[PASSO 3] Carregando logs...")
    eventos = carregar_todos_os_logs("logs")
    print("Total de eventos:", len(eventos))

    # Aplica regras
    print("\n[PASSO 4] Aplicando regras...")
    alertas = aplicar_regras(eventos, regras)
    print("Total de alertas gerados:", len(alertas))

    # Exibe alertas por severidade
    print("\n[PASSO 5] Alertas por severidade:")
    for nivel in ("CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO"):
        filtrados = [a for a in alertas if a["severidade"] == nivel]
        print("  " + nivel + ": " + str(len(filtrados)) + " alerta(s)")

    # Exibe os 5 primeiros alertas
    print("\n[PASSO 6] Primeiros alertas:")
    for alerta in alertas[:5]:
        print(" ", alerta["severidade"], "|", alerta["regra_id"],
              "|", alerta["ip"], "|", alerta["descricao"])
