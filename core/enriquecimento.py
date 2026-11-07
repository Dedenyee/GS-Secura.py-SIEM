"""
Módulo 5 — Enriquecimento de IPs (enriquecimento.py)
Consulta a API ipinfo.io para obter geolocalização e dados de threat intelligence.
"""

import requests


# ---------------------------------------------------------------------------
# 1. Classificação de IP privado (RFC 1918)
# ---------------------------------------------------------------------------

def eh_ip_privado(ip: str) -> bool:
    """
    Verifica se um IP é de rede privada (RFC 1918).
    Retorna True para 10.x.x.x, 172.16-31.x.x, 192.168.x.x
    Também retorna True para loopback (127.x.x.x).
    """
    try:
        partes = ip.strip().split(".")
        if len(partes) != 4:
            return False
        octetos = [int(p) for p in partes]

        # Validação básica de range
        if not all(0 <= o <= 255 for o in octetos):
            return False

        a, b = octetos[0], octetos[1]

        if a == 10:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
        if a == 127:
            return True

        return False

    except (ValueError, AttributeError):
        return False


# ---------------------------------------------------------------------------
# 2. Consulta à API ipinfo.io com cache
# ---------------------------------------------------------------------------

def consultar_ip(ip: str, cache: dict) -> dict:
    """
    Consulta ipinfo.io para obter dados do IP.
    Usa cache (dict) para evitar consultas repetidas.
    Retorna dict com: ip, cidade, regiao, pais, org, hostname.
    """
    # Retorno padrão em caso de erro
    dados_vazios = {
        "ip": ip,
        "cidade": "Desconhecido",
        "regiao": "Desconhecido",
        "pais": "Desconhecido",
        "org": "Desconhecido",
        "hostname": "Desconhecido",
    }

    # IP privado — não consultar externamente
    if eh_ip_privado(ip):
        return {
            "ip": ip,
            "cidade": "Rede Interna",
            "regiao": "Rede Interna",
            "pais": "Rede Interna",
            "org": "Rede Interna",
            "hostname": "Rede Interna",
        }

    # Cache hit — busca O(1)
    if ip in cache:
        return cache[ip]

    # Consulta à API
    try:
        url = f"https://ipinfo.io/{ip}/json"
        resposta = requests.get(url, timeout=5)

        if resposta.status_code == 200:
            dados_json = resposta.json()
            dados = {
                "ip": dados_json.get("ip", ip),
                "cidade": dados_json.get("city", "Desconhecido"),
                "regiao": dados_json.get("region", "Desconhecido"),
                "pais": dados_json.get("country", "Desconhecido"),
                "org": dados_json.get("org", "Desconhecido"),
                "hostname": dados_json.get("hostname", "Desconhecido"),
            }
            cache[ip] = dados
            return dados

        elif resposta.status_code == 429:
            print(f"  [!] Limite de requisições atingido para {ip} (429). Tente mais tarde.")
            return dados_vazios

        else:
            print(f"  [!] Erro na API para {ip}: status {resposta.status_code}")
            return dados_vazios

    except requests.exceptions.ConnectionError:
        print(f"  [!] Sem conexão com a internet ao consultar {ip}.")
        return dados_vazios
    except requests.exceptions.Timeout:
        print(f"  [!] Timeout ao consultar {ip}.")
        return dados_vazios
    except requests.exceptions.HTTPError as e:
        print(f"  [!] Erro HTTP ao consultar {ip}: {e}")
        return dados_vazios
    except Exception as e:
        print(f"  [!] Erro inesperado ao consultar {ip}: {e}")
        return dados_vazios


# ---------------------------------------------------------------------------
# 3. Enriquecimento em lote de alertas
# ---------------------------------------------------------------------------

def enriquecer_alertas(alertas: list, cache: dict) -> list:
    """
    Recebe lista de alertas e adiciona informações de geolocalização.
    Pula IPs privados (marca como 'Rede Interna').
    Retorna alertas enriquecidos.
    """
    alertas_enriquecidos = []

    for alerta in alertas:
        ip = alerta.get("ip", "")
        dados_ip = consultar_ip(ip, cache)

        alerta_enriquecido = dict(alerta)
        alerta_enriquecido["geo"] = dados_ip
        alertas_enriquecidos.append(alerta_enriquecido)

    return alertas_enriquecidos


# ---------------------------------------------------------------------------
# 4. Exibição formatada dos dados de um IP
# ---------------------------------------------------------------------------

def exibir_enriquecimento(dados_ip: dict) -> None:
    """Exibe as informações do IP de forma formatada."""
    print("\n" + "=" * 45)
    print(f"  Dados de Enriquecimento — IP: {dados_ip.get('ip', 'N/A')}")
    print("=" * 45)
    print(f"  {'Cidade':<12}: {dados_ip.get('cidade', 'N/A')}")
    print(f"  {'Região':<12}: {dados_ip.get('regiao', 'N/A')}")
    print(f"  {'País':<12}: {dados_ip.get('pais', 'N/A')}")
    print(f"  {'Organização':<12}: {dados_ip.get('org', 'N/A')}")
    print(f"  {'Hostname':<12}: {dados_ip.get('hostname', 'N/A')}")
    print("=" * 45)


# ---------------------------------------------------------------------------
# 5. Enriquecimento de lista de IPs únicos (para o menu)
# ---------------------------------------------------------------------------

def enriquecer_ips_suspeitos(eventos: list, cache: dict) -> list:
    """
    Extrai IPs únicos dos eventos, consulta a API e retorna lista de resultados.
    Usado pela opção 7 do menu principal.
    """
    ips_vistos = set()
    resultados = []

    for evento in eventos:
        ip = evento.get("ip", "")
        if ip and ip not in ips_vistos:
            ips_vistos.add(ip)
            dados = consultar_ip(ip, cache)
            resultados.append(dados)

    return resultados
