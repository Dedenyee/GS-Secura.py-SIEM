"""
core/enriquecimento.py — Enriquecimento de IPs via ipinfo.io (1º semestre, melhorado)

Melhorias em relacao ao 1º semestre:
- valida o IP com o modulo ipaddress antes de qualquer consulta
- token opcional via variavel de ambiente IPINFO_TOKEN (nunca no codigo)
- erros de rede nunca sao cacheados como definitivos
"""

import ipaddress
import os

import requests

URL_IPINFO = "https://ipinfo.io/{ip}/json"
TIMEOUT = 5


def _desconhecido(ip):
    return {"ip": ip, "privado": False, "cidade": "Desconhecido", "regiao": "Desconhecido",
            "pais": "Desconhecido", "org": "Desconhecido", "hostname": "Desconhecido"}


def eh_ip_valido(ip):
    try:
        ipaddress.IPv4Address(str(ip))
        return True
    except ValueError:
        return False


def eh_ip_privado(ip):
    """True para 10/8, 172.16/12, 192.168/16 e 127/8."""
    try:
        octetos = [int(x) for x in str(ip).split(".")]
    except ValueError:
        return False
    if len(octetos) != 4 or any(o < 0 or o > 255 for o in octetos):
        return False
    a, b = octetos[0], octetos[1]
    return (a == 10 or a == 127 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168))


def consultar_ip(ip, cache):
    """Consulta ipinfo.io com cache. Nunca levanta excecao de rede."""
    if ip in cache:
        return cache[ip]

    if eh_ip_privado(ip):
        resultado = {"ip": ip, "privado": True, "cidade": "Rede Interna", "regiao": "Rede Interna",
                     "pais": "Rede Interna", "org": "Rede Interna", "hostname": "-"}
        cache[ip] = resultado
        return resultado

    if not eh_ip_valido(ip):
        return _desconhecido(ip)

    headers = {}
    token = os.environ.get("IPINFO_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        resposta = requests.get(URL_IPINFO.format(ip=ip), timeout=TIMEOUT, headers=headers)
        if resposta.status_code != 200:
            return _desconhecido(ip)
        dados = resposta.json()
    except (requests.exceptions.RequestException, ValueError):
        return _desconhecido(ip)

    resultado = {
        "ip": ip,
        "privado": False,
        "cidade": dados.get("city", "Desconhecido"),
        "regiao": dados.get("region", "Desconhecido"),
        "pais": dados.get("country", "Desconhecido"),
        "org": dados.get("org", "Desconhecido"),
        "hostname": dados.get("hostname", "Desconhecido"),
    }
    cache[ip] = resultado
    return resultado


def enriquecer_alertas(alertas, cache):
    """Adiciona 'geolocalizacao' a cada alerta, consultando cada IP unico uma vez."""
    if not alertas:
        return []
    ips_unicos = {a.get("ip") for a in alertas}
    geo = {ip: consultar_ip(ip, cache) for ip in ips_unicos}
    for alerta in alertas:
        alerta["geolocalizacao"] = geo[alerta.get("ip")]
    return alertas


def exibir_enriquecimento(dados_ip):
    tipo = "Privado (rede interna)" if dados_ip.get("privado") else "Publico"
    print(f"{'IP:':<12} {dados_ip.get('ip')}")
    print(f"{'Tipo:':<12} {tipo}")
    print(f"{'Cidade:':<12} {dados_ip.get('cidade')}")
    print(f"{'Regiao:':<12} {dados_ip.get('regiao')}")
    print(f"{'Pais:':<12} {dados_ip.get('pais')}")
    print(f"{'Org:':<12} {dados_ip.get('org')}")
