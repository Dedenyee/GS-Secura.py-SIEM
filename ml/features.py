# ml/features.py
#
# Enunciado: extrair, a partir da lista unificada de eventos do coletor,
# as features numericas de cada IP que alimentam o classificador (Modulo C).
#
# Features por IP:
#   fails_auth, usuarios_distintos, portas_distintas, bloqueios_fw,
#   erros_web, web_suspeitos, na_blacklist
#
# Testes a realizar:
#   python -m ml.features
#   185.220.101.1 deve aparecer com fails altos, 7 portas e na_blacklist = 1

FEATURES = [
    "fails_auth",
    "usuarios_distintos",
    "portas_distintas",
    "bloqueios_fw",
    "erros_web",
    "web_suspeitos",
    "na_blacklist",
]

MARCADORES_WEB = ("../", "<script", "wp-admin", "phpmyadmin", "shell", "etc/passwd", "union", "cmd=")


def pegar_campo(detalhes, chave):
    for parte in detalhes.split():
        if parte.startswith(chave + "="):
            return parte.split("=", 1)[1]
    return ""


def features_vazias():
    return {
        "fails_auth": 0,
        "usuarios_distintos": set(),
        "portas_distintas": set(),
        "bloqueios_fw": 0,
        "erros_web": 0,
        "web_suspeitos": 0,
        "na_blacklist": 0,
    }


def extrair_features(eventos, blacklist=None):
    if blacklist is None:
        blacklist = set()

    por_ip = {}
    for evento in eventos:
        ip = evento.get("ip", "")
        if not ip:
            continue
        if ip not in por_ip:
            por_ip[ip] = features_vazias()
        dados = por_ip[ip]
        fonte = evento.get("fonte")
        tipo = evento.get("tipo")
        detalhes = evento.get("detalhes", "")

        if fonte == "auth" and tipo == "FAIL":
            dados["fails_auth"] += 1
            dados["usuarios_distintos"].add(pegar_campo(detalhes, "usuario"))
        elif fonte == "firewall" and tipo == "BLOCK":
            dados["bloqueios_fw"] += 1
            porta = pegar_campo(detalhes, "dport")
            if porta.isdigit():
                dados["portas_distintas"].add(int(porta))
        elif fonte == "web":
            status = pegar_campo(detalhes, "status")
            if status.isdigit() and int(status) >= 400:
                dados["erros_web"] += 1
            url = pegar_campo(detalhes, "url").lower()
            for marcador in MARCADORES_WEB:
                if marcador in url:
                    dados["web_suspeitos"] += 1
                    break

    resultado = {}
    for ip in por_ip:
        dados = por_ip[ip]
        resultado[ip] = {
            "fails_auth": dados["fails_auth"],
            "usuarios_distintos": len(dados["usuarios_distintos"]),
            "portas_distintas": len(dados["portas_distintas"]),
            "bloqueios_fw": dados["bloqueios_fw"],
            "erros_web": dados["erros_web"],
            "web_suspeitos": dados["web_suspeitos"],
            "na_blacklist": 1 if ip in blacklist else 0,
        }
    return resultado


def para_vetor(features_ip):
    return [features_ip.get(nome, 0) for nome in FEATURES]


if __name__ == "__main__":
    from core.coletor import carregar_todos_os_logs

    BLACKLIST_TESTE = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}
    eventos = carregar_todos_os_logs("logs")
    tabela = extrair_features(eventos, BLACKLIST_TESTE)
    for ip in sorted(tabela):
        print(ip, tabela[ip])
