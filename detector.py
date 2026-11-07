"""
Módulo 3 — Detecção de Anomalias e Ataques (detector.py)
SecuraPy SIEM
"""


def detectar_brute_force(eventos, threshold=5):
    contagem = {}

    for evento in eventos:
        if evento["fonte"] != "auth":
            continue
        if evento["tipo"] != "FAIL":
            continue

        ip = evento["ip"]
        detalhes = evento["detalhes"]

        usuario = "desconhecido"
        partes = detalhes.split()
        for parte in partes:
            if parte.startswith("usuario="):
                usuario = parte.split("=")[1]

        if ip not in contagem:
            contagem[ip] = {"tentativas": 0, "usuarios": []}

        contagem[ip]["tentativas"] += 1
        if usuario not in contagem[ip]["usuarios"]:
            contagem[ip]["usuarios"].append(usuario)

    resultado = {}
    for ip in contagem:
        tentativas = contagem[ip]["tentativas"]
        if tentativas >= threshold:
            if tentativas > 20:
                severidade = "CRITICA"
            elif tentativas > 10:
                severidade = "ALTA"
            elif tentativas > 5:
                severidade = "MEDIA"
            else:
                severidade = "BAIXA"

            resultado[ip] = {
                "tentativas": tentativas,
                "usuarios": contagem[ip]["usuarios"],
                "severidade": severidade,
            }

    return resultado


def detectar_port_scan(eventos, threshold=3):
    portas_por_ip = {}

    for evento in eventos:
        if evento["fonte"] != "firewall":
            continue
        if evento["tipo"] != "BLOCK":
            continue

        ip = evento["ip"]
        detalhes = evento["detalhes"]

        porta = None
        partes = detalhes.split()
        for parte in partes:
            if parte.startswith("dport="):
                numero = parte.split("=")[1]
                porta = int(numero)

        if porta is None:
            continue

        if ip not in portas_por_ip:
            portas_por_ip[ip] = set()
        portas_por_ip[ip].add(porta)

    resultado = {}
    for ip in portas_por_ip:
        quantidade = len(portas_por_ip[ip])
        if quantidade >= threshold:
            if quantidade > 10:
                severidade = "CRITICA"
            elif quantidade > 6:
                severidade = "ALTA"
            elif quantidade > 3:
                severidade = "MEDIA"
            else:
                severidade = "BAIXA"

            resultado[ip] = {
                "portas": portas_por_ip[ip],
                "quantidade": quantidade,
                "severidade": severidade,
            }

    return resultado


def verificar_blacklist(eventos, blacklist):
    ips_nos_logs = set()
    for evento in eventos:
        ips_nos_logs.add(evento["ip"])

    ips_encontrados = ips_nos_logs & blacklist

    contagem_por_ip = {}
    for evento in eventos:
        ip = evento["ip"]
        if ip in ips_encontrados:
            if ip not in contagem_por_ip:
                contagem_por_ip[ip] = 0
            contagem_por_ip[ip] += 1

    return ips_encontrados, contagem_por_ip


def gerar_resumo_ameacas(brute_force, port_scan, ips_blacklist):
    todos_ips = set()
    for ip in brute_force:
        todos_ips.add(ip)
    for ip in port_scan:
        todos_ips.add(ip)
    for ip in ips_blacklist:
        todos_ips.add(ip)

    resumo = []
    for ip in todos_ips:
        motivos = []
        pontuacao = 0

        if ip in brute_force:
            dados = brute_force[ip]
            tentativas = dados["tentativas"]
            usuarios = ", ".join(dados["usuarios"])
            severidade = dados["severidade"]
            motivos.append(
                "Brute Force [" + severidade + "]: " + str(tentativas)
                + " tentativas (usuarios: " + usuarios + ")"
            )
            if severidade == "CRITICA":
                pontuacao += 4
            elif severidade == "ALTA":
                pontuacao += 3
            elif severidade == "MEDIA":
                pontuacao += 2
            else:
                pontuacao += 1

        if ip in port_scan:
            dados = port_scan[ip]
            quantidade = dados["quantidade"]
            severidade = dados["severidade"]
            lista_portas = [str(porta) for porta in sorted(dados["portas"])]
            portas_str = ", ".join(lista_portas)
            motivos.append(
                "Port Scan [" + severidade + "]: " + str(quantidade)
                + " portas (" + portas_str + ")"
            )
            if severidade == "CRITICA":
                pontuacao += 4
            elif severidade == "ALTA":
                pontuacao += 3
            elif severidade == "MEDIA":
                pontuacao += 2
            else:
                pontuacao += 1

        if ip in ips_blacklist:
            motivos.append("IP encontrado na Blacklist")
            pontuacao += 3

        if pontuacao >= 9:
            severidade_final = "CRITICA"
        elif pontuacao >= 6:
            severidade_final = "ALTA"
        elif pontuacao >= 4:
            severidade_final = "MEDIA"
        elif pontuacao >= 2:
            severidade_final = "BAIXA"
        else:
            severidade_final = "INFO"

        resumo.append({
            "ip": ip,
            "motivos": motivos,
            "pontuacao": pontuacao,
            "severidade": severidade_final,
        })

    resumo.sort(key=lambda x: x["pontuacao"], reverse=True)
    return resumo


if __name__ == "__main__":
    eventos_teste = []

    for i in range(11):
        eventos_teste.append({
            "fonte": "auth",
            "tipo": "FAIL",
            "ip": "185.220.101.1",
            "detalhes": "usuario=admin",
            "timestamp": "2025-02-20 08:15:01",
            "linha_original": ""
        })

    for i in range(6):
        eventos_teste.append({
            "fonte": "auth",
            "tipo": "FAIL",
            "ip": "91.240.118.172",
            "detalhes": "usuario=root",
            "timestamp": "2025-02-20 08:15:02",
            "linha_original": ""
        })

    portas_teste = [22, 23, 445, 3306, 8080, 21, 139]
    for porta in portas_teste:
        eventos_teste.append({
            "fonte": "firewall",
            "tipo": "BLOCK",
            "ip": "185.220.101.1",
            "detalhes": "proto=TCP dport=" + str(porta),
            "timestamp": "2025-02-20 08:10:01",
            "linha_original": ""
        })

    BLACKLIST_TESTE = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}

    bf = detectar_brute_force(eventos_teste)
    for ip in bf:
        print("IP:", ip, "| Tentativas:", bf[ip]["tentativas"], "| Severidade:", bf[ip]["severidade"])

    ps = detectar_port_scan(eventos_teste)
    for ip in ps:
        print("IP:", ip, "| Portas:", ps[ip]["quantidade"], "| Severidade:", ps[ip]["severidade"])

    ips_bl, contagem = verificar_blacklist(eventos_teste, BLACKLIST_TESTE)
    print("IPs maliciosos encontrados:", ips_bl)

    resumo = gerar_resumo_ameacas(bf, ps, ips_bl)
    for item in resumo:
        print("IP:", item["ip"], "| Severidade:", item["severidade"], "| Pontuacao:", item["pontuacao"])
        for motivo in item["motivos"]:
            print(" -", motivo)
