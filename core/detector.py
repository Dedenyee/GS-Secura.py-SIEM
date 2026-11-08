"""
core/detector.py — Detector de Ataques (reaproveitado do 1º semestre)

Correlaciona eventos para encontrar:
- Brute force  (dict de contagem + set de usuarios)
- Port scan    (set de portas distintas por IP)
- Blacklist    (intersecao de sets)
+ Bonus: brute force em janela de tempo (correlacao temporal).
"""

from datetime import datetime, timedelta

from core.regras import classificar_severidade, extrair_campo

BLACKLIST_PADRAO = frozenset({"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"})
PONTOS_POR_DETECCAO = 5
FORMATO_TS = "%Y-%m-%d %H:%M:%S"


def _severidade_brute_force(tentativas):
    if tentativas > 20:
        return "CRITICA"
    if tentativas > 10:
        return "ALTA"
    if tentativas > 5:
        return "MEDIA"
    return "BAIXA"


def detectar_brute_force(eventos, threshold=5):
    """{ip: {"tentativas": N, "usuarios": [...], "severidade": ...}} para IPs >= threshold."""
    contagem = {}
    usuarios = {}
    for evento in eventos or []:
        if evento.get("fonte") != "auth" or evento.get("tipo") != "FAIL":
            continue
        ip = evento.get("ip")
        contagem[ip] = contagem.get(ip, 0) + 1
        usuarios.setdefault(ip, set()).add(extrair_campo(evento.get("detalhes", ""), "usuario"))

    return {
        ip: {
            "tentativas": total,
            "usuarios": sorted(u for u in usuarios[ip] if u),
            "severidade": _severidade_brute_force(total),
        }
        for ip, total in contagem.items()
        if total >= threshold
    }


def detectar_brute_force_janela(eventos, threshold=5, janela_segundos=60):
    """Bonus: brute force so conta se >= threshold FAILs dentro de uma janela de tempo.

    Retorna {ip: {"max_na_janela": N, "inicio": ts, "fim": ts, "severidade": ...}}.
    """
    tempos = {}
    for evento in eventos or []:
        if evento.get("fonte") != "auth" or evento.get("tipo") != "FAIL":
            continue
        try:
            ts = datetime.strptime(evento.get("timestamp", ""), FORMATO_TS)
        except ValueError:
            continue
        tempos.setdefault(evento.get("ip"), []).append(ts)

    janela = timedelta(seconds=janela_segundos)
    resultado = {}
    for ip, lista in tempos.items():
        lista.sort()
        melhor, ini, fim, esquerda = 0, None, None, 0
        for direita, ts in enumerate(lista):
            while ts - lista[esquerda] > janela:
                esquerda += 1
            qtd = direita - esquerda + 1
            if qtd > melhor:
                melhor, ini, fim = qtd, lista[esquerda], ts
        if melhor >= threshold:
            resultado[ip] = {
                "max_na_janela": melhor,
                "inicio": ini.strftime(FORMATO_TS),
                "fim": fim.strftime(FORMATO_TS),
                "severidade": _severidade_brute_force(melhor),
            }
    return resultado


def detectar_port_scan(eventos, threshold=3):
    """{ip: {"portas": set, "quantidade": N, "severidade": ...}} para IPs com >= threshold portas."""
    portas_por_ip = {}
    for evento in eventos or []:
        if evento.get("fonte") != "firewall" or evento.get("tipo") != "BLOCK":
            continue
        porta = extrair_campo(evento.get("detalhes", ""), "dport")
        if not porta or not porta.isdigit():
            continue
        portas_por_ip.setdefault(evento.get("ip"), set()).add(int(porta))

    resultado = {}
    for ip, portas in portas_por_ip.items():
        qtd = len(portas)
        if qtd < threshold:
            continue
        if qtd > 10:
            sev = "CRITICA"
        elif qtd > 5:
            sev = "ALTA"
        else:
            sev = "MEDIA"
        resultado[ip] = {"portas": portas, "quantidade": qtd, "severidade": sev}
    return resultado


def verificar_blacklist(eventos, blacklist=BLACKLIST_PADRAO):
    """Retorna (ips_encontrados: set, contagem_por_ip: dict)."""
    blacklist = set(blacklist)
    ips_eventos = {e.get("ip") for e in eventos or []}
    encontrados = ips_eventos & blacklist
    contagem = {}
    for evento in eventos or []:
        ip = evento.get("ip")
        if ip in encontrados:
            contagem[ip] = contagem.get(ip, 0) + 1
    return encontrados, contagem


def gerar_resumo_ameacas(brute_force, port_scan, blacklist_resultado):
    """Consolida as deteccoes em lista de ameacas ordenada por pontuacao.

    blacklist_resultado pode ser a tupla (set, dict) de verificar_blacklist()
    ou so o set de IPs (forma usada por api/app.py).
    """
    if isinstance(blacklist_resultado, tuple):
        bl_ips, bl_contagem = blacklist_resultado
    else:
        bl_ips, bl_contagem = set(blacklist_resultado or ()), {}
    todos_ips = set(brute_force) | set(port_scan) | set(bl_ips)

    ameacas = []
    for ip in todos_ips:
        deteccoes = []
        detalhes = {}
        if ip in brute_force:
            deteccoes.append("brute_force")
            detalhes["brute_force"] = {
                "tentativas": brute_force[ip]["tentativas"],
                "usuarios": list(brute_force[ip]["usuarios"]),
            }
        if ip in port_scan:
            deteccoes.append("port_scan")
            detalhes["port_scan"] = {
                "quantidade": port_scan[ip]["quantidade"],
                "portas": sorted(port_scan[ip]["portas"]),
            }
        if ip in bl_ips:
            deteccoes.append("blacklist")
            detalhes["blacklist"] = {"eventos": bl_contagem.get(ip, 0)}

        pontuacao = PONTOS_POR_DETECCAO * len(deteccoes)
        ameacas.append({
            "ip": ip,
            "deteccoes": deteccoes,
            "pontuacao": pontuacao,
            "severidade": classificar_severidade(pontuacao),
            "detalhes": detalhes,
        })

    return sorted(ameacas, key=lambda a: (-a["pontuacao"], a["ip"]))
