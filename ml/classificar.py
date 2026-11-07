# ml/classificar.py
# Classificador de risco por IP.
#
# AVISO: versao provisoria (heuristica simples baseada na severidade),
# so pra API ter um "score de ML" pra expor enquanto o Modulo C
# (Pessoa B) nao entrega o modelo treinado de verdade.

PESOS_SEVERIDADE = {"CRITICA": 4, "ALTA": 3, "MEDIA": 2, "BAIXA": 1, "INFO": 0}


def pontuar(resumo_ameacas):
    resumo_pontuado = []
    for item in resumo_ameacas:
        pontuacao = item.get("pontuacao", 0)
        score = min(pontuacao * 10, 100)
        rotulo = "ataque" if score >= 50 else "normal"

        item_pontuado = dict(item)
        item_pontuado["score"] = score
        item_pontuado["rotulo"] = rotulo
        resumo_pontuado.append(item_pontuado)

    return resumo_pontuado


def classificar_ip(ip, alertas_do_ip):
    pontuacao = 0
    for alerta in alertas_do_ip:
        severidade = alerta.get("severidade", "INFO")
        pontuacao += PESOS_SEVERIDADE.get(severidade, 0)

    score = min(pontuacao * 10, 100)
    rotulo = "ataque" if score >= 50 else "normal"

    return {"ip": ip, "score": score, "rotulo": rotulo}
