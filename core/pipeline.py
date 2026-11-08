"""
core/pipeline.py — Orquestra o nucleo do 1º semestre numa unica chamada.

    resultado = processar_logs("logs", "config/regras.json")
    resultado["eventos"], resultado["alertas"], resultado["ameacas"]

Eh o ponto de entrada que a migracao (db) e a rota POST /api/analisar (API)
devem usar, para todos rodarem exatamente o mesmo fluxo.
"""

import os

from core import coletor, detector, regras

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASTA_LOGS_PADRAO = os.path.join(RAIZ, "logs")
REGRAS_PADRAO = os.path.join(RAIZ, "config", "regras.json")


def analisar_eventos(eventos, caminho_regras=REGRAS_PADRAO, blacklist=detector.BLACKLIST_PADRAO):
    """Roda regras + detector sobre uma lista de eventos ja normalizados."""
    lista_regras = regras.carregar_regras(caminho_regras)
    alertas = regras.aplicar_regras(eventos, lista_regras)

    brute = detector.detectar_brute_force(eventos)
    scan = detector.detectar_port_scan(eventos)
    bl = detector.verificar_blacklist(eventos, blacklist)
    ameacas = detector.gerar_resumo_ameacas(brute, scan, bl)

    return {
        "eventos": eventos,
        "alertas": alertas,
        "ameacas": ameacas,
        "brute_force": brute,
        "port_scan": scan,
        "blacklist": sorted(bl[0]),
        "brute_force_janela": detector.detectar_brute_force_janela(eventos),
    }


def processar_logs(pasta_logs=PASTA_LOGS_PADRAO, caminho_regras=REGRAS_PADRAO,
                   blacklist=detector.BLACKLIST_PADRAO):
    """Le os logs da pasta e roda o fluxo completo do nucleo."""
    eventos = coletor.carregar_todos_os_logs(pasta_logs)
    return analisar_eventos(eventos, caminho_regras, blacklist)
