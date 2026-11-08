"""
scripts/migrar_logs.py — Ingestao inicial: logs -> nucleo -> MongoDB (Modulo B, req. 3)

Uso (na raiz do projeto):
    python -m scripts.migrar_logs              # usa ./logs e config/regras.json
    python -m scripts.migrar_logs --limpar     # apaga as colecoes antes
    python -m scripts.migrar_logs --pasta outra/

Roda o MESMO fluxo do POST /api/analisar (nucleo do 1º semestre) e grava
eventos, alertas e o resumo de ameacas. Eh idempotente: rodar 2x nao duplica.
"""

import argparse
import sys

from core.coletor import carregar_todos_os_logs
from core.detector import detectar_brute_force, detectar_port_scan, gerar_resumo_ameacas, verificar_blacklist
from core.regras import aplicar_regras, carregar_regras
from db import mongo_repo

PASTA_LOGS = "logs"
ARQUIVO_REGRAS = "config/regras.json"
BLACKLIST = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}


def migrar(pasta_logs=PASTA_LOGS, arquivo_regras=ARQUIVO_REGRAS, limpar=False, db=None):
    db = db if db is not None else mongo_repo.obter_db()
    if limpar:
        mongo_repo.limpar_tudo(db=db)

    eventos = carregar_todos_os_logs(pasta_logs)
    alertas = aplicar_regras(eventos, carregar_regras(arquivo_regras))
    ips_blacklist, _ = verificar_blacklist(eventos, BLACKLIST)
    ameacas = gerar_resumo_ameacas(detectar_brute_force(eventos), detectar_port_scan(eventos), ips_blacklist)

    return {
        "eventos_lidos": len(eventos),
        "eventos_novos": mongo_repo.salvar_eventos(eventos, db=db),
        "alertas_gerados": len(alertas),
        "alertas_novos": mongo_repo.salvar_alertas(alertas, db=db),
        "ameacas": mongo_repo.salvar_ameacas(ameacas, db=db),
        "total_no_banco": db.eventos.count_documents({}),
        "por_fonte": mongo_repo.contagem_por_fonte(db=db),
        "top5_ips": mongo_repo.top_ips(5, db=db),
        "alertas_por_severidade": mongo_repo.contagem_por_severidade(db=db),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Ingestao dos logs no MongoDB")
    parser.add_argument("--pasta", default=PASTA_LOGS)
    parser.add_argument("--regras", default=ARQUIVO_REGRAS)
    parser.add_argument("--limpar", action="store_true", help="apaga eventos/alertas/ameacas antes")
    args = parser.parse_args(argv)

    try:
        resumo = migrar(args.pasta, args.regras, args.limpar)
    except mongo_repo.MongoRepoErro as erro:
        print(f"[ERRO] {erro}. Verifique MONGO_URL e se o MongoDB esta rodando.")
        return 1

    print("\n=== Ingestao concluida ===")
    print(f"Eventos lidos dos logs : {resumo['eventos_lidos']}")
    print(f"Eventos novos no banco : {resumo['eventos_novos']}")
    print(f"Total de eventos no BD : {resumo['total_no_banco']}  {resumo['por_fonte']}")
    print(f"Alertas gerados/novos  : {resumo['alertas_gerados']}/{resumo['alertas_novos']}")
    print(f"Alertas por severidade : {resumo['alertas_por_severidade']}")
    print(f"Ameacas (IPs)          : {resumo['ameacas']}")
    print("Top 5 IPs por eventos  :")
    for posicao, item in enumerate(resumo["top5_ips"], start=1):
        print(f"  {posicao}. {item['ip']:<16} {item['total']} eventos")
    return 0


if __name__ == "__main__":
    sys.exit(main())
