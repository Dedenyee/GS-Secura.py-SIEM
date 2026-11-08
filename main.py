"""
main.py — Demonstracao do Nucleo (Modulo A) + Persistencia (Modulo B)

    python main.py                 # roda o nucleo e mostra A1-A4 (sem banco)
    python main.py --persistir     # tambem grava no MongoDB (precisa MONGO_URI)
    python main.py --servidor      # sobe o servidor de alertas e transmite os CRITICOS/ALTOS

Para ver os alertas chegando em tempo real, abra 2 terminais com:
    python -m alertas.cliente_alertas
"""

import argparse
import time

from alertas import servidor_alertas
from core.pipeline import processar_logs


def exibir_resultado(r):
    eventos = r["eventos"]
    fontes = {}
    for e in eventos:
        fontes[e["fonte"]] = fontes.get(e["fonte"], 0) + 1
    print(f"\n[A1] {len(eventos)} eventos carregados por fonte: {fontes}")

    bf = r["brute_force"].get("185.220.101.1")
    if bf:
        print(f"[A2] Brute force 185.220.101.1: {bf['tentativas']} FAILs ({bf['severidade']}) "
              f"usuarios={bf['usuarios']}")

    ps = r["port_scan"].get("185.220.101.1")
    if ps:
        print(f"[A3] Port scan 185.220.101.1: {ps['quantidade']} portas distintas {sorted(ps['portas'])}")

    print(f"[A4] IPs da blacklist encontrados nos logs: {r['blacklist']}")
    print(f"\nAlertas das regras: {len(r['alertas'])}")
    print("Ameacas consolidadas:")
    for a in r["ameacas"]:
        print(f"  {a['ip']:<16} {a['severidade']:<8} pts={a['pontuacao']:<3} {a['deteccoes']}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--persistir", action="store_true")
    parser.add_argument("--servidor", action="store_true")
    args = parser.parse_args()

    resultado = processar_logs()
    exibir_resultado(resultado)

    if args.persistir:
        from scripts.migrar_logs import migrar
        from db.mongo_repo import MongoRepoErro
        try:
            resumo = migrar()
            print(f"\n[B1] MongoDB: {resumo['total_no_banco']} eventos {resumo['por_fonte']}")
            print(f"[B2] Top 5 IPs: {resumo['top5_ips']}")
        except MongoRepoErro as erro:
            print(f"\n[ERRO] {erro} — siga sem persistencia.")

    if args.servidor:
        servidor_alertas.iniciar_em_background()
        print("\nConecte os consoles (python -m alertas.cliente_alertas). Enviando em 10s...")
        time.sleep(10)
        importantes = [a for a in resultado["alertas"] if a["severidade"] in ("CRITICA", "ALTA")]
        for alerta in importantes:
            servidor_alertas.broadcast_alerta(alerta)
            time.sleep(0.3)
        print(f"{len(importantes)} alertas transmitidos. Ctrl+C para sair.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
