# verificar_containers.py — Modulo F
# Confere se os 3 servicos do docker-compose (api, mongo, mysql) estao
# rodando, usando o SDK docker-py.
#
# Como testar:
#   1. docker-compose up -d
#   2. python verificar_containers.py
#
# Saida esperada (exemplo):
# securapy_api_1       running
# securapy_mongo_1     running
# securapy_mysql_1     running
# Total: 3 | Rodando: 3 | Parados: 0

import docker

SERVICOS_ESPERADOS = ("api", "mongo", "mysql")


def verificar_containers():
    cliente = docker.from_env()

    try:
        containers = cliente.containers.list(all=True)
    except Exception as erro:
        print("[ERRO] Falha ao conectar no Docker:", str(erro))
        return

    rodando = 0
    parados = 0
    for container in containers:
        nome_bate = any(servico in container.name for servico in SERVICOS_ESPERADOS)
        if not nome_bate:
            continue

        if container.status == "running":
            rodando += 1
            print("{:<25}{}".format(container.name, container.status))
        else:
            parados += 1
            print("{:<25}{:<12}<- ATENCAO".format(container.name, container.status))

    print("\nTotal: {} | Rodando: {} | Parados: {}".format(rodando + parados, rodando, parados))


verificar_containers()
