# db/mongo_repo.py
# Repositorio de eventos e alertas no MongoDB.
#
# AVISO: versao provisoria, so pra API (Modulo D) ter o que consultar
# enquanto o Modulo B (Pessoa A) nao entrega a versao final com indices
# e agregacoes. As funcoes abaixo sao as que a API chama:
#   salvar_eventos, salvar_alertas, salvar_alerta,
#   buscar_eventos, buscar_alertas, buscar_alerta_por_id,
#   buscar_eventos_por_ip, buscar_alertas_por_ip

import os
from pymongo import MongoClient
from bson import ObjectId

MONGO_URL = os.environ.get("MONGO_URL", "mongodb://localhost:27017/")

cliente = MongoClient(MONGO_URL)
banco = cliente.securapy


def salvar_eventos(eventos):
    if not eventos:
        return 0
    try:
        resultado = banco.eventos.insert_many(eventos)
        return len(resultado.inserted_ids)
    except Exception as erro:
        print("[ERRO] Falha ao salvar eventos:", str(erro))
        return 0


def salvar_alertas(alertas):
    if not alertas:
        return 0
    try:
        resultado = banco.alertas.insert_many(alertas)
        return len(resultado.inserted_ids)
    except Exception as erro:
        print("[ERRO] Falha ao salvar alertas:", str(erro))
        return 0


def salvar_alerta(alerta):
    try:
        resultado = banco.alertas.insert_one(alerta)
        return str(resultado.inserted_id)
    except Exception as erro:
        print("[ERRO] Falha ao salvar alerta:", str(erro))
        return None


def buscar_eventos(fonte=None, tipo=None, ip=None, pagina=1, tamanho=20):
    filtro = {}
    if fonte:
        filtro["fonte"] = fonte
    if tipo:
        filtro["tipo"] = tipo
    if ip:
        filtro["ip"] = ip

    try:
        pular = (pagina - 1) * tamanho
        cursor = banco.eventos.find(filtro, {"_id": 0}).skip(pular).limit(tamanho)
        return list(cursor)
    except Exception as erro:
        print("[ERRO] Falha ao buscar eventos:", str(erro))
        return []


def buscar_alertas(severidade=None, pagina=1, tamanho=20):
    filtro = {}
    if severidade:
        filtro["severidade"] = severidade.upper()

    try:
        pular = (pagina - 1) * tamanho
        cursor = banco.alertas.find(filtro).skip(pular).limit(tamanho)
        alertas = []
        for doc in cursor:
            doc["id"] = str(doc["_id"])
            del doc["_id"]
            alertas.append(doc)
        return alertas
    except Exception as erro:
        print("[ERRO] Falha ao buscar alertas:", str(erro))
        return []


def buscar_alerta_por_id(alerta_id):
    try:
        doc = banco.alertas.find_one({"_id": ObjectId(alerta_id)})
    except Exception:
        return None

    if doc is None:
        return None

    doc["id"] = str(doc["_id"])
    del doc["_id"]
    return doc


def buscar_eventos_por_ip(ip):
    try:
        return list(banco.eventos.find({"ip": ip}, {"_id": 0}))
    except Exception as erro:
        print("[ERRO] Falha ao buscar eventos do IP:", str(erro))
        return []


def buscar_alertas_por_ip(ip):
    try:
        cursor = banco.alertas.find({"ip": ip})
        alertas = []
        for doc in cursor:
            doc["id"] = str(doc["_id"])
            del doc["_id"]
            alertas.append(doc)
        return alertas
    except Exception as erro:
        print("[ERRO] Falha ao buscar alertas do IP:", str(erro))
        return []
