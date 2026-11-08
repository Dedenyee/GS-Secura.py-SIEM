"""
db/mongo_repo.py — Eventos, alertas e ameacas no MongoDB
Modulo B da GS — baseado nas Aulas 1, 2 e 7 da apostila do 2º semestre.

Por que MongoDB aqui (Aula 1.3/1.4): eventos e alertas tem alto volume e
schema flexivel (cada fonte de log traz campos diferentes). Pelo Teorema CAP
(Aula 1.5), coleta de logs pode priorizar disponibilidade.

Colecoes (banco -> colecoes -> documentos, Aula 2.1):
    eventos  — eventos normalizados do coletor (1º semestre)
    alertas  — alertas do motor de regras (e os criados via API)
    ameacas  — resumo por IP do detector (+ score de ML, quando houver)

O que vem de cada aula:
    - Conexao com MongoClient + ping, string em variavel de ambiente (Aula 2.2)
    - CRUD: insert_many, insert_one, find, find_one, update_one, delete_many,
      count_documents (Aula 2.3)
    - Indices simples, compostos e TTL (Aula 2.4)
    - Aggregation pipeline $match -> $group -> $sort -> $limit (Aula 2.5)
    - Filtro montado dinamicamente so com os parametros informados (Exerc. 2.3)
    - Paginacao com skip/limit e serializacao de ObjectId (Aula 7.2)
    - ObjectId invalido tratado com InvalidId (Aula 7.2)

Decisoes extras:
    - Ingestao IDEMPOTENTE: cada evento/alerta recebe uma "chave" SHA-256
      (hashlib, 1º sem.) com indice unico. Rodar a migracao 2x NAO duplica.
    - "timestamp" eh gravado como datetime (filtro por periodo funciona) e
      devolvido como string "AAAA-MM-DD HH:MM:SS" (mesmo contrato do nucleo).
    - Filtros so aceitam texto simples: {"$ne": ""} vindo da API eh rejeitado
      (NoSQL injection — a "SQL injection" do MongoDB, OWASP A05).
    - Variaveis de ambiente: MONGO_URL (ou MONGO_URI), MONGO_DB, MONGO_TTL_DIAS.
"""

import hashlib
import os
from datetime import datetime, timedelta, timezone

from bson import ObjectId
from bson.errors import InvalidId
from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.errors import BulkWriteError, DuplicateKeyError, PyMongoError

FORMATO_TS = "%Y-%m-%d %H:%M:%S"
SEVERIDADES = ("CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO")
FONTES = ("auth", "firewall", "web")
TAMANHO_MAXIMO_PAGINA = 100

_cliente = None
_db = None


class MongoRepoErro(Exception):
    """Erro de persistencia no MongoDB (mensagem segura para exibir)."""


class FiltroInvalidoError(MongoRepoErro):
    """Parametro de busca com tipo/valor invalido."""


# ============================================================
# Conexao e indices
# ============================================================

def conectar(uri=None, nome_db=None, cliente=None):
    """Abre (ou injeta) a conexao e garante os indices. Retorna o Database.

    `cliente` permite injetar um mongomock.MongoClient nos testes.
    """
    global _cliente, _db
    # MONGO_URL eh o nome usado no docker-compose.yml do time; MONGO_URI tambem funciona
    uri = uri or os.environ.get("MONGO_URL") or os.environ.get("MONGO_URI", "mongodb://localhost:27017")
    nome_db = nome_db or os.environ.get("MONGO_DB", "securapy")
    try:
        _cliente = cliente or MongoClient(uri, serverSelectionTimeoutMS=3000)
        _cliente.admin.command("ping")
    except PyMongoError as erro:
        _cliente, _db = None, None
        raise MongoRepoErro("MongoDB indisponivel") from erro
    _db = _cliente[nome_db]
    criar_indices(_db)
    return _db


def obter_db():
    if _db is None:
        return conectar()
    return _db


def _resolver(db):
    return db if db is not None else obter_db()


def criar_indices(db=None):
    """Indices em ip e timestamp (consultas mais comuns) + chave unica de deduplicacao."""
    db = _resolver(db)
    for nome in ("eventos", "alertas"):
        col = db[nome]
        col.create_index([("ip", ASCENDING)], name="idx_ip")
        col.create_index([("timestamp", DESCENDING)], name="idx_timestamp")
        col.create_index([("ip", ASCENDING), ("timestamp", DESCENDING)], name="idx_ip_timestamp")
        col.create_index([("chave", ASCENDING)], name="uniq_chave", unique=True)
    db.eventos.create_index([("fonte", ASCENDING), ("tipo", ASCENDING)], name="idx_fonte_tipo")
    db.alertas.create_index([("severidade", ASCENDING)], name="idx_severidade")
    db.ameacas.create_index([("ip", ASCENDING)], name="uniq_ip", unique=True)

    # TTL opcional (Aula 2, secao 2.4): expira eventos X dias apos a INGESTAO.
    # Usa "ingerido_em" e nao "timestamp" porque os logs de teste sao antigos.
    ttl_dias = os.environ.get("MONGO_TTL_DIAS")
    if ttl_dias and ttl_dias.isdigit() and int(ttl_dias) > 0:
        db.eventos.create_index([("ingerido_em", ASCENDING)], name="ttl_ingestao",
                                expireAfterSeconds=int(ttl_dias) * 86400)


def fechar():
    global _cliente, _db
    if _cliente is not None:
        _cliente.close()
    _cliente, _db = None, None


# ============================================================
# Conversoes (contrato do nucleo <-> documento Mongo)
# ============================================================

def _para_datetime(valor):
    if isinstance(valor, datetime):
        return valor
    try:
        return datetime.strptime(str(valor), FORMATO_TS)
    except (TypeError, ValueError):
        return None


def _chave(*partes):
    return hashlib.sha256("|".join(str(p) for p in partes).encode()).hexdigest()


def _chave_evento(evento):
    return _chave("evento", evento.get("fonte"), evento.get("linha_original")
                  or f"{evento.get('timestamp')} {evento.get('tipo')} {evento.get('ip')} {evento.get('detalhes')}")


def _chave_alerta(alerta):
    return _chave("alerta", alerta.get("regra_id"), alerta.get("ip"),
                  alerta.get("timestamp"), alerta.get("descricao"))


def _doc_para_dict(doc):
    """Documento Mongo -> dict serializavel (id string, timestamp string)."""
    if doc is None:
        return None
    saida = {k: v for k, v in doc.items() if k not in ("_id", "chave")}
    saida["id"] = str(doc["_id"])
    for campo in ("timestamp", "ingerido_em", "atualizado_em"):
        if isinstance(saida.get(campo), datetime):
            saida[campo] = saida[campo].strftime(FORMATO_TS)
    return saida


def _texto(valor, nome):
    """Aceita apenas string simples (bloqueia {"$gt": ""} e afins)."""
    if valor is None or valor == "":
        return None
    if not isinstance(valor, str) or valor.startswith("$"):
        raise FiltroInvalidoError(f"Filtro '{nome}' invalido")
    return valor.strip()


def _paginacao(pagina, tamanho):
    try:
        pagina, tamanho = int(pagina), int(tamanho)
    except (TypeError, ValueError):
        raise FiltroInvalidoError("pagina e tamanho devem ser inteiros")
    if pagina < 1 or tamanho < 1:
        raise FiltroInvalidoError("pagina e tamanho devem ser >= 1")
    return pagina, min(tamanho, TAMANHO_MAXIMO_PAGINA)


def _upsert_lote(colecao, documentos):
    """Insere em lote ignorando os que ja existem (pela chave). Retorna qtd nova."""
    if not documentos:
        return 0
    try:
        # ordered=False: continua inserindo mesmo se alguns ja existirem
        return len(colecao.insert_many(documentos, ordered=False).inserted_ids)
    except BulkWriteError as erro:
        erros = erro.details.get("writeErrors", [])
        if any(e.get("code") != 11000 for e in erros):   # 11000 = chave duplicada (ok)
            raise MongoRepoErro("Falha ao gravar no MongoDB") from erro
        return erro.details.get("nInserted", len(documentos) - len(erros))
    except PyMongoError as erro:
        raise MongoRepoErro("Falha ao gravar no MongoDB") from erro


# ============================================================
# Escrita
# ============================================================

def salvar_eventos(eventos, db=None):
    """Persiste eventos do coletor. Retorna quantos eram novos."""
    db = _resolver(db)
    agora = datetime.now(timezone.utc).replace(tzinfo=None)
    documentos = []
    for evento in eventos or []:
        ts = _para_datetime(evento.get("timestamp"))
        if ts is None or not evento.get("ip"):
            print(f"[AVISO] Evento ignorado (timestamp/ip invalido): {evento!r:.80}")
            continue
        doc = dict(evento)
        doc["timestamp"] = ts
        doc["ingerido_em"] = agora
        doc["chave"] = _chave_evento(evento)
        documentos.append(doc)
    return _upsert_lote(db.eventos, documentos)


def _preparar_alerta(alerta):
    doc = dict(alerta)
    doc.pop("id", None)
    ts = _para_datetime(alerta.get("timestamp"))
    doc["timestamp"] = ts or datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
    doc["chave"] = _chave_alerta({**alerta, "timestamp": doc["timestamp"].strftime(FORMATO_TS)})
    return doc


def salvar_alertas(alertas, db=None):
    """Persiste alertas do motor de regras. Retorna quantos eram novos."""
    db = _resolver(db)
    return _upsert_lote(db.alertas, [_preparar_alerta(a) for a in alertas or []])


def salvar_alerta(alerta, db=None):
    """Grava UM alerta (uso da API POST /api/alertas). Retorna o id (str).

    Se um alerta identico ja existir, retorna o id do existente.
    """
    db = _resolver(db)
    doc = _preparar_alerta(alerta)
    try:
        return str(db.alertas.insert_one(doc).inserted_id)
    except DuplicateKeyError:
        return str(db.alertas.find_one({"chave": doc["chave"]}, {"_id": 1})["_id"])
    except PyMongoError as erro:
        raise MongoRepoErro("Falha ao gravar alerta") from erro


def salvar_ameacas(ameacas, db=None):
    """Upsert do resumo de ameacas por IP (o ML pode completar com 'score_risco')."""
    db = _resolver(db)
    agora = datetime.now(timezone.utc).replace(tzinfo=None)
    total = 0
    try:
        for ameaca in ameacas or []:
            # set nao eh serializavel no BSON -> vira lista ordenada
            dados = {k: (sorted(v) if isinstance(v, (set, frozenset)) else v)
                     for k, v in ameaca.items() if k != "id"}
            dados["atualizado_em"] = agora
            db.ameacas.update_one({"ip": ameaca["ip"]}, {"$set": dados}, upsert=True)
            total += 1
    except PyMongoError as erro:
        raise MongoRepoErro("Falha ao gravar ameacas") from erro
    return total


def atualizar_score_ip(ip, score, rotulo=None, db=None):
    """Gancho para o Modulo C (ML) gravar o score de risco de um IP."""
    db = _resolver(db)
    campos = {"score_risco": float(score)}
    if rotulo is not None:
        campos["rotulo_ml"] = str(rotulo)
    db.ameacas.update_one({"ip": _texto(ip, "ip")}, {"$set": campos}, upsert=True)


# ============================================================
# Leitura com filtros
# ============================================================

def _filtro_periodo(inicio, fim):
    periodo = {}
    if inicio:
        dt = _para_datetime(inicio)
        if dt is None:
            raise FiltroInvalidoError("inicio deve ter formato AAAA-MM-DD HH:MM:SS")
        periodo["$gte"] = dt
    if fim:
        dt = _para_datetime(fim)
        if dt is None:
            raise FiltroInvalidoError("fim deve ter formato AAAA-MM-DD HH:MM:SS")
        periodo["$lte"] = dt
    return periodo


def buscar_eventos_paginado(fonte=None, tipo=None, ip=None, inicio=None, fim=None,
                            pagina=1, tamanho=20, db=None):
    """Busca eventos com filtros + paginacao.

    Retorna {"total": N, "pagina": p, "tamanho": t, "itens": [...]}.
    """
    db = _resolver(db)
    pagina, tamanho = _paginacao(pagina, tamanho)
    filtro = {}
    fonte = _texto(fonte, "fonte")
    if fonte:
        if fonte not in FONTES:
            raise FiltroInvalidoError(f"fonte deve ser uma de {FONTES}")
        filtro["fonte"] = fonte
    tipo = _texto(tipo, "tipo")
    if tipo:
        filtro["tipo"] = tipo.upper()
    ip = _texto(ip, "ip")
    if ip:
        filtro["ip"] = ip
    periodo = _filtro_periodo(inicio, fim)
    if periodo:
        filtro["timestamp"] = periodo

    try:
        total = db.eventos.count_documents(filtro)
        cursor = (db.eventos.find(filtro).sort([("timestamp", ASCENDING), ("_id", ASCENDING)])
                  .skip((pagina - 1) * tamanho).limit(tamanho))
        itens = [_doc_para_dict(d) for d in cursor]
    except PyMongoError as erro:
        raise MongoRepoErro("Falha ao consultar eventos") from erro
    return {"total": total, "pagina": pagina, "tamanho": tamanho, "itens": itens}


def buscar_alertas_paginado(severidade=None, ip=None, regra_id=None, inicio=None, fim=None,
                            pagina=1, tamanho=20, db=None):
    """Busca alertas com filtros + paginacao (mais recentes primeiro)."""
    db = _resolver(db)
    pagina, tamanho = _paginacao(pagina, tamanho)
    filtro = {}
    severidade = _texto(severidade, "severidade")
    if severidade:
        # aceita "critica"/"CRITICA"/"crítica"
        sev = severidade.upper().replace("Í", "I")
        if sev not in SEVERIDADES:
            raise FiltroInvalidoError(f"severidade deve ser uma de {SEVERIDADES}")
        filtro["severidade"] = sev
    ip = _texto(ip, "ip")
    if ip:
        filtro["ip"] = ip
    regra_id = _texto(regra_id, "regra_id")
    if regra_id:
        filtro["regra_id"] = regra_id.upper()
    periodo = _filtro_periodo(inicio, fim)
    if periodo:
        filtro["timestamp"] = periodo

    try:
        total = db.alertas.count_documents(filtro)
        cursor = (db.alertas.find(filtro).sort([("timestamp", DESCENDING), ("_id", ASCENDING)])
                  .skip((pagina - 1) * tamanho).limit(tamanho))
        itens = [_doc_para_dict(d) for d in cursor]
    except PyMongoError as erro:
        raise MongoRepoErro("Falha ao consultar alertas") from erro
    return {"total": total, "pagina": pagina, "tamanho": tamanho, "itens": itens}


def buscar_eventos(fonte=None, tipo=None, ip=None, inicio=None, fim=None,
                   pagina=1, tamanho=20, db=None):
    """Mesma busca, devolvendo so a LISTA de eventos (contrato usado pela API)."""
    return buscar_eventos_paginado(fonte, tipo, ip, inicio, fim, pagina, tamanho, db)["itens"]


def buscar_alertas(severidade=None, ip=None, regra_id=None, inicio=None, fim=None,
                   pagina=1, tamanho=20, db=None):
    """Mesma busca, devolvendo so a LISTA de alertas (contrato usado pela API)."""
    return buscar_alertas_paginado(severidade, ip, regra_id, inicio, fim, pagina, tamanho, db)["itens"]


def buscar_eventos_por_ip(ip, db=None):
    """Todos os eventos de um IP em ordem cronologica (GET /api/ip/<ip>)."""
    db = _resolver(db)
    try:
        return [_doc_para_dict(d) for d in db.eventos.find({"ip": _texto(ip, "ip")}).sort("timestamp", ASCENDING)]
    except PyMongoError as erro:
        raise MongoRepoErro("Falha ao consultar eventos do IP") from erro


def buscar_alertas_por_ip(ip, db=None):
    """Todos os alertas de um IP em ordem cronologica (GET /api/ip/<ip>)."""
    db = _resolver(db)
    try:
        return [_doc_para_dict(d) for d in db.alertas.find({"ip": _texto(ip, "ip")}).sort("timestamp", ASCENDING)]
    except PyMongoError as erro:
        raise MongoRepoErro("Falha ao consultar alertas do IP") from erro


def buscar_alerta_por_id(alerta_id, db=None):
    """Retorna o alerta ou None (id malformado tambem -> None, nunca excecao)."""
    db = _resolver(db)
    try:
        oid = ObjectId(str(alerta_id))
    except (InvalidId, TypeError):
        return None
    return _doc_para_dict(db.alertas.find_one({"_id": oid}))


def buscar_ameaca_por_ip(ip, db=None):
    db = _resolver(db)
    return _doc_para_dict(db.ameacas.find_one({"ip": _texto(ip, "ip")}))


def listar_ameacas(limite=50, db=None):
    db = _resolver(db)
    cursor = db.ameacas.find().sort([("pontuacao", DESCENDING), ("ip", ASCENDING)]).limit(int(limite))
    return [_doc_para_dict(d) for d in cursor]


def resumo_ip(ip, db=None):
    """Tudo que o banco sabe de um IP (base para GET /api/ip/<ip>)."""
    db = _resolver(db)
    ip = _texto(ip, "ip")
    eventos = buscar_eventos_por_ip(ip, db=db)
    alertas = buscar_alertas_por_ip(ip, db=db)
    return {
        "ip": ip,
        "total_eventos": len(eventos),
        "total_alertas": len(alertas),
        "eventos": eventos,
        "alertas": alertas,
        "ameaca": buscar_ameaca_por_ip(ip, db=db),
    }


def consultar(fonte=None, tipo=None, ip=None, desde=None, db=None):
    """Exercicio 2.3 da apostila: filtro dinamico, so com os parametros != None,
    resultado ordenado por timestamp.

        consultar(tipo="FAIL", ip="185.220.101.1")  -> so as falhas desse IP
        consultar(fonte="auth")                     -> todos os eventos de auth
    """
    db = _resolver(db)
    filtro = {}
    if fonte is not None:
        filtro["fonte"] = _texto(fonte, "fonte")
    if tipo is not None:
        filtro["tipo"] = _texto(tipo, "tipo").upper()
    if ip is not None:
        filtro["ip"] = _texto(ip, "ip")
    if desde is not None:
        inicio = _para_datetime(desde)
        if inicio is None:
            raise FiltroInvalidoError("desde deve ter formato AAAA-MM-DD HH:MM:SS")
        filtro["timestamp"] = {"$gte": inicio}
    return [_doc_para_dict(d) for d in db.eventos.find(filtro).sort("timestamp", ASCENDING)]


# ============================================================
# Agregacoes (Aula 2.5 — aggregation pipeline)
# ============================================================

def top_ips_por_falhas(limite=5, db=None):
    """Exercicio 2.2 da apostila: IPs com mais falhas de login.

    Pipeline: $match tipo=FAIL -> $group por ip -> $sort desc -> $limit
    (equivale a SELECT ip, COUNT(*) ... WHERE tipo='FAIL' GROUP BY ip ORDER BY ... LIMIT)
    """
    db = _resolver(db)
    pipeline = [
        {"$match": {"fonte": "auth", "tipo": "FAIL"}},
        {"$group": {"_id": "$ip", "total": {"$sum": 1}}},
        {"$sort": {"total": -1, "_id": 1}},
        {"$limit": int(limite)},
    ]
    try:
        return [{"ip": linha["_id"], "total": linha["total"]} for linha in db.eventos.aggregate(pipeline)]
    except PyMongoError as erro:
        raise MongoRepoErro("Falha na agregacao de falhas") from erro


def top_ips(limite=5, colecao="eventos", db=None):
    """Top N IPs por quantidade de documentos. Retorna [{"ip":..., "total":...}]."""
    db = _resolver(db)
    if colecao not in ("eventos", "alertas"):
        raise FiltroInvalidoError("colecao deve ser 'eventos' ou 'alertas'")
    pipeline = [
        {"$group": {"_id": "$ip", "total": {"$sum": 1}}},
        {"$sort": {"total": -1, "_id": 1}},
        {"$limit": int(limite)},
    ]
    try:
        return [{"ip": d["_id"], "total": d["total"]} for d in db[colecao].aggregate(pipeline)]
    except PyMongoError as erro:
        raise MongoRepoErro("Falha na agregacao top_ips") from erro


def contagem_por_severidade(db=None):
    """{"CRITICA": n, "ALTA": n, ...} (sempre com as 5 chaves)."""
    db = _resolver(db)
    pipeline = [{"$group": {"_id": "$severidade", "total": {"$sum": 1}}}]
    contagem = dict.fromkeys(SEVERIDADES, 0)
    for d in db.alertas.aggregate(pipeline):
        contagem[d["_id"]] = d["total"]
    return contagem


def contagem_por_fonte(db=None):
    """{"auth": n, "firewall": n, "web": n} — usado no dashboard."""
    db = _resolver(db)
    pipeline = [{"$group": {"_id": "$fonte", "total": {"$sum": 1}}}]
    contagem = dict.fromkeys(FONTES, 0)
    for d in db.eventos.aggregate(pipeline):
        contagem[d["_id"]] = d["total"]
    return contagem


def contagem_por_tipo(fonte=None, db=None):
    db = _resolver(db)
    pipeline = []
    fonte = _texto(fonte, "fonte")
    if fonte:
        pipeline.append({"$match": {"fonte": fonte}})
    pipeline += [{"$group": {"_id": "$tipo", "total": {"$sum": 1}}}, {"$sort": {"total": -1}}]
    return {d["_id"]: d["total"] for d in db.eventos.aggregate(pipeline)}


def estatisticas(db=None):
    """Resumo geral para dashboard / relatorio."""
    db = _resolver(db)
    return {
        "total_eventos": db.eventos.count_documents({}),
        "total_alertas": db.alertas.count_documents({}),
        "eventos_por_fonte": contagem_por_fonte(db=db),
        "alertas_por_severidade": contagem_por_severidade(db=db),
        "top_ips": top_ips(10, db=db),
    }


def limpar_tudo(db=None):
    """Apaga eventos, alertas e ameacas (usado pela migracao com --limpar e nos testes)."""
    db = _resolver(db)
    for nome in ("eventos", "alertas", "ameacas"):
        db[nome].delete_many({})
