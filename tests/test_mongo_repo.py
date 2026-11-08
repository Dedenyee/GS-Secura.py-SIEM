"""Testes do db/mongo_repo.py com MongoDB simulado (mongomock).

Usa uma amostra fixa dos logs (independente do nucleo) para testar
ingestao, idempotencia, filtros, paginacao, agregacoes e o contrato da API.
"""

import mongomock
import pytest

from db import mongo_repo


def _ev(ts, fonte, tipo, ip, detalhes):
    return {"timestamp": f"2025-02-20 {ts}", "fonte": fonte, "tipo": tipo, "ip": ip,
            "detalhes": detalhes, "linha_original": f"2025-02-20 {ts} {tipo} {detalhes} ip={ip}"}


EVENTOS = (
    [_ev(f"08:15:{i:02d}", "auth", "FAIL", "185.220.101.1", "usuario=admin") for i in range(11)]
    + [_ev(f"08:15:{20 + i:02d}", "auth", "FAIL", "91.240.118.172", "usuario=root") for i in range(5)]
    + [_ev("08:15:40", "auth", "OK", "192.168.1.10", "usuario=carlos")]
    + [_ev(f"08:10:{i:02d}", "firewall", "BLOCK", "185.220.101.1", f"proto=TCP dst=10.0.0.1 dport={p}")
       for i, p in enumerate([21, 22, 23, 139, 445, 3306, 8080])]
    + [_ev("08:20:08", "web", "GET", "91.240.118.172", "url=/../../etc/passwd status=400")]
)
ALERTAS = [
    {"timestamp": "2025-02-20 08:20:08", "regra_id": "R003", "regra_nome": "Tentativa de Path Traversal",
     "severidade": "CRITICA", "ip": "91.240.118.172", "descricao": "URL: /../../etc/passwd"},
    {"timestamp": "2025-02-20 08:10:01", "regra_id": "R002", "regra_nome": "Porta Critica",
     "severidade": "ALTA", "ip": "185.220.101.1", "descricao": "dport=22"},
]


@pytest.fixture
def db():
    banco = mongo_repo.conectar(cliente=mongomock.MongoClient(), nome_db="securapy_teste")
    yield banco
    mongo_repo.fechar()


@pytest.fixture
def db_populado(db):
    mongo_repo.salvar_eventos(EVENTOS, db=db)
    mongo_repo.salvar_alertas(ALERTAS, db=db)
    return db


def test_ingestao_conta_todos(db):
    assert mongo_repo.salvar_eventos(EVENTOS, db=db) == len(EVENTOS)
    assert db.eventos.count_documents({}) == len(EVENTOS)


def test_ingestao_idempotente(db_populado):
    assert mongo_repo.salvar_eventos(EVENTOS, db=db_populado) == 0
    assert mongo_repo.salvar_alertas(ALERTAS, db=db_populado) == 0
    assert db_populado.eventos.count_documents({}) == len(EVENTOS)


def test_top_ips_185_no_topo(db_populado):
    top = mongo_repo.top_ips(5, db=db_populado)
    assert top[0] == {"ip": "185.220.101.1", "total": 18}


def test_indices_criados(db):
    assert {"idx_ip", "idx_timestamp", "uniq_chave"} <= set(db.eventos.index_information())


def test_filtros_e_paginacao(db_populado):
    r = mongo_repo.buscar_eventos_paginado(fonte="auth", tipo="fail", ip="185.220.101.1", tamanho=5, db=db_populado)
    assert r["total"] == 11 and len(r["itens"]) == 5
    p2 = mongo_repo.buscar_eventos_paginado(fonte="auth", tipo="fail", ip="185.220.101.1",
                                            pagina=2, tamanho=5, db=db_populado)
    assert {e["id"] for e in r["itens"]}.isdisjoint({e["id"] for e in p2["itens"]})


def test_filtro_periodo(db_populado):
    r = mongo_repo.buscar_eventos_paginado(inicio="2025-02-20 08:10:00", fim="2025-02-20 08:10:59", db=db_populado)
    assert r["total"] == 7


def test_contagens(db_populado):
    assert mongo_repo.contagem_por_fonte(db=db_populado) == {"auth": 17, "firewall": 7, "web": 1}
    assert mongo_repo.contagem_por_severidade(db=db_populado)["CRITICA"] == 1


def test_contrato_da_api(db_populado):
    """Funcoes chamadas por api/app.py: devolvem listas / None, como a versao provisoria."""
    eventos = mongo_repo.buscar_eventos(fonte="firewall", pagina=1, tamanho=5, db=db_populado)
    assert isinstance(eventos, list) and len(eventos) == 5
    alertas = mongo_repo.buscar_alertas(severidade="critica", pagina=1, tamanho=5, db=db_populado)
    assert [a["severidade"] for a in alertas] == ["CRITICA"]
    assert len(mongo_repo.buscar_eventos_por_ip("185.220.101.1", db=db_populado)) == 18
    assert len(mongo_repo.buscar_alertas_por_ip("185.220.101.1", db=db_populado)) == 1
    novo_id = mongo_repo.salvar_alerta({"ip": "1.2.3.4", "severidade": "ALTA",
                                        "descricao": "<script>alert(1)</script>"}, db=db_populado)
    assert mongo_repo.buscar_alerta_por_id(novo_id, db=db_populado)["descricao"] == "<script>alert(1)</script>"
    assert mongo_repo.buscar_alerta_por_id("abc", db=db_populado) is None


def test_bloqueia_nosql_injection(db):
    with pytest.raises(mongo_repo.FiltroInvalidoError):
        mongo_repo.buscar_eventos(ip={"$ne": ""}, db=db)
    with pytest.raises(mongo_repo.FiltroInvalidoError):
        mongo_repo.buscar_eventos(fonte="banco", db=db)


def test_ameacas_e_score_ml(db):
    mongo_repo.salvar_ameacas([{"ip": "185.220.101.1", "motivos": ["Brute Force"], "pontuacao": 9,
                                "portas": {22, 23}}], db=db)
    mongo_repo.atualizar_score_ip("185.220.101.1", 0.97, "ataque", db=db)
    ameaca = mongo_repo.buscar_ameaca_por_ip("185.220.101.1", db=db)
    assert ameaca["score_risco"] == 0.97 and ameaca["portas"] == [22, 23]


def test_mongo_indisponivel_erro_tratado():
    with pytest.raises(mongo_repo.MongoRepoErro):
        mongo_repo.conectar(uri="mongodb://127.0.0.1:1/?serverSelectionTimeoutMS=200")
