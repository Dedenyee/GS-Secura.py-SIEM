# tests/test_ml.py
#
# Enunciado: testes automatizados (pytest) do Modulo C - features,
# classificacao, integridade do modelo e fallback.
#
# Testes a realizar:
#   python -m pytest tests/test_ml.py -v

import shutil

from core.coletor import carregar_todos_os_logs
from core.detector import detectar_brute_force, detectar_port_scan, verificar_blacklist, gerar_resumo_ameacas
from ml import classificar
from ml.anomalias import detectar_anomalias
from ml.features import extrair_features

BLACKLIST = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}


def carregar_eventos():
    return carregar_todos_os_logs("logs")


def test_features_do_ip_malicioso():
    tabela = extrair_features(carregar_eventos(), BLACKLIST)
    dados = tabela["185.220.101.1"]
    assert dados["portas_distintas"] == 7
    assert dados["na_blacklist"] == 1
    assert dados["fails_auth"] >= 10


def test_c2_ip_malicioso_e_ataque_alto():
    resultado = classificar.classificar_ip("185.220.101.1", [], carregar_eventos(), BLACKLIST)
    assert resultado["rotulo"] == "ataque"
    assert resultado["nivel_risco"] == "ALTO"
    assert resultado["origem"] == "ml"


def test_c3_ip_interno_e_normal():
    resultado = classificar.classificar_ip("192.168.1.10", [], carregar_eventos(), BLACKLIST)
    assert resultado["rotulo"] == "normal"
    assert resultado["score"] < 50


def test_pontuar_ordena_por_score():
    eventos = carregar_eventos()
    resumo = gerar_resumo_ameacas(
        detectar_brute_force(eventos), detectar_port_scan(eventos), verificar_blacklist(eventos, BLACKLIST)[0]
    )
    pontuado = classificar.pontuar(resumo, eventos, BLACKLIST)
    scores = [item["score"] for item in pontuado]
    assert scores == sorted(scores, reverse=True)
    assert all(item["origem"] == "ml" for item in pontuado)


def test_pontuar_sem_eventos_usa_heuristica():
    pontuado = classificar.pontuar([{"ip": "1.1.1.1", "pontuacao": 7}])
    assert pontuado[0]["origem"] == "heuristica"
    assert pontuado[0]["rotulo"] == "ataque"


def test_c4_hash_confere():
    assert classificar.verificar_integridade() is True


def test_c4_modelo_adulterado_e_recusado(tmp_path):
    modelo = tmp_path / "modelo.pkl"
    hash_arquivo = tmp_path / "modelo.sha256"
    shutil.copy(classificar.CAMINHO_MODELO, modelo)
    shutil.copy(classificar.CAMINHO_HASH, hash_arquivo)
    with open(modelo, "ab") as arquivo:
        arquivo.write(b"x")
    assert classificar.verificar_integridade(str(modelo), str(hash_arquivo)) is False
    assert classificar.carregar_modelo(True, str(modelo), str(hash_arquivo)) is None
    classificar.carregar_modelo(True)


def test_modelo_ausente_cai_em_fallback(tmp_path):
    assert classificar.carregar_modelo(True, str(tmp_path / "nao_existe.pkl"), str(tmp_path / "nao_existe.sha256")) is None
    classificar.carregar_modelo(True)


def test_anomalias_aponta_ip_atacante():
    resultado = detectar_anomalias(carregar_eventos())
    assert resultado["185.220.101.1"]["anomalo"] is True
    assert resultado["192.168.1.10"]["anomalo"] is False
