# ml/classificar.py
#
# Enunciado: carregar o modelo treinado (verificando o hash SHA-256 antes de
# deserializar) e atribuir a cada IP um score de risco (0-100), um rotulo
# (ataque/normal) e um nivel (BAIXO/MEDIO/ALTO), usado para ordenar alertas.
# Se o modelo estiver ausente, adulterado ou ilegivel, cai na heuristica por
# severidade (a API nunca quebra).
#
# Interface usada pela API (api/app.py):
#   pontuar(resumo_ameacas, eventos=None, blacklist=None)
#   classificar_ip(ip, alertas_do_ip, eventos_do_ip=None, blacklist=None)
#
# Testes a realizar:
#   python -m ml.classificar
#   C2: 185.220.101.1 -> ataque / ALTO
#   C3: 192.168.1.10  -> normal
#   C4: hash confere; modelo adulterado -> [ALERTA] e heuristica

import os
import hashlib
import joblib

from ml.features import extrair_features, para_vetor

PASTA_ML = os.path.dirname(os.path.abspath(__file__))
CAMINHO_MODELO = os.path.join(PASTA_ML, "modelo.pkl")
CAMINHO_HASH = os.path.join(PASTA_ML, "modelo.sha256")
LIMIAR_ATAQUE = 50
LIMIAR_ALTO = 70
PESOS_SEVERIDADE = {"CRITICA": 4, "ALTA": 3, "MEDIA": 2, "BAIXA": 1, "INFO": 0}

cache = {"modelo": None}


def calcular_hash(caminho):
    sha = hashlib.sha256()
    with open(caminho, "rb") as arquivo:
        for bloco in iter(lambda: arquivo.read(8192), b""):
            sha.update(bloco)
    return sha.hexdigest()


def verificar_integridade(caminho_modelo=CAMINHO_MODELO, caminho_hash=CAMINHO_HASH):
    try:
        with open(caminho_hash, "r", encoding="utf-8") as arquivo:
            hash_esperado = arquivo.read().strip()
        hash_atual = calcular_hash(caminho_modelo)
    except FileNotFoundError:
        print("[ALERTA] Modelo ou arquivo de hash nao encontrado. Rode: python -m ml.treinar")
        return False
    except OSError as erro:
        print("[ALERTA] Falha ao ler modelo/hash:", type(erro).__name__)
        return False

    if hash_atual != hash_esperado:
        print("[ALERTA] Hash do modelo NAO confere - possivel adulteracao. Modelo nao sera carregado.")
        print("         esperado:", hash_esperado)
        print("         atual   :", hash_atual)
        return False

    print("[OK] Integridade do modelo verificada (SHA-256 confere).")
    return True


def carregar_modelo(forcar=False, caminho_modelo=CAMINHO_MODELO, caminho_hash=CAMINHO_HASH):
    if cache["modelo"] is not None and not forcar:
        return cache["modelo"]

    cache["modelo"] = None
    if not verificar_integridade(caminho_modelo, caminho_hash):
        return None

    try:
        cache["modelo"] = joblib.load(caminho_modelo)
    except Exception as erro:
        print("[ALERTA] Modelo nao pode ser carregado:", type(erro).__name__)
        return None
    return cache["modelo"]


def nivel_do_score(score):
    if score >= LIMIAR_ALTO:
        return "ALTO"
    if score >= LIMIAR_ATAQUE:
        return "MEDIO"
    return "BAIXO"


def montar_resultado(score, origem):
    score = round(float(score), 1)
    rotulo = "ataque" if score >= LIMIAR_ATAQUE else "normal"
    return {"score": score, "rotulo": rotulo, "nivel_risco": nivel_do_score(score), "origem": origem}


def score_modelo(modelo, features_ip):
    probabilidade = modelo.predict_proba([para_vetor(features_ip)])[0][1]
    return probabilidade * 100


def score_heuristico(pontuacao):
    return min(pontuacao * 10, 100)


def pontuar(resumo_ameacas, eventos=None, blacklist=None):
    modelo = carregar_modelo() if eventos else None
    tabela = extrair_features(eventos, blacklist) if modelo is not None else {}

    resumo_pontuado = []
    for item in resumo_ameacas:
        ip = item.get("ip", "")
        if modelo is not None and ip in tabela:
            resultado = montar_resultado(score_modelo(modelo, tabela[ip]), "ml")
        else:
            resultado = montar_resultado(score_heuristico(item.get("pontuacao", 0)), "heuristica")

        item_pontuado = dict(item)
        item_pontuado.update(resultado)
        resumo_pontuado.append(item_pontuado)

    resumo_pontuado.sort(key=lambda x: x["score"], reverse=True)
    return resumo_pontuado


def classificar_ip(ip, alertas_do_ip, eventos_do_ip=None, blacklist=None):
    modelo = carregar_modelo() if eventos_do_ip else None

    if modelo is not None:
        tabela = extrair_features(eventos_do_ip, blacklist)
        features_ip = tabela.get(ip)
        if features_ip is not None:
            resultado = montar_resultado(score_modelo(modelo, features_ip), "ml")
            resultado["ip"] = ip
            return resultado

    pontuacao = 0
    for alerta in alertas_do_ip:
        pontuacao += PESOS_SEVERIDADE.get(alerta.get("severidade", "INFO"), 0)
    resultado = montar_resultado(score_heuristico(pontuacao), "heuristica")
    resultado["ip"] = ip
    return resultado


if __name__ == "__main__":
    import shutil
    import tempfile
    from core.coletor import carregar_todos_os_logs

    BLACKLIST_TESTE = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}
    eventos = carregar_todos_os_logs("logs")

    print("\n[C4] Verificando integridade do modelo...")
    print("Hash confere?", verificar_integridade())

    print("\n[C2] 185.220.101.1 (brute force + port scan + blacklist)")
    print(classificar_ip("185.220.101.1", [], eventos, BLACKLIST_TESTE))

    print("\n[C3] 192.168.1.10 (trafego interno normal)")
    print(classificar_ip("192.168.1.10", [], eventos, BLACKLIST_TESTE))

    print("\n[C4] Simulando modelo adulterado...")
    pasta_temp = tempfile.mkdtemp()
    modelo_copia = os.path.join(pasta_temp, "modelo.pkl")
    hash_copia = os.path.join(pasta_temp, "modelo.sha256")
    shutil.copy(CAMINHO_MODELO, modelo_copia)
    shutil.copy(CAMINHO_HASH, hash_copia)
    with open(modelo_copia, "ab") as arquivo:
        arquivo.write(b"adulterado")
    print("Hash confere?", verificar_integridade(modelo_copia, hash_copia))
    shutil.rmtree(pasta_temp)
