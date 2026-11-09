# ml/treinar.py
#
# Enunciado: treinar o classificador de risco por IP (ataque / normal) do
# SecuraPy Platform, dentro de um Pipeline (StandardScaler + RandomForest),
# avaliar com validacao cruzada (precisao, recall, F1), salvar o modelo com
# joblib e registrar o hash SHA-256 do arquivo (integridade).
#
# Dados: como os logs reais tem so ~8 IPs, o treino usa um conjunto sintetico
# (seed fixa) gerado por perfis de comportamento, com perfis que se
# sobrepoem e 3% de ruido de rotulo (rotulagem imperfeita do analista). Os logs reais ficam de fora
# do treino e servem de validacao final.
#
# Testes a realizar:
#   python -m ml.treinar
#   C1: relatorio com precisao, recall e F1 impresso
#   C2: 185.220.101.1 -> ataque / risco ALTO
#   C3: 192.168.1.10  -> normal
#   gera ml/modelo.pkl, ml/modelo.sha256 e ml/relatorio_metricas.txt

import os
import hashlib
import joblib
import numpy as np
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.metrics import classification_report, confusion_matrix

from ml.features import FEATURES, extrair_features, para_vetor
from core.coletor import carregar_todos_os_logs

PASTA_ML = os.path.dirname(os.path.abspath(__file__))
CAMINHO_MODELO = os.path.join(PASTA_ML, "modelo.pkl")
CAMINHO_HASH = os.path.join(PASTA_ML, "modelo.sha256")
CAMINHO_RELATORIO = os.path.join(PASTA_ML, "relatorio_metricas.txt")
PASTA_LOGS = os.path.join(os.path.dirname(PASTA_ML), "logs")
BLACKLIST = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}
SEMENTE = 42
RUIDO_ROTULO = 0.03

relatorio = []


def registrar(texto=""):
    print(texto)
    relatorio.append(texto)


def sortear(gerador, minimo, maximo):
    return int(gerador.integers(minimo, maximo + 1))


def gerar_amostra(gerador, perfil):
    if perfil == "brute_force":
        fails = sortear(gerador, 4, 40)
        linha = [fails, sortear(gerador, 1, min(6, fails)), sortear(gerador, 0, 2), sortear(gerador, 0, 3),
                 sortear(gerador, 0, 4), sortear(gerador, 0, 1), int(gerador.random() < 0.6)]
    elif perfil == "port_scan":
        portas = sortear(gerador, 3, 20)
        linha = [sortear(gerador, 0, 3), sortear(gerador, 0, 2), portas, portas + sortear(gerador, 0, 5),
                 sortear(gerador, 0, 2), 0, int(gerador.random() < 0.5)]
    elif perfil == "web_attack":
        linha = [sortear(gerador, 0, 2), sortear(gerador, 0, 1), sortear(gerador, 0, 2), sortear(gerador, 0, 2),
                 sortear(gerador, 2, 12), sortear(gerador, 1, 6), int(gerador.random() < 0.5)]
    elif perfil == "misto":
        portas = sortear(gerador, 2, 8)
        linha = [sortear(gerador, 3, 15), sortear(gerador, 2, 5), portas, portas + sortear(gerador, 0, 3),
                 sortear(gerador, 2, 8), sortear(gerador, 1, 4), int(gerador.random() < 0.8)]
    elif perfil == "baixo_e_lento":
        linha = [sortear(gerador, 1, 3), sortear(gerador, 1, 2), sortear(gerador, 1, 2), sortear(gerador, 1, 2),
                 sortear(gerador, 1, 2), 1, 1]
    elif perfil == "usuario_normal":
        fails = sortear(gerador, 0, 2)
        linha = [fails, min(fails, 1), 0, sortear(gerador, 0, 1), sortear(gerador, 0, 2), 0, 0]
    elif perfil == "esqueceu_senha":
        linha = [sortear(gerador, 3, 8), sortear(gerador, 1, 2), 0, sortear(gerador, 0, 1), sortear(gerador, 0, 1), 0, 0]
    elif perfil == "crawler_legitimo":
        linha = [0, 0, 0, 0, sortear(gerador, 3, 10), sortear(gerador, 0, 1), 0]
    else:
        portas = sortear(gerador, 2, 4)
        linha = [sortear(gerador, 0, 1), sortear(gerador, 0, 1), portas, portas, sortear(gerador, 0, 1), 0, 0]
    return linha


def gerar_dataset(total=800):
    gerador = np.random.default_rng(SEMENTE)
    perfis_ataque = ["brute_force", "port_scan", "web_attack", "misto", "baixo_e_lento"]
    perfis_normais = ["usuario_normal", "esqueceu_senha", "crawler_legitimo", "scan_interno_legitimo"]
    pesos_normais = [0.5, 0.2, 0.15, 0.15]

    X = []
    y = []
    for i in range(total):
        if gerador.random() < 0.4:
            perfil = perfis_ataque[int(gerador.integers(0, len(perfis_ataque)))]
            y.append(1)
        else:
            perfil = str(gerador.choice(perfis_normais, p=pesos_normais))
            y.append(0)
        if gerador.random() < RUIDO_ROTULO:
            y[-1] = 1 - y[-1]
        X.append(gerar_amostra(gerador, perfil))
    return np.array(X), np.array(y)


def montar_pipeline():
    return Pipeline([
        ("scaler", StandardScaler()),
        ("modelo", RandomForestClassifier(n_estimators=150, max_depth=8, class_weight="balanced", random_state=SEMENTE)),
    ])


def calcular_hash(caminho):
    sha = hashlib.sha256()
    with open(caminho, "rb") as arquivo:
        for bloco in iter(lambda: arquivo.read(8192), b""):
            sha.update(bloco)
    return sha.hexdigest()


def avaliar(X, y):
    registrar("=" * 60)
    registrar("AVALIACAO DO MODELO (dados sinteticos, seed " + str(SEMENTE) + ")")
    registrar("=" * 60)
    registrar("Amostras: " + str(len(y)) + " | ataques: " + str(int(y.sum())) + " | normais: " + str(int(len(y) - y.sum())))

    validacao = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEMENTE)
    cv = cross_validate(montar_pipeline(), X, y, cv=validacao, scoring=["precision", "recall", "f1"])
    registrar("")
    registrar("Validacao cruzada estratificada (5 folds):")
    for nome in ["precision", "recall", "f1"]:
        valores = cv["test_" + nome]
        registrar("  " + nome.ljust(10) + ": " + format(valores.mean(), ".3f") + " +/- " + format(valores.std(), ".3f"))

    X_treino, X_teste, y_treino, y_teste = train_test_split(X, y, test_size=0.2, stratify=y, random_state=SEMENTE)
    teste = montar_pipeline()
    teste.fit(X_treino, y_treino)
    previsto = teste.predict(X_teste)
    registrar("")
    registrar("Holdout 80/20:")
    registrar(classification_report(y_teste, previsto, target_names=["normal", "ataque"], digits=3))
    registrar("Matriz de confusao [[VN FP] [FN VP]]:")
    registrar(str(confusion_matrix(y_teste, previsto)))


def treinar_e_salvar(X, y):
    pipeline = montar_pipeline()
    pipeline.fit(X, y)
    joblib.dump(pipeline, CAMINHO_MODELO)
    hash_modelo = calcular_hash(CAMINHO_MODELO)
    with open(CAMINHO_HASH, "w", encoding="utf-8") as arquivo:
        arquivo.write(hash_modelo + "\n")

    registrar("")
    registrar("Importancia das features:")
    importancias = pipeline.named_steps["modelo"].feature_importances_
    ordem = sorted(range(len(FEATURES)), key=lambda i: importancias[i], reverse=True)
    for i in ordem:
        registrar("  " + FEATURES[i].ljust(20) + format(importancias[i], ".3f"))

    registrar("")
    registrar("Modelo salvo em: " + CAMINHO_MODELO)
    registrar("SHA-256: " + hash_modelo)
    return pipeline


def validar_nos_logs_reais(pipeline):
    eventos = carregar_todos_os_logs(PASTA_LOGS)
    if not eventos:
        registrar("[AVISO] Sem logs reais para validar.")
        return

    tabela = extrair_features(eventos, BLACKLIST)
    registrar("")
    registrar("Validacao nos logs reais (fora do treino):")
    ips = sorted(tabela, key=lambda ip: pipeline.predict_proba([para_vetor(tabela[ip])])[0][1], reverse=True)
    for ip in ips:
        probabilidade = pipeline.predict_proba([para_vetor(tabela[ip])])[0][1]
        rotulo = "ataque" if probabilidade >= 0.5 else "normal"
        registrar("  " + ip.ljust(16) + "score=" + format(probabilidade * 100, "5.1f") + "  -> " + rotulo)


def main():
    X, y = gerar_dataset()
    avaliar(X, y)
    pipeline = treinar_e_salvar(X, y)
    validar_nos_logs_reais(pipeline)
    with open(CAMINHO_RELATORIO, "w", encoding="utf-8") as arquivo:
        arquivo.write("\n".join(relatorio) + "\n")
    print("\nRelatorio salvo em:", CAMINHO_RELATORIO)


if __name__ == "__main__":
    main()
