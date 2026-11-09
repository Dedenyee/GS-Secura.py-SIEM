# ml/anomalias.py
#
# Enunciado (bonus): detectar IPs com padrao de trafego incomum usando
# Isolation Forest sobre as metricas de trafego de cada IP, sem depender de
# rotulos. Complementa o classificador supervisionado e as regras fixas,
# apontando comportamento fora do padrao do conjunto analisado.
#
# Testes a realizar:
#   python -m ml.anomalias
#   185.220.101.1 deve aparecer como anomalo; IPs internos como normais

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from ml.features import FEATURES, extrair_features, para_vetor

METRICAS_TRAFEGO = [nome for nome in FEATURES if nome != "na_blacklist"]


def detectar_anomalias(eventos, contaminacao=0.3):
    tabela = extrair_features(eventos)
    ips = sorted(tabela)
    if len(ips) < 3:
        print("[AVISO] IPs insuficientes para detectar anomalias.")
        return {}

    matriz = [[tabela[ip][nome] for nome in METRICAS_TRAFEGO] for ip in ips]
    matriz = StandardScaler().fit_transform(matriz)
    modelo = IsolationForest(n_estimators=200, contamination=contaminacao, random_state=42)
    previsoes = modelo.fit_predict(matriz)
    pontuacoes = modelo.score_samples(matriz)

    resultado = {}
    for i in range(len(ips)):
        resultado[ips[i]] = {"anomalo": bool(previsoes[i] == -1), "score_anomalia": round(float(-pontuacoes[i]), 3)}
    return resultado


if __name__ == "__main__":
    from core.coletor import carregar_todos_os_logs

    eventos = carregar_todos_os_logs("logs")
    resultado = detectar_anomalias(eventos)
    for ip in sorted(resultado, key=lambda x: resultado[x]["score_anomalia"], reverse=True):
        print(ip.ljust(16), resultado[ip])
