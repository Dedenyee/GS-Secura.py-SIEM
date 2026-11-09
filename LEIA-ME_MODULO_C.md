# Modulo C - Machine Learning (Pessoa B)

## Arquivos (copiar para a raiz do projeto, mantendo as pastas)
- ml/features.py        extracao de features por IP (compartilhada por treino e classificacao)
- ml/treinar.py         gera dataset sintetico, avalia (CV 5 folds + holdout), treina Pipeline, salva modelo + hash
- ml/classificar.py     verifica SHA-256, carrega modelo, calcula score/rotulo/nivel; fallback por heuristica
- ml/anomalias.py       bonus: Isolation Forest
- ml/modelo.pkl, ml/modelo.sha256, ml/relatorio_metricas.txt   entregavel 5
- tests/test_ml.py      bonus: pytest

## requirements.txt (acrescentar)
numpy
scikit-learn
joblib

## Para a Pessoa C (api/app.py) - 2 linhas para o ML usar os eventos
Em analisar():
    resumo_pontuado = classificar.pontuar(resumo, eventos, BLACKLIST)
Em buscar_por_ip():
    score_ml = classificar.classificar_ip(ip, alertas_ip, eventos_ip, BLACKLIST)
(sem os argumentos novos continua funcionando, mas cai na heuristica antiga)

## Comandos (da raiz do projeto)
python -m ml.treinar       # treina, imprime metricas, grava modelo/hash/relatorio
python -m ml.classificar   # cenarios C2, C3 e C4
python -m ml.anomalias     # bonus
python -m pytest tests/test_ml.py -v

Observacao: retreine (python -m ml.treinar) dentro do container Docker antes de
entregar, para o modelo.pkl ser gerado com a mesma versao do scikit-learn que vai rodar.
