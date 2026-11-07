# SecuraPy SIEM

Sistema de detecção de intrusão e monitoramento de segurança em Python.

## Estrutura do Projeto

```
securaPy/
├── main.py                 # Ponto de entrada e menu principal
├── coletor.py              # Módulo 1 — Leitura e parsing de logs
├── regras.py               # Módulo 2 — Motor de regras de detecção
├── detector.py             # Módulo 3 — Detecção de anomalias e ataques
├── servidor_alertas.py     # Módulo 4 — Servidor TCP de alertas em tempo real
├── cliente_alertas.py      # Módulo 4 — Cliente TCP que recebe alertas
├── enriquecimento.py       # Módulo 5 — Consulta a APIs de threat intelligence
├── relatorios.py           # Módulo 6 — Dashboard CLI e geração de relatórios
├── logs/
│   ├── auth.log
│   ├── firewall.log
│   └── web_access.log
├── config/
│   └── regras.json
├── saida/
│   └── (relatórios gerados pelo sistema)
├── tests/
│   ├── conftest.py
│   ├── test_coletor.py
│   └── test_regras.py
└── README.md
```

## Como usar

### Menu principal
```bash
python main.py
```

### Servidor e cliente de alertas (terminais separados)
```bash
# Terminal 1
python servidor_alertas.py

# Terminal 2
python cliente_alertas.py
```

### Testes
```bash
pytest tests/
```

## Módulos

| Módulo | Descrição |
|--------|-----------|
| `coletor.py` | Lê e normaliza logs de auth, firewall e web |
| `regras.py` | Aplica regras de detecção configuráveis via JSON |
| `detector.py` | Detecta brute force, port scan e IPs na blacklist |
| `enriquecimento.py` | Geolocalização de IPs via ipinfo.io |
| `relatorios.py` | Dashboard CLI, filtros, busca e exportação JSON |
| `servidor_alertas.py` | Servidor TCP multithread para envio de alertas |
| `cliente_alertas.py` | Cliente TCP que recebe e exibe alertas em tempo real |

## Regras de detecção (config/regras.json)

| ID | Nome | Severidade |
|----|------|-----------|
| R001 | Login com Usuário Privilegiado | MÉDIA |
| R002 | Acesso a Porta Crítica Bloqueado | ALTA |
| R003 | Tentativa de Path Traversal | CRÍTICA |
| R004 | Tentativa de XSS | ALTA |
| R005 | Reconhecimento Web | MÉDIA |
