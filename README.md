# SecuraPy Platform — GS 2º Semestre

Trabalho final (GS) da disciplina Coding for Security. Evolução do SecuraPy SIEM
(1º semestre) para uma plataforma de segurança completa, com API REST, banco de
dados (MongoDB + MySQL), machine learning, dashboard web, LLM e Docker.

## Integrantes

- **Pessoa A — Marcos — Núcleo + Persistência (Módulos A, B)**
- **Pessoa B — Guilherme — Machine Learning (Módulo C)**
- **Pessoa C — Vinicius — API + Docker (Módulos D, F)**
- **Pessoa D — Lucas — Web + LLM (Módulos E, G)**

## Arquitetura

```
securapy_platform/
├── core/          # NÚCLEO — reaproveitado do 1º semestre
├── db/            # Persistência (MongoDB + MySQL)
├── ml/            # Machine Learning
├── api/           # API REST (Flask) — Módulo D
├── alertas/       # Servidor TCP de alertas (1º semestre)
├── logs/          # Dados de teste
├── config/        # Configuração de regras
├── Dockerfile
└── docker-compose.yml
```

## Como executar

### Com Docker (recomendado)

```bash
docker-compose up -d
```

Isso sobe três contêineres: `api` (Flask, porta 5000), `mongo` (porta 27017) e
`mysql` (porta 3306). Para conferir que os três subiram:

```bash
python verificar_containers.py
```

### Rodando a API localmente (sem Docker)

Da raiz do projeto:

```bash
pip install -r requirements.txt
python -m api.app
```

## Rotas da API

| Método | Rota                        | Descrição                                      |
|--------|-----------------------------|------------------------------------------------|
| GET    | `/api/eventos`              | Lista eventos (filtros: fonte, tipo, ip)       |
| GET    | `/api/alertas`              | Lista alertas (filtro: severidade)             |
| GET    | `/api/alertas/<id>`         | Obtém um alerta específico                     |
| POST   | `/api/alertas`              | Cria um alerta manual (exige token)            |
| POST   | `/api/analisar`             | Roda a pipeline sobre os logs (exige token)    |
| GET    | `/api/ip/<ip>`              | Eventos + alertas + geo + score de ML de um IP |

Rotas de escrita (POST) exigem header `Authorization: Bearer <token>`.
Token padrão: `segredo123` (variável de ambiente `SECURAPY_TOKEN`).

## Exemplos de teste

```bash
# Listar alertas críticos paginados
curl "http://localhost:5000/api/alertas?severidade=critica&pagina=1&tamanho=5"

# Buscar tudo sobre um IP
curl "http://localhost:5000/api/ip/185.220.101.1"

# Rodar a análise completa (exige token)
curl -X POST "http://localhost:5000/api/analisar" \
  -H "Authorization: Bearer segredo123" \
  -H "Content-Type: application/json" \
  -d '{}'

# Criar alerta manual
curl -X POST "http://localhost:5000/api/alertas" \
  -H "Authorization: Bearer segredo123" \
  -H "Content-Type: application/json" \
  -d '{"ip":"1.2.3.4","severidade":"alta","descricao":"teste"}'
```

## O que foi reaproveitado do 1º semestre

- `core/coletor.py` — leitura e parsing dos 3 logs
- `core/regras.py` — motor de regras configurável
- `core/detector.py` — detecção de brute force, port scan e blacklist
- `core/enriquecimento.py` — consulta ipinfo.io com cache
- `alertas/servidor_alertas.py` — servidor TCP de alertas em tempo real
- `alertas/cliente_alertas.py` — cliente console para o servidor de alertas
- `logs/` — dados de teste (auth, firewall, web)
- `config/regras.json` — regras configuráveis

## Persistência — MongoDB + MySQL (Módulo B, Pessoa A)

Versão final de `db/`, substituindo a provisória. **Mantém os mesmos nomes de função que `api/app.py` já chama**, então a API não precisa mudar.

**MongoDB (`db/mongo_repo.py`)** guarda eventos, alertas e ameaças (resumo por IP, onde o ML grava o `score_risco`).
- Índices em `ip`, `timestamp`, `ip+timestamp`, `fonte+tipo` e `severidade`. TTL opcional via `MONGO_TTL_DIAS`.
- Ingestão **idempotente**: cada documento tem uma `chave` SHA-256 com índice único. Rodar a análise 2x não duplica.
- Filtros por fonte, tipo, IP e período (`inicio`/`fim`), com paginação.
  - `buscar_eventos` e `buscar_alertas` devolvem lista, como a API espera.
  - `buscar_eventos_paginado` e `buscar_alertas_paginado` devolvem também o `total`.
- Agregações: `top_ips`, `contagem_por_severidade`, `contagem_por_fonte` e `estatisticas()` (para o dashboard).
- Defesa contra NoSQL injection: os filtros só aceitam texto simples (`{"$ne": ""}` levanta `FiltroInvalidoError`).
- Erros de banco viram `MongoRepoErro`, sem vazar detalhes.

**MySQL (`db/mysql_repo.py`)** guarda os usuários (operadores) da plataforma.
- CRUD completo: `criar_usuario`, `buscar_usuario_por_id`/`_por_email`, `listar_usuarios`, `atualizar_usuario`, `remover_usuario`.
- **Todas as queries são parametrizadas** (`%s`): `' OR '1'='1` no login não passa.
- Email `UNIQUE` (`EmailDuplicadoError`, tratado) e `nivel_acesso` de 1 a 5 (`CHECK`).
- Senhas com PBKDF2-SHA256 e salt. A resposta é igual para usuário inexistente e para senha errada.
- `autenticar(email, senha)` e `tem_permissao(usuario, "analisar_logs")`.

**Scripts:**

```bash
python -m scripts.migrar_logs --limpar   # ingestão inicial: logs -> núcleo -> MongoDB
python -m scripts.usuarios init          # cria a tabela usuarios (+ admin, se ADMIN_EMAIL/ADMIN_SENHA)
python -m scripts.usuarios demo          # demonstra email duplicado e SQL injection
```

**Testes**, sem precisar de banco rodando:

```bash
pip install -r requirements-dev.txt
python -m pytest tests -q
```
