# Pessoa D — Módulo E (Dashboard e segurança web) + Módulo G (Assistente LLM)

## O que foi entregue

| Arquivo | Função |
|---|---|
| `web/__init__.py` | `registrar_web(app)`: liga tudo na API Flask da Pessoa C |
| `web/dashboard.py` | Rotas: login, logout, painel, busca por IP, página do IP |
| `web/seguranca.py` | Headers de segurança, log de acesso (OWASP A09), erros genéricos |
| `web/servicos.py` | **Único** ponto de contato com `db/`, `ml/` e `core/` (+ dados demo) |
| `web/templates/`, `web/static/css/` | HTML (Jinja2 com autoescape) e CSS, sem script/estilo inline |
| `ia/assistente.py` | Classificação NORMAL/SUSPEITO/CRÍTICO + explicação, com fallback |
| `tests/test_web.py`, `tests/test_assistente.py` | 40 testes (cenários E1–E4 e G1–G4 + extras) |
| `run_web_demo.py` | Sobe só o dashboard com dados de exemplo |

## Como rodar

```bash
pip install -r requirements_pessoa_D.txt
python run_web_demo.py                 # http://127.0.0.1:5000
# login: operador@securapy.local / SecuraPy@2026   (apenas dados demo)

python -m unittest discover -s tests -t . -v   # ou: pytest
```

Variáveis de ambiente: `SECRET_KEY` (obrigatória em produção), `OPENAI_API_KEY` (opcional),
`OPENAI_MODEL` (padrão `gpt-4o-mini`), `ASSISTENTE_MODO=mock` (força regras, sem rede),
`COOKIE_SECURE=1` (quando houver HTTPS), `LOG_ACESSO_DIR` (padrão `logs/`), `SECURAPY_DEMO=1`.

## Integração com o resto do grupo

**Pessoa C (API/Docker)** — em `api/app.py`, depois de criar o `app` e as rotas `/api/...`:

```python
from web import registrar_web
registrar_web(app)
```

Erros em rotas `/api/*` continuam saindo em JSON. No `Dockerfile`/compose, copie as pastas
`web/` e `ia/` e passe `SECRET_KEY` e (opcional) `OPENAI_API_KEY` por variável de ambiente.

**Pessoa A (Persistência)** — o dashboard espera estas funções (se os nomes forem outros,
ajuste só `web/servicos.py`):

```
db/mongo_repo.py   contagem_por_fonte() -> {"auth": 23, ...}
                   contagem_por_severidade() -> {"critica": 3, ...}      # chaves: critica|alta|media|baixa
                   top_ips(n) -> [{"ip", "eventos", "alertas"}]
                   alertas_recentes(n) -> [alerta]
                   buscar_eventos({"ip": ip}, limite) / buscar_alertas({"ip": ip}, limite)
db/mysql_repo.py   buscar_usuario_por_email(email) -> {"email","nome","nivel_acesso","senha_hash"} | None
```

Contrato de dados: evento = `{fonte, ip, timestamp, mensagem}`; alerta = `{id, severidade, tipo, ip, descricao, timestamp}`.
**A senha deve ser gravada com `werkzeug.security.generate_password_hash`** (login usa `check_password_hash`).

**Pessoa B (ML)** — opcional: `ml.classificar.pontuar_ip(ip) -> float 0..1` aparece como "Risco estimado".
O enriquecimento do 1º semestre (`core.enriquecimento.enriquecer_ip(ip) -> dict`) aparece em "Localização".

Sem os módulos do grupo, o dashboard cai automaticamente em **modo demo** (com aviso na tela).

## Mapa dos cenários de teste do enunciado

| # | Cenário | Como é atendido | Teste |
|---|---|---|---|
| E1 | Alerta com `<script>alert(1)</script>` | Jinja2 autoescape; sem `\|safe`; CSP sem `unsafe-inline` | `TestE1XSS` |
| E2 | Headers de segurança | `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy` (+ Referrer-Policy, Permissions-Policy) em todas as respostas, inclusive erros | `TestE2Headers` |
| E3 | Senha errada vs. usuário inexistente | Mesma mensagem e mesmo 401; hash sempre verificado (anti-timing); CSRF; bloqueio após 5 falhas (429) | `TestE3Login` |
| E4 | Log por requisição | `logs/acesso_web.log` (IP, método, rota, status, tempo, usuário); sem senha/query; sem quebra de linha injetada | `TestE4Log` |
| G1 | `GET /../../etc/passwd` | CRÍTICO (path traversal) | `TestRegras` |
| G2 | Acesso interno normal | NORMAL | `TestRegras` |
| G3 | Sem API key | Fallback por regras, não quebra | `TestFallback` |
| G4 | Prompt injection | Evento delimitado e escapado; regras funcionam como piso (LLM não rebaixa); saída validada | `TestG4PromptInjection` |

## Decisões de segurança (úteis para explicar no vídeo)

1. **XSS**: todo dado vem de logs controlados por atacantes, então nada é inserido sem escape. A CSP sem
   `unsafe-inline` é a segunda camada: mesmo que um escape falhasse, o script não rodaria. Por isso as barras
   do painel são SVG com atributos (e não `style="width:..."`).
2. **Login**: mensagem genérica, verificação de hash mesmo para usuário inexistente, token CSRF,
   cookie `HttpOnly` + `SameSite=Lax`, sessão renovada no login (session fixation), expira em 30 min.
3. **Erros**: handler global; o traceback vai só para o log do servidor.
4. **LLM**: chave em variável de ambiente, `temperature=0`, campos sensíveis removidos antes do envio,
   saída validada contra os 3 rótulos, fallback por regras, e nenhuma ação automática com base na resposta.
5. **Prompt injection**: o LLM pode *subir* a gravidade, nunca baixar abaixo do que as regras detectaram.

## Roteiro sugerido para o seu trecho do vídeo (~4 min)

1. Login com senha errada e com e-mail inexistente (mesma mensagem) e depois o login correto.
2. Painel: faixa de severidade, eventos por fonte, top IPs. Mostrar o alerta `<script>alert(1)</script>` como texto.
3. DevTools → Network → headers de segurança. Mostrar `logs/acesso_web.log` com as linhas das requisições.
4. Buscar `185.220.101.1`: score de ML, geo e explicação do assistente. Mostrar `fonte: mock`/`llm+regras`.
5. Rodar `python -m unittest discover -s tests -t . -v` (G4: injeção não vira NORMAL).

## Texto pronto para o README do grupo (divisão de tarefas)

> **Pessoa D** — Módulo E (dashboard HTML, defesa XSS, headers de segurança, login endurecido, log de acesso)
> e Módulo G (assistente LLM com fallback por regras, validação de saída e proteção contra prompt injection).
> Arquivos: `web/`, `ia/`, `tests/test_web.py`, `tests/test_assistente.py`.
