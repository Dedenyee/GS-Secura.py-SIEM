"""
Camada de serviços do dashboard.

É o ÚNICO ponto onde o módulo web conversa com os outros módulos do grupo
(db/mongo_repo.py, db/mysql_repo.py, ml/classificar.py, core/enriquecimento.py).
Se os nomes das funções combinados com os colegas forem diferentes, ajuste só aqui.

Contrato esperado (combinar com a Pessoa A — Persistência):

    db.mongo_repo.contagem_por_fonte()      -> dict[str, int]          {"auth": 23, ...}
    db.mongo_repo.contagem_por_severidade() -> dict[str, int]          {"critica": 3, ...}
    db.mongo_repo.top_ips(n)                -> list[dict]              [{"ip", "eventos", "alertas"}]
    db.mongo_repo.alertas_recentes(n)       -> list[dict]
    db.mongo_repo.buscar_eventos(filtros, limite) -> list[dict]        filtros={"ip": "..."}
    db.mongo_repo.buscar_alertas(filtros, limite) -> list[dict]
    db.mysql_repo.buscar_usuario_por_email(email) -> dict | None
        com as chaves: email, nome, nivel_acesso, senha_hash
        (a senha deve ser gravada com werkzeug.security.generate_password_hash)

Opcionais (Pessoa B — ML, e núcleo do 1º semestre):

    ml.classificar.pontuar_ip(ip)           -> float entre 0 e 1
    core.enriquecimento.enriquecer_ip(ip)   -> dict (pais, cidade, org...)

Modo demo: com SECURAPY_DEMO=1 (ou se os módulos db ainda não existirem) o
dashboard usa os dados de exemplo abaixo, para você desenvolver e gravar o
vídeo sem depender dos colegas.
"""
import importlib
import logging
import os

from werkzeug.security import check_password_hash, generate_password_hash

log = logging.getLogger("securapy.web")

ORDEM_SEVERIDADE = ("critica", "alta", "media", "baixa")

# hash "falso" usado quando o e-mail não existe, para o tempo de resposta
# ser parecido com o de uma senha errada (anti-enumeração por timing)
_HASH_FALSO = generate_password_hash("senha-que-nao-existe-securapy")


# --------------------------------------------------------------------------- #
# Dados de demonstração (batem com os cenários de teste do enunciado)
# --------------------------------------------------------------------------- #
def _montar_demo():
    ip_mal = "185.220.101.1"
    eventos = []
    for i in range(10):
        eventos.append({"fonte": "auth", "ip": ip_mal, "timestamp": f"2026-11-08T03:12:{i:02d}",
                        "mensagem": "Failed password for root", "resultado": "FAIL"})
    for porta in (21, 22, 23, 80, 443, 3306, 8080):
        eventos.append({"fonte": "firewall", "ip": ip_mal, "timestamp": f"2026-11-08T03:14:{porta % 60:02d}",
                        "mensagem": f"BLOCK tcp dport={porta}", "acao": "BLOCK"})
    eventos.append({"fonte": "web", "ip": ip_mal, "timestamp": "2026-11-08T03:15:01",
                    "mensagem": "GET /../../etc/passwd HTTP/1.1", "status": 404})
    for ip, n in (("45.155.205.233", 4), ("103.75.190.12", 3)):
        for i in range(n):
            eventos.append({"fonte": "auth", "ip": ip, "timestamp": f"2026-11-08T04:00:{i:02d}",
                            "mensagem": "Failed password for admin", "resultado": "FAIL"})
    for i in range(14):
        eventos.append({"fonte": "web", "ip": "192.168.1.10", "timestamp": f"2026-11-08T09:{i:02d}:00",
                        "mensagem": "GET /index.html HTTP/1.1", "status": 200})

    alertas = [
        {"id": "a1", "severidade": "critica", "tipo": "brute_force", "ip": ip_mal,
         "descricao": "10 falhas de login em sequência", "timestamp": "2026-11-08T03:12:09"},
        {"id": "a2", "severidade": "critica", "tipo": "port_scan", "ip": ip_mal,
         "descricao": "7 portas distintas bloqueadas pelo firewall", "timestamp": "2026-11-08T03:14:56",
         "em_blacklist": True},
        {"id": "a3", "severidade": "alta", "tipo": "path_traversal", "ip": ip_mal,
         "descricao": "GET /../../etc/passwd HTTP/1.1", "timestamp": "2026-11-08T03:15:01"},
        {"id": "a4", "severidade": "alta", "tipo": "blacklist", "ip": "45.155.205.233",
         "descricao": "IP presente na blacklist", "timestamp": "2026-11-08T04:00:03", "em_blacklist": True},
        {"id": "a5", "severidade": "media", "tipo": "brute_force", "ip": "103.75.190.12",
         "descricao": "3 falhas de login", "timestamp": "2026-11-08T04:00:02"},
        # cenário E1: descrição maliciosa que NÃO pode executar na tela
        {"id": "a6", "severidade": "baixa", "tipo": "teste_xss", "ip": "198.51.100.7",
         "descricao": "<script>alert(1)</script>", "timestamp": "2026-11-08T10:00:00"},
    ]
    usuarios = {
        "operador@securapy.local": {
            "email": "operador@securapy.local", "nome": "Operador SOC", "nivel_acesso": 3,
            "senha_hash": generate_password_hash("SecuraPy@2026"),
        }
    }
    return eventos, alertas, usuarios


_DEMO = None


def _demo():
    global _DEMO
    if _DEMO is None:
        _DEMO = _montar_demo()
    return _DEMO


# --------------------------------------------------------------------------- #
# Acesso aos módulos reais (com fallback para demo)
# --------------------------------------------------------------------------- #
def _modulo(nome):
    """Importa um módulo do grupo; devolve None se estiver em modo demo ou ausente."""
    if os.getenv("SECURAPY_DEMO") == "1":
        return None
    try:
        return importlib.import_module(nome)
    except ImportError:
        log.warning("Módulo %s não encontrado; usando dados de demonstração.", nome)
        return None


def em_modo_demo():
    return _modulo("db.mongo_repo") is None


# --------------------------------------------------------------------------- #
# Autenticação
# --------------------------------------------------------------------------- #
def _buscar_usuario(email):
    mysql = _modulo("db.mysql_repo")
    if mysql is None:
        return _demo()[2].get(email)
    return mysql.buscar_usuario_por_email(email)


def autenticar(email, senha):
    """
    Retorna o usuário (sem o hash) se as credenciais forem válidas, senão None.
    Sempre executa uma verificação de hash, exista o usuário ou não.
    """
    try:
        usuario = _buscar_usuario(email)
    except Exception:
        log.exception("Falha ao consultar usuário no banco")  # detalhe só no log do servidor
        usuario = None

    hash_armazenado = usuario["senha_hash"] if usuario else _HASH_FALSO
    senha_ok = check_password_hash(hash_armazenado, senha)
    if usuario and senha_ok:
        return {"email": usuario["email"], "nome": usuario.get("nome", usuario["email"]),
                "nivel_acesso": usuario.get("nivel_acesso", 1)}
    return None


# --------------------------------------------------------------------------- #
# Dados do dashboard
# --------------------------------------------------------------------------- #
def _ordenar_severidade(contagem):
    return {sev: int(contagem.get(sev, 0)) for sev in ORDEM_SEVERIDADE}


def resumo_dashboard(n_top=10, n_recentes=8):
    mongo = _modulo("db.mongo_repo")
    if mongo is not None:
        por_fonte = dict(mongo.contagem_por_fonte())
        por_sev = _ordenar_severidade(mongo.contagem_por_severidade())
        top = list(mongo.top_ips(n_top))
        recentes = list(mongo.alertas_recentes(n_recentes))
    else:
        eventos, alertas, _ = _demo()
        por_fonte, contagem_ip, alertas_ip, contagem_sev = {}, {}, {}, {}
        for e in eventos:
            por_fonte[e["fonte"]] = por_fonte.get(e["fonte"], 0) + 1
            contagem_ip[e["ip"]] = contagem_ip.get(e["ip"], 0) + 1
        for a in alertas:
            contagem_sev[a["severidade"]] = contagem_sev.get(a["severidade"], 0) + 1
            alertas_ip[a["ip"]] = alertas_ip.get(a["ip"], 0) + 1
        por_sev = _ordenar_severidade(contagem_sev)
        top = [{"ip": ip, "eventos": n, "alertas": alertas_ip.get(ip, 0)}
               for ip, n in sorted(contagem_ip.items(), key=lambda kv: kv[1], reverse=True)[:n_top]]
        recentes = sorted(alertas, key=lambda a: a["timestamp"], reverse=True)[:n_recentes]

    return {
        "por_fonte": por_fonte,
        "por_severidade": por_sev,
        "top_ips": top,
        "alertas_recentes": recentes,
        "total_eventos": sum(por_fonte.values()),
        "total_alertas": sum(por_sev.values()),
    }


def _opcional(modulo, funcao, *args):
    """Chama uma função opcional de outro módulo; None se não existir ou falhar."""
    try:
        mod = importlib.import_module(modulo)
        return getattr(mod, funcao)(*args)
    except (ImportError, AttributeError):
        return None
    except Exception:
        log.warning("Falha em %s.%s", modulo, funcao, exc_info=True)
        return None


def dados_ip(ip, limite=50):
    """Eventos, alertas, geolocalização e score de ML de um IP."""
    mongo = _modulo("db.mongo_repo")
    if mongo is not None:
        eventos = list(mongo.buscar_eventos({"ip": ip}, limite))
        alertas = list(mongo.buscar_alertas({"ip": ip}, limite))
        geo = _opcional("core.enriquecimento", "enriquecer_ip", ip)
        score = _opcional("ml.classificar", "pontuar_ip", ip)
    else:
        todos_eventos, todos_alertas, _ = _demo()
        eventos = [e for e in todos_eventos if e["ip"] == ip][:limite]
        alertas = [a for a in todos_alertas if a["ip"] == ip][:limite]
        geo = ({"pais": "Alemanha", "cidade": "Frankfurt", "org": "Tor Exit Node (demo)"}
               if ip == "185.220.101.1" else None)
        score = {"185.220.101.1": 0.97, "45.155.205.233": 0.81, "103.75.190.12": 0.64}.get(ip, 0.04)
    return {"ip": ip, "eventos": eventos, "alertas": alertas, "geo": geo, "score": score}
