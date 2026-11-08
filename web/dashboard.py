"""
Módulo E — Dashboard web do SecuraPy Platform (Blueprint Flask).

Rotas:
    GET  /                 -> redireciona para o painel
    GET  /login            -> formulário de login
    POST /login            -> autentica (mensagem de erro genérica, CSRF, limite de tentativas)
    POST /logout           -> encerra a sessão
    GET  /dashboard        -> resumo: eventos por fonte, alertas por severidade, top IPs
    GET  /ip?ip=...        -> busca por IP (redireciona para /ip/<ip>)
    GET  /ip/<ip>          -> eventos + alertas + geo + score de ML + triagem do LLM

Defesa contra XSS: todo dado dinâmico é exibido via Jinja2 (autoescape ligado) —
não existe |safe nem render_template_string com dados do usuário.
"""
import hmac
import ipaddress
import secrets
import time
from functools import wraps

from flask import (Blueprint, abort, current_app, redirect, render_template,
                   request, session, url_for)

from ia import assistente

from . import servicos

bp = Blueprint("web", __name__, template_folder="templates",
               static_folder="static", static_url_path="/web-static")

MENSAGEM_LOGIN_INVALIDO = "E-mail ou senha incorretos."  # igual para senha errada e usuário inexistente

# limite simples de tentativas de login por IP de origem (em memória)
MAX_FALHAS = 5
JANELA_SEGUNDOS = 300
_falhas = {}

ROTULO_SEVERIDADE = {"critica": "Crítica", "alta": "Alta", "media": "Média", "baixa": "Baixa"}


# --------------------------------------------------------------------------- #
# Utilidades de segurança
# --------------------------------------------------------------------------- #
def _token_csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def _csrf_valido():
    esperado = session.get("csrf", "")
    enviado = request.form.get("csrf", "")
    return bool(esperado) and hmac.compare_digest(esperado, enviado)


def _tentativas_recentes(origem):
    agora = time.time()
    recentes = [t for t in _falhas.get(origem, []) if agora - t < JANELA_SEGUNDOS]
    _falhas[origem] = recentes
    return recentes


def login_obrigatorio(rota):
    @wraps(rota)
    def protegida(*args, **kwargs):
        if "usuario" not in session:
            return redirect(url_for("web.login"))
        return rota(*args, **kwargs)
    return protegida


@bp.app_context_processor
def _injetar_contexto():
    return {"csrf_token": _token_csrf, "rotulo_sev": ROTULO_SEVERIDADE}


# --------------------------------------------------------------------------- #
# Autenticação
# --------------------------------------------------------------------------- #
@bp.get("/")
def raiz():
    return redirect(url_for("web.painel"))


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", erro=None, email="")

    if not _csrf_valido():
        abort(400)

    origem = request.remote_addr or "desconhecido"
    if len(_tentativas_recentes(origem)) >= MAX_FALHAS:
        abort(429)

    email = (request.form.get("email") or "").strip().lower()[:254]
    senha = request.form.get("senha") or ""
    usuario = servicos.autenticar(email, senha)

    if usuario is None:
        _falhas.setdefault(origem, []).append(time.time())
        return render_template("login.html", erro=MENSAGEM_LOGIN_INVALIDO, email=email), 401

    _falhas.pop(origem, None)
    session.clear()  # descarta a sessão anterior (evita session fixation)
    session.permanent = True  # aplica PERMANENT_SESSION_LIFETIME (expira em 30 min)
    session["usuario"] = usuario
    return redirect(url_for("web.painel"))


@bp.post("/logout")
def logout():
    if not _csrf_valido():
        abort(400)
    session.clear()
    return redirect(url_for("web.login"))


# --------------------------------------------------------------------------- #
# Painel
# --------------------------------------------------------------------------- #
def _barras(contagem):
    """Calcula largura (0-100) de cada barra para o SVG (sem style inline por causa da CSP)."""
    maior = max(contagem.values(), default=0) or 1
    return [{"nome": nome, "total": total, "pct": round(total * 100 / maior, 1)}
            for nome, total in contagem.items()]


def _faixa_severidade(por_severidade):
    """Segmentos proporcionais (x, largura) da faixa de severidade."""
    total = sum(por_severidade.values()) or 1
    x, segmentos = 0.0, []
    for sev, n in por_severidade.items():
        largura = n * 100 / total
        segmentos.append({"sev": sev, "n": n, "x": round(x, 2), "largura": round(largura, 2)})
        x += largura
    return segmentos


def _renderizar_painel(erro_busca=None, status=200):
    resumo = servicos.resumo_dashboard()
    return render_template(
        "dashboard.html",
        resumo=resumo,
        barras_fonte=_barras(resumo["por_fonte"]),
        faixa=_faixa_severidade(resumo["por_severidade"]),
        erro_busca=erro_busca,
        modo_demo=servicos.em_modo_demo(),
    ), status


@bp.get("/dashboard")
@login_obrigatorio
def painel():
    return _renderizar_painel()


@bp.get("/ip")
@login_obrigatorio
def buscar_ip():
    ip = (request.args.get("ip") or "").strip()
    if not ip:
        return redirect(url_for("web.painel"))
    return redirect(url_for("web.pagina_ip", ip=ip))


@bp.get("/ip/<ip>")
@login_obrigatorio
def pagina_ip(ip):
    try:
        ip = str(ipaddress.ip_address(ip))  # valida e normaliza
    except ValueError:
        return _renderizar_painel(erro_busca="Digite um endereço IP válido, como 185.220.101.1.",
                                  status=400)

    dados = servicos.dados_ip(ip)
    # triagem do assistente (máx. 5 alertas, para limitar chamadas à API)
    triagens = assistente.classificar_lote(dados["alertas"], limite=5)
    alertas_triados = list(zip(dados["alertas"], triagens + [None] * len(dados["alertas"])))

    return render_template(
        "ip.html",
        dados=dados,
        alertas_triados=alertas_triados,
        rotulo_ip=assistente.rotulo_mais_grave(triagens),
        erro_busca=None,
    )
