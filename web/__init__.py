"""
Módulo web do SecuraPy Platform (Módulo E).

Como plugar na API Flask da Pessoa C (api/app.py):

    from web import registrar_web
    app = Flask(__name__)
    ...                      # rotas /api/...
    registrar_web(app)       # adiciona dashboard, headers de segurança, log e erros
"""
import logging
import os
import secrets

from .dashboard import bp
from .seguranca import aplicar_seguranca

log = logging.getLogger("securapy.web")


def registrar_web(app):
    """Configura sessão segura, headers, log de acesso e registra o dashboard."""
    if not app.config.get("SECRET_KEY"):
        chave = os.getenv("SECRET_KEY")
        if not chave:
            chave = secrets.token_hex(32)
            log.warning("SECRET_KEY não definida: usando chave temporária "
                        "(as sessões serão perdidas ao reiniciar).")
        app.config["SECRET_KEY"] = chave

    # Atribuição direta: o Flask já define essas chaves (com None/False), então setdefault não surtiria efeito.
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    # em produção com HTTPS: COOKIE_SECURE=1
    app.config["SESSION_COOKIE_SECURE"] = os.getenv("COOKIE_SECURE") == "1"
    app.config["PERMANENT_SESSION_LIFETIME"] = 1800  # sessão expira em 30 min

    aplicar_seguranca(app)
    app.register_blueprint(bp)
    return app
