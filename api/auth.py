# Autenticacao por token das rotas de escrita da API.
#
# As rotas que alteram dados exigem o header:
#   Authorization: Bearer <token>
# Sem o token certo, a rota responde 401.
#
# Teste:
#   validar_token("Bearer segredo123") -> True
#   validar_token("Bearer errado")     -> False
#   validar_token(None)                -> False

import os

TOKEN_API = os.environ.get("SECURAPY_TOKEN", "segredo123")


def validar_token(header_autorizacao):
    if not header_autorizacao:
        return False

    if not header_autorizacao.startswith("Bearer "):
        return False

    token = header_autorizacao.split(" ", 1)[1]
    return token == TOKEN_API
