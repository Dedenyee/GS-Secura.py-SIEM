"""Testes do Módulo E (dashboard). Cenários E1–E4 do enunciado + extras de segurança."""
import os
import re
import tempfile
import unittest

os.environ["SECURAPY_DEMO"] = "1"
os.environ["ASSISTENTE_MODO"] = "mock"
os.environ["LOG_ACESSO_DIR"] = tempfile.mkdtemp()

from flask import Flask  # noqa: E402

from web import registrar_web  # noqa: E402
from web import dashboard  # noqa: E402

EMAIL = "operador@securapy.local"
SENHA = "SecuraPy@2026"


def criar_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "chave-de-teste"
    app.config["TESTING"] = False  # queremos exercitar os handlers de erro de verdade
    return registrar_web(app)


class BaseWeb(unittest.TestCase):
    def setUp(self):
        dashboard._falhas.clear()
        self.app = criar_app()
        self.client = self.app.test_client()

    def csrf(self):
        html = self.client.get("/login").get_data(as_text=True)
        return re.search(r'name="csrf" value="([^"]+)"', html).group(1)

    def login(self, email=EMAIL, senha=SENHA):
        return self.client.post("/login", data={"csrf": self.csrf(), "email": email, "senha": senha})


class TestE1XSS(BaseWeb):
    def test_script_no_alerta_aparece_como_texto(self):
        self.login()
        html = self.client.get("/dashboard").get_data(as_text=True)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("<script>alert(1)</script>", html)

    def test_pagina_de_ip_tambem_escapa(self):
        self.login()
        html = self.client.get("/ip/198.51.100.7").get_data(as_text=True)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("<script>alert(1)</script>", html)


class TestE2Headers(BaseWeb):
    def test_headers_presentes_em_varias_rotas(self):
        self.login()
        for rota in ("/login", "/dashboard", "/ip/185.220.101.1", "/rota-que-nao-existe"):
            r = self.client.get(rota)
            self.assertEqual(r.headers.get("X-Content-Type-Options"), "nosniff", rota)
            self.assertEqual(r.headers.get("X-Frame-Options"), "DENY", rota)
            self.assertIn("default-src 'self'", r.headers.get("Content-Security-Policy", ""), rota)

    def test_csp_sem_unsafe_inline(self):
        csp = self.client.get("/login").headers["Content-Security-Policy"]
        self.assertNotIn("unsafe-inline", csp)


class TestE3Login(BaseWeb):
    def test_senha_errada_e_usuario_inexistente_tem_mesma_resposta(self):
        r1 = self.login(EMAIL, "senha-errada")
        r2 = self.login("ninguem@securapy.local", "qualquer")
        self.assertEqual(r1.status_code, 401)
        self.assertEqual(r2.status_code, 401)
        msg = re.search(r'role="alert">([^<]+)<', r1.get_data(as_text=True)).group(1)
        msg2 = re.search(r'role="alert">([^<]+)<', r2.get_data(as_text=True)).group(1)
        self.assertEqual(msg, msg2)

    def test_login_correto_redireciona(self):
        r = self.login()
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r.headers["Location"].endswith("/dashboard"))

    def test_sql_injection_no_login_nao_autentica(self):
        r = self.login("' OR '1'='1", "' OR '1'='1")
        self.assertEqual(r.status_code, 401)

    def test_login_sem_csrf_e_rejeitado(self):
        r = self.client.post("/login", data={"email": EMAIL, "senha": SENHA})
        self.assertEqual(r.status_code, 400)

    def test_bloqueio_apos_muitas_falhas(self):
        for _ in range(dashboard.MAX_FALHAS):
            self.login(EMAIL, "errada")
        self.assertEqual(self.login(EMAIL, SENHA).status_code, 429)

    def test_painel_exige_login(self):
        r = self.client.get("/dashboard")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])

    def test_cookie_de_sessao_httponly(self):
        r = self.login()
        cookie = r.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)


class TestE4Log(BaseWeb):
    def test_cada_requisicao_gera_linha_de_log(self):
        with self.assertLogs("securapy.acesso", level="INFO") as cap:
            self.client.get("/login")
            self.client.get("/rota-que-nao-existe")
        self.assertEqual(len(cap.output), 2)
        self.assertIn("GET /login -> 200", cap.output[0])
        self.assertIn("-> 404", cap.output[1])

    def test_log_nao_contem_senha(self):
        with self.assertLogs("securapy.acesso", level="INFO") as cap:
            self.login()
        self.assertNotIn(SENHA, "\n".join(cap.output))


class TestBusca(BaseWeb):
    def test_ip_valido(self):
        self.login()
        r = self.client.get("/ip/185.220.101.1")
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        self.assertIn("185.220.101.1", html)
        self.assertIn("Frankfurt", html)

    def test_ip_malformado_retorna_400_amigavel(self):
        self.login()
        r = self.client.get("/ip/nao-e-um-ip")
        self.assertEqual(r.status_code, 400)
        self.assertIn("endereço IP válido", r.get_data(as_text=True))

    def test_busca_redireciona(self):
        self.login()
        r = self.client.get("/ip?ip=185.220.101.1")
        self.assertEqual(r.status_code, 302)


class TestErrosSemVazamento(BaseWeb):
    def test_404_generico(self):
        r = self.client.get("/nao-existe")
        self.assertEqual(r.status_code, 404)
        self.assertNotIn("Traceback", r.get_data(as_text=True))

    def test_500_nao_vaza_traceback(self):
        @self.app.get("/explode")
        def explode():
            raise RuntimeError("senha-do-banco=123 SELECT * FROM usuarios")

        r = self.client.get("/explode")
        corpo = r.get_data(as_text=True)
        self.assertEqual(r.status_code, 500)
        self.assertNotIn("senha-do-banco", corpo)
        self.assertNotIn("SELECT", corpo)
        self.assertNotIn("Traceback", corpo)

    def test_erro_em_rota_api_continua_json(self):
        r = self.client.get("/api/nao-existe")
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.get_json(), {"erro": "Página não encontrada."})


if __name__ == "__main__":
    unittest.main()
