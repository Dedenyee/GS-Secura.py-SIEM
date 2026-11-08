"""Cenarios B3/B4 + CRUD do mysql_repo.

Sem servidor MySQL no CI: um "banco falso" substitui a conexao. Ele recebe
a SQL e os PARAMETROS separados (como o driver real) e verifica que nenhum
dado do usuario aparece concatenado dentro da SQL.
"""

import contextlib

import mysql.connector
import pytest
from mysql.connector import errorcode

from db import mysql_repo as repo


class CursorFalso:
    def __init__(self, banco):
        self.banco = banco
        self.resultado = []
        self.lastrowid = None
        self.rowcount = 0

    def execute(self, sql, params=()):
        self.banco.sqls.append((sql, params))
        for valor in params:
            if isinstance(valor, str) and valor and valor in sql:
                raise AssertionError(f"dado do usuario concatenado na SQL: {valor!r}")
        tabela = self.banco.linhas
        s = " ".join(sql.split())
        if s.startswith("INSERT INTO usuarios"):
            nome, email, senha_hash, nivel = params
            if any(l["email"] == email for l in tabela.values()):
                raise mysql.connector.IntegrityError(msg="Duplicate entry", errno=errorcode.ER_DUP_ENTRY)
            self.banco.proximo_id += 1
            uid = self.banco.proximo_id
            tabela[uid] = {"id": uid, "nome": nome, "email": email, "senha_hash": senha_hash,
                           "nivel_acesso": nivel, "ativo": 1, "criado_em": None, "atualizado_em": None}
            self.lastrowid, self.rowcount = uid, 1
        elif "WHERE email = %s" in s:
            self.resultado = [dict(l) for l in tabela.values() if l["email"] == params[0]]
        elif s.startswith("SELECT") and "WHERE id = %s" in s:
            self.resultado = [dict(l) for l in tabela.values() if l["id"] == params[0]]
        elif s.startswith("SELECT"):
            self.resultado = [dict(l) for l in tabela.values()]
        elif s.startswith("UPDATE usuarios SET"):
            uid = params[-1]
            colunas = [c.split("=")[0].strip() for c in s.split(" SET ")[1].split(" WHERE ")[0].split(",")]
            self.rowcount = 0
            if uid in tabela:
                tabela[uid].update(dict(zip(colunas, params[:-1])))
                self.rowcount = 1
        elif s.startswith("DELETE"):
            self.rowcount = 1 if tabela.pop(params[0], None) else 0

    def fetchone(self):
        return self.resultado[0] if self.resultado else None

    def fetchall(self):
        return self.resultado


class BancoFalso:
    def __init__(self):
        self.linhas, self.sqls, self.proximo_id = {}, [], 0

    @contextlib.contextmanager
    def conexao(self):
        yield CursorFalso(self)


@pytest.fixture
def banco(monkeypatch):
    b = BancoFalso()
    monkeypatch.setattr(repo, "_conexao", b.conexao)
    return b


def test_criar_e_buscar_usuario(banco):
    uid = repo.criar_usuario("Ana", "Ana@CyberShield.com", "SenhaForte123", 3)
    u = repo.buscar_usuario_por_id(uid)
    assert u["email"] == "ana@cybershield.com"
    assert u["perfil"] == "analista_senior"
    assert "senha_hash" not in u


def test_senha_nunca_em_texto_puro(banco):
    repo.criar_usuario("Ana", "ana@x.com", "SenhaForte123", 1)
    guardado = next(iter(banco.linhas.values()))["senha_hash"]
    assert "SenhaForte123" not in guardado and guardado.startswith("pbkdf2_sha256$")


def test_b3_email_duplicado_erro_tratado(banco):
    repo.criar_usuario("Ana", "ana@x.com", "SenhaForte123", 1)
    with pytest.raises(repo.EmailDuplicadoError) as erro:
        repo.criar_usuario("Outra Ana", "ANA@x.com", "OutraSenha123", 2)
    assert "Email ja cadastrado" in str(erro.value)
    assert len(banco.linhas) == 1


@pytest.mark.parametrize("nivel", [0, 6, "5", True])
def test_nivel_fora_de_1_a_5_rejeitado(banco, nivel):
    with pytest.raises(repo.DadosInvalidosError):
        repo.criar_usuario("Ana", "ana@x.com", "SenhaForte123", nivel)


def test_b4_sql_injection_no_login_neutralizado(banco):
    repo.criar_usuario("Admin", "admin@x.com", "SenhaForte123", 5)
    assert repo.autenticar("' OR '1'='1", "' OR '1'='1") is None
    assert repo.autenticar("admin@x.com", "' OR '1'='1") is None
    assert repo.autenticar("admin@x.com' --", "qualquer") is None
    sql, params = banco.sqls[-1]
    assert "%s" in sql and params == ("admin@x.com' --",)


def test_autenticacao_valida_e_mesma_resposta_para_erros(banco):
    repo.criar_usuario("Admin", "admin@x.com", "SenhaForte123", 5)
    assert repo.autenticar("admin@x.com", "SenhaForte123")["nivel_acesso"] == 5
    assert repo.autenticar("admin@x.com", "errada") == repo.autenticar("naoexiste@x.com", "errada") is None


def test_usuario_inativo_nao_autentica(banco):
    uid = repo.criar_usuario("Ana", "ana@x.com", "SenhaForte123", 2)
    repo.atualizar_usuario(uid, ativo=False)
    assert repo.autenticar("ana@x.com", "SenhaForte123") is None


def test_atualizar_listar_remover(banco):
    uid = repo.criar_usuario("Ana", "ana@x.com", "SenhaForte123", 1)
    assert repo.atualizar_usuario(uid, nivel_acesso=4)["nivel_acesso"] == 4
    assert len(repo.listar_usuarios()) == 1
    assert repo.remover_usuario(uid) is True
    assert repo.remover_usuario(uid) is False
    with pytest.raises(repo.UsuarioNaoEncontradoError):
        repo.atualizar_usuario(999, nome="X")


def test_permissoes_por_nivel():
    assert repo.tem_permissao({"nivel_acesso": 3, "ativo": True}, "analisar_logs")
    assert not repo.tem_permissao({"nivel_acesso": 2, "ativo": True}, "analisar_logs")
    assert not repo.tem_permissao({"nivel_acesso": 5, "ativo": False}, "gerenciar_usuarios")


def test_banco_fora_do_ar_vira_erro_tratado(monkeypatch):
    monkeypatch.setenv("MYSQL_HOST", "127.0.0.1")
    monkeypatch.setenv("MYSQL_PORT", "1")
    with pytest.raises(repo.BancoIndisponivelError):
        repo.listar_usuarios()
