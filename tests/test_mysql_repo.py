"""Testes do db/mysql_repo.py — cenarios B3/B4 e Exercicios 3.1/3.2 da apostila.

Sem servidor MySQL: um "banco falso" substitui mysql_repo.conectar(). Ele
recebe a SQL e os PARAMETROS separados (como o driver real) e falha o teste
se algum dado do usuario aparecer concatenado dentro da SQL.
"""

import mysql.connector
import pytest

from db import mysql_repo as repo


class CursorFalso:
    def __init__(self, banco):
        self.banco = banco
        self.resultado = []
        self.lastrowid = None
        self.rowcount = 0

    def _checar_parametrizacao(self, sql, params):
        for valor in params:
            if isinstance(valor, str) and valor and valor in sql:
                raise AssertionError(f"dado do usuario concatenado na SQL: {valor!r}")

    def execute(self, sql, params=()):
        self.banco.sqls.append((sql, params))
        self._checar_parametrizacao(sql, params)
        tabela = self.banco.pendente
        s = " ".join(sql.split())
        if s.startswith("INSERT INTO usuarios"):
            nome, email, senha_hash, nivel = params
            if any(l["email"] == email for l in tabela.values()):
                raise mysql.connector.IntegrityError(msg="Duplicate entry", errno=1062)
            self.banco.proximo_id += 1
            uid = self.banco.proximo_id
            tabela[uid] = {"id": uid, "nome": nome, "email": email, "senha_hash": senha_hash,
                           "nivel_acesso": nivel, "ativo": 1, "criado_em": None}
            self.lastrowid, self.rowcount = uid, 1
        elif s.startswith("SELECT 1"):
            self.resultado = [{"ok": 1}]
        elif "GROUP BY nivel_acesso" in s:
            contagem = {}
            for l in tabela.values():
                contagem[l["nivel_acesso"]] = contagem.get(l["nivel_acesso"], 0) + 1
            self.resultado = [{"nivel_acesso": n, "total": t} for n, t in sorted(contagem.items())]
        elif s.startswith("SELECT") and "WHERE email = %s" in s:
            self.resultado = [dict(l) for l in tabela.values() if l["email"] == params[0]]
        elif s.startswith("SELECT") and "WHERE id = %s" in s:
            self.resultado = [dict(l) for l in tabela.values() if l["id"] == params[0]]
        elif s.startswith("SELECT"):
            self.resultado = [dict(l) for l in tabela.values()]
        elif s.startswith("UPDATE usuarios SET nivel_acesso = %s WHERE email = %s"):
            alvo = [l for l in tabela.values() if l["email"] == params[1]]
            for l in alvo:
                l["nivel_acesso"] = params[0]
            self.rowcount = len(alvo)
        elif s.startswith("UPDATE usuarios SET"):
            uid = params[-1]
            colunas = [c.split("=")[0].strip() for c in s.split(" SET ")[1].split(" WHERE ")[0].split(",")]
            self.rowcount = 0
            if uid in tabela:
                tabela[uid].update(dict(zip(colunas, params[:-1])))
                self.rowcount = 1
        elif s.startswith("DELETE"):
            self.rowcount = 1 if tabela.pop(params[0], None) else 0

    def executemany(self, sql, lista):
        total = 0
        for params in lista:
            self.execute(sql, params)
            total += self.rowcount
        self.rowcount = total

    def fetchone(self):
        return self.resultado[0] if self.resultado else None

    def fetchall(self):
        return self.resultado

    def close(self):
        pass


class ConexaoFalsa:
    """Simula commit/rollback: as escritas so valem depois do commit."""

    def __init__(self, banco):
        self.banco = banco
        banco.pendente = {k: dict(v) for k, v in banco.linhas.items()}

    def cursor(self, dictionary=False):
        return CursorFalso(self.banco)

    def commit(self):
        self.banco.linhas = self.banco.pendente
        self.banco.commits += 1

    def rollback(self):
        self.banco.pendente = {}
        self.banco.rollbacks += 1

    def close(self):
        pass


class BancoFalso:
    def __init__(self):
        self.linhas, self.pendente, self.sqls = {}, {}, []
        self.proximo_id = self.commits = self.rollbacks = 0


@pytest.fixture
def banco(monkeypatch):
    b = BancoFalso()
    monkeypatch.setattr(repo, "conectar", lambda: ConexaoFalsa(b))
    return b


def test_criar_e_buscar_usuario(banco):
    uid = repo.criar_usuario("Ana Costa", "Ana@Empresa.com", "SenhaForte123", 5)
    u = repo.buscar_usuario_por_email("ana@empresa.com")
    assert u["id"] == uid and u["nivel_acesso"] == 5 and u["perfil"] == "administrador"
    assert "senha_hash" not in u
    assert banco.commits == 1


def test_senha_nunca_em_texto_puro(banco):
    repo.criar_usuario("Ana", "ana@x.com", "SenhaForte123", 1)
    guardado = next(iter(banco.linhas.values()))["senha_hash"]
    assert "SenhaForte123" not in guardado and guardado.startswith("pbkdf2_sha256$")


def test_b3_email_duplicado_erro_tratado(banco):
    repo.criar_usuario("Carlos Silva", "carlos@empresa.com", "SenhaForte123", 3)
    with pytest.raises(repo.EmailDuplicadoError, match="Email ja cadastrado"):
        repo.criar_usuario("Outro Carlos", "CARLOS@empresa.com", "OutraSenha123", 2)
    assert len(banco.linhas) == 1
    assert banco.rollbacks == 1


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


def test_login_mesma_resposta_para_usuario_inexistente_e_senha_errada(banco):
    repo.criar_usuario("Admin", "admin@x.com", "SenhaForte123", 5)
    assert repo.autenticar("admin@x.com", "SenhaForte123")["nivel_acesso"] == 5
    assert repo.autenticar("admin@x.com", "errada") is None
    assert repo.autenticar("naoexiste@x.com", "errada") is None
    assert repo.autenticar("", "") is None


def test_usuario_inativo_nao_autentica(banco):
    uid = repo.criar_usuario("Ana", "ana@x.com", "SenhaForte123", 2)
    repo.atualizar_usuario(uid, ativo=False)
    assert repo.autenticar("ana@x.com", "SenhaForte123") is None


def test_exercicio_3_1_lote_promover_e_listar(banco):
    """Sequencia de teste do Exercicio 3.1 da apostila."""
    inseridos = repo.inserir_usuarios_lote([
        ("Carlos Silva", "carlos@empresa.com", "SenhaCarlos1", 3),
        ("Ana Costa", "ana@empresa.com", "SenhaAna1234", 5),
        ("Bruno Lima", "bruno@empresa.com", "SenhaBruno12", 1),
    ])
    assert inseridos == 3
    with pytest.raises(repo.EmailDuplicadoError):
        repo.criar_usuario("Carlos", "carlos@empresa.com", "SenhaForte123", 3)
    assert repo.buscar_usuario_por_email("ana@empresa.com")["nivel_acesso"] == 5
    assert repo.alterar_nivel("bruno@empresa.com", 4) is True
    assert [(u["nome"], u["nivel_acesso"]) for u in repo.listar_usuarios()] == [
        ("Carlos Silva", 3), ("Ana Costa", 5), ("Bruno Lima", 4)]
    assert repo.contagem_por_nivel() == {3: 1, 4: 1, 5: 1}


def test_lote_com_duplicado_faz_rollback_de_tudo(banco):
    repo.criar_usuario("Ana", "ana@x.com", "SenhaForte123", 1)
    with pytest.raises(repo.EmailDuplicadoError):
        repo.inserir_usuarios_lote([("Novo", "novo@x.com", "SenhaForte123", 2),
                                    ("Ana de novo", "ana@x.com", "SenhaForte123", 2)])
    assert [u["email"] for u in repo.listar_usuarios()] == ["ana@x.com"]


def test_atualizar_e_remover(banco):
    uid = repo.criar_usuario("Ana", "ana@x.com", "SenhaForte123", 1)
    assert repo.atualizar_usuario(uid, nivel_acesso=4)["nivel_acesso"] == 4
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
    with pytest.raises(repo.BancoIndisponivelError) as erro:
        repo.listar_usuarios()
    assert "indisponivel" in str(erro.value)        # mensagem nao vaza host/porta
    assert repo.verificar_conexao() is False
