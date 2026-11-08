"""
db/mysql_repo.py — Usuarios (operadores) e permissoes no MySQL (Aulas 1 e 3)

Por que MySQL aqui: usuarios precisam de integridade relacional
(email UNICO, nivel de acesso restrito a 1-5, transacoes).

Seguranca:
    - TODAS as queries sao parametrizadas (%s). Nenhuma concatenacao de string
      com dado do usuario -> SQL Injection neutralizado (cenario B4).
    - Senha nunca em texto puro: PBKDF2-HMAC-SHA256 com salt aleatorio
      (hashlib da biblioteca padrao, mesmo modulo usado no 1º semestre).
    - autenticar() devolve None tanto para usuario inexistente quanto para
      senha errada, e gasta o mesmo tempo nos dois casos (anti-enumeracao).
    - Credenciais do banco SOMENTE via variaveis de ambiente.

Niveis de acesso (1-5):
    1 leitor | 2 analista | 3 analista senior | 4 gestor | 5 administrador
"""

import hashlib
import hmac
import os
import re
import secrets
from contextlib import contextmanager

import mysql.connector
from mysql.connector import errorcode

NIVEIS_ACESSO = {
    1: "leitor",
    2: "analista",
    3: "analista_senior",
    4: "gestor",
    5: "administrador",
}

# Permissao -> nivel minimo exigido (consultado pela API/dashboard)
PERMISSOES = {
    "ler_eventos": 1,
    "ler_alertas": 1,
    "criar_alerta": 2,
    "analisar_logs": 3,
    "gerenciar_usuarios": 5,
}

ITERACOES_PBKDF2 = 260_000
REGEX_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
CAMPOS_PUBLICOS = "id, nome, email, nivel_acesso, ativo, criado_em, atualizado_em"

SQL_CRIAR_TABELA = """
CREATE TABLE IF NOT EXISTS usuarios (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    nome          VARCHAR(100) NOT NULL,
    email         VARCHAR(150) NOT NULL,
    senha_hash    VARCHAR(255) NOT NULL,
    nivel_acesso  TINYINT      NOT NULL DEFAULT 1,
    ativo         BOOLEAN      NOT NULL DEFAULT TRUE,
    criado_em     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    atualizado_em TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT uq_usuarios_email UNIQUE (email),
    CONSTRAINT ck_usuarios_nivel CHECK (nivel_acesso BETWEEN 1 AND 5)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""


# ============================================================
# Excecoes (mensagens seguras: nunca levam query nem detalhes do banco)
# ============================================================

class MySQLRepoErro(Exception):
    """Erro generico de persistencia."""


class BancoIndisponivelError(MySQLRepoErro):
    pass


class EmailDuplicadoError(MySQLRepoErro):
    pass


class DadosInvalidosError(MySQLRepoErro):
    pass


class UsuarioNaoEncontradoError(MySQLRepoErro):
    pass


# ============================================================
# Conexao
# ============================================================

def configuracao():
    """Le a configuracao do ambiente (nunca hard-coded)."""
    return {
        "host": os.environ.get("MYSQL_HOST", "localhost"),
        "port": int(os.environ.get("MYSQL_PORT", "3306")),
        "user": os.environ.get("MYSQL_USER", "securapy"),
        "password": os.environ.get("MYSQL_PASSWORD", ""),
        "database": os.environ.get("MYSQL_DATABASE", "securapy"),
        "connection_timeout": 5,
    }


@contextmanager
def _conexao():
    """Abre conexao + cursor (dicionario); commit no sucesso, rollback no erro."""
    try:
        conn = mysql.connector.connect(**configuracao())
    except mysql.connector.Error as erro:
        raise BancoIndisponivelError("MySQL indisponivel") from erro
    cursor = conn.cursor(dictionary=True)
    try:
        yield cursor
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()


def conectar():
    """Conexao crua (mantida por compatibilidade com a versao provisoria)."""
    return mysql.connector.connect(**configuracao())


def verificar_conexao():
    """True se o MySQL responde (usado em health check / verificacao do compose)."""
    try:
        with _conexao() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
        return True
    except MySQLRepoErro:
        return False


def criar_tabela():
    with _conexao() as cur:
        cur.execute(SQL_CRIAR_TABELA)


# ============================================================
# Senhas
# ============================================================

def gerar_hash_senha(senha):
    """'pbkdf2_sha256$iteracoes$salt_hex$hash_hex'."""
    salt = secrets.token_bytes(16)
    derivada = hashlib.pbkdf2_hmac("sha256", senha.encode(), salt, ITERACOES_PBKDF2)
    return f"pbkdf2_sha256${ITERACOES_PBKDF2}${salt.hex()}${derivada.hex()}"


def verificar_senha(senha, senha_hash):
    try:
        algoritmo, iteracoes, salt_hex, hash_hex = senha_hash.split("$")
        if algoritmo != "pbkdf2_sha256":
            return False
        derivada = hashlib.pbkdf2_hmac("sha256", senha.encode(), bytes.fromhex(salt_hex), int(iteracoes))
    except (ValueError, AttributeError):
        return False
    return hmac.compare_digest(derivada.hex(), hash_hex)


# Hash "isca" usado quando o email nao existe, para o tempo de resposta ser igual
_HASH_ISCA = gerar_hash_senha(secrets.token_hex(16))


# ============================================================
# Validacao
# ============================================================

def _validar_email(email):
    if not isinstance(email, str) or not REGEX_EMAIL.match(email.strip()) or len(email) > 150:
        raise DadosInvalidosError("Email invalido")
    return email.strip().lower()


def _validar_nome(nome):
    if not isinstance(nome, str) or not nome.strip() or len(nome.strip()) > 100:
        raise DadosInvalidosError("Nome obrigatorio (ate 100 caracteres)")
    return nome.strip()


def _validar_nivel(nivel):
    if isinstance(nivel, bool) or not isinstance(nivel, int) or nivel not in NIVEIS_ACESSO:
        raise DadosInvalidosError("Nivel de acesso deve ser inteiro de 1 a 5")
    return nivel


def _validar_senha(senha):
    if not isinstance(senha, str) or len(senha) < 8:
        raise DadosInvalidosError("Senha deve ter ao menos 8 caracteres")
    return senha


def _publico(linha):
    """Remove o hash e normaliza tipos antes de devolver o usuario."""
    if linha is None:
        return None
    usuario = {k: v for k, v in linha.items() if k != "senha_hash"}
    if "ativo" in usuario:
        usuario["ativo"] = bool(usuario["ativo"])
    usuario["perfil"] = NIVEIS_ACESSO.get(usuario.get("nivel_acesso"))
    for campo in ("criado_em", "atualizado_em"):
        if hasattr(usuario.get(campo), "strftime"):
            usuario[campo] = usuario[campo].strftime("%Y-%m-%d %H:%M:%S")
    return usuario


# ============================================================
# CRUD
# ============================================================

def criar_usuario(nome, email, senha, nivel_acesso=1):
    """Cria o usuario e retorna seu id.

    Email duplicado -> EmailDuplicadoError (tratavel, nao derruba a aplicacao).
    """
    nome = _validar_nome(nome)
    email = _validar_email(email)
    nivel_acesso = _validar_nivel(nivel_acesso)
    senha_hash = gerar_hash_senha(_validar_senha(senha))
    try:
        with _conexao() as cur:
            cur.execute(
                "INSERT INTO usuarios (nome, email, senha_hash, nivel_acesso) VALUES (%s, %s, %s, %s)",
                (nome, email, senha_hash, nivel_acesso),
            )
            return cur.lastrowid
    except mysql.connector.IntegrityError as erro:
        if erro.errno == errorcode.ER_DUP_ENTRY:
            raise EmailDuplicadoError("Email ja cadastrado") from erro
        raise DadosInvalidosError("Dados violam as regras da tabela") from erro
    except mysql.connector.Error as erro:
        raise MySQLRepoErro("Falha ao criar usuario") from erro


def buscar_usuario_por_id(usuario_id):
    try:
        with _conexao() as cur:
            cur.execute(f"SELECT {CAMPOS_PUBLICOS} FROM usuarios WHERE id = %s", (int(usuario_id),))
            return _publico(cur.fetchone())
    except (TypeError, ValueError):
        return None
    except mysql.connector.Error as erro:
        raise MySQLRepoErro("Falha ao buscar usuario") from erro


def buscar_usuario_por_email(email):
    try:
        with _conexao() as cur:
            cur.execute(f"SELECT {CAMPOS_PUBLICOS} FROM usuarios WHERE email = %s",
                        (str(email).strip().lower(),))
            return _publico(cur.fetchone())
    except mysql.connector.Error as erro:
        raise MySQLRepoErro("Falha ao buscar usuario") from erro


def listar_usuarios(apenas_ativos=False, limite=100, deslocamento=0):
    sql = f"SELECT {CAMPOS_PUBLICOS} FROM usuarios"
    params = []
    if apenas_ativos:
        sql += " WHERE ativo = %s"
        params.append(True)
    sql += " ORDER BY id LIMIT %s OFFSET %s"
    params += [max(1, min(int(limite), 500)), max(0, int(deslocamento))]
    try:
        with _conexao() as cur:
            cur.execute(sql, tuple(params))
            return [_publico(l) for l in cur.fetchall()]
    except mysql.connector.Error as erro:
        raise MySQLRepoErro("Falha ao listar usuarios") from erro


def atualizar_usuario(usuario_id, nome=None, email=None, senha=None, nivel_acesso=None, ativo=None):
    """Atualiza apenas os campos informados. Retorna o usuario atualizado.

    Os NOMES de coluna vem de uma lista fixa (nunca do usuario);
    os VALORES vao sempre como parametros.
    """
    campos, params = [], []
    if nome is not None:
        campos.append("nome = %s"); params.append(_validar_nome(nome))
    if email is not None:
        campos.append("email = %s"); params.append(_validar_email(email))
    if senha is not None:
        campos.append("senha_hash = %s"); params.append(gerar_hash_senha(_validar_senha(senha)))
    if nivel_acesso is not None:
        campos.append("nivel_acesso = %s"); params.append(_validar_nivel(nivel_acesso))
    if ativo is not None:
        campos.append("ativo = %s"); params.append(bool(ativo))
    if not campos:
        raise DadosInvalidosError("Nenhum campo para atualizar")

    params.append(int(usuario_id))
    try:
        with _conexao() as cur:
            cur.execute(f"UPDATE usuarios SET {', '.join(campos)} WHERE id = %s", tuple(params))
            if cur.rowcount == 0:
                cur.execute("SELECT id FROM usuarios WHERE id = %s", (int(usuario_id),))
                if cur.fetchone() is None:
                    raise UsuarioNaoEncontradoError("Usuario nao encontrado")
    except mysql.connector.IntegrityError as erro:
        if erro.errno == errorcode.ER_DUP_ENTRY:
            raise EmailDuplicadoError("Email ja cadastrado") from erro
        raise DadosInvalidosError("Dados violam as regras da tabela") from erro
    except mysql.connector.Error as erro:
        raise MySQLRepoErro("Falha ao atualizar usuario") from erro
    return buscar_usuario_por_id(usuario_id)


def remover_usuario(usuario_id):
    """Remove o usuario. Retorna True se removeu, False se nao existia."""
    try:
        with _conexao() as cur:
            cur.execute("DELETE FROM usuarios WHERE id = %s", (int(usuario_id),))
            return cur.rowcount > 0
    except mysql.connector.Error as erro:
        raise MySQLRepoErro("Falha ao remover usuario") from erro


# ============================================================
# Autenticacao e permissoes
# ============================================================

def autenticar(email, senha):
    """Retorna o usuario (sem hash) se email+senha conferem e ele esta ativo; senao None.

    Entrada como "' OR '1'='1" eh tratada como TEXTO pelo driver (parametro),
    entao simplesmente nao encontra ninguem.
    """
    if not isinstance(email, str) or not isinstance(senha, str):
        return None
    try:
        with _conexao() as cur:
            cur.execute(
                f"SELECT {CAMPOS_PUBLICOS}, senha_hash FROM usuarios WHERE email = %s",
                (email.strip().lower(),),
            )
            linha = cur.fetchone()
    except mysql.connector.Error as erro:
        raise MySQLRepoErro("Falha ao autenticar") from erro

    if linha is None:
        verificar_senha(senha, _HASH_ISCA)   # mesmo custo de tempo (anti-enumeracao)
        return None
    if not verificar_senha(senha, linha["senha_hash"]) or not linha.get("ativo"):
        return None
    return _publico(linha)


def tem_permissao(usuario, permissao):
    """tem_permissao(usuario, 'analisar_logs') -> bool."""
    if not usuario or permissao not in PERMISSOES:
        return False
    return bool(usuario.get("ativo", True)) and usuario.get("nivel_acesso", 0) >= PERMISSOES[permissao]
