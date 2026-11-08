"""
db/mysql_repo.py — Usuarios (operadores) e permissoes no MySQL
Modulo B da GS — baseado nas Aulas 1, 3, 7 e 8 da apostila do 2º semestre.

Por que MySQL aqui (Aula 1.4): usuarios e permissoes precisam de
integridade relacional — email UNICO, nivel de acesso 1-5, transacoes ACID.
Pelo Teorema CAP (Aula 1.5), autenticacao prefere CP: melhor negar acesso
do que liberar indevidamente.

Fluxo de toda operacao (Aula 3.1):
    conectar -> cursor -> executar -> commit (ou rollback) -> fechar

Seguranca:
    - TODAS as queries sao parametrizadas com %s (Aula 3.2 / Aula 8 - A05).
      "' OR '1'='1" vira texto literal e nao encontra ninguem (cenario B4).
    - Email duplicado -> IntegrityError tratado (Aula 7.3, cenario B3).
    - Senha nunca em texto puro (Aula 8 - A04/A07): hash com hashlib
      (1º semestre, Aula 11.4) usando PBKDF2-SHA256 + salt aleatorio,
      que eh o jeito correto de aplicar SHA-256 a senhas.
    - Login com resposta generica (Aula 8, Exercicio 8.2): autenticar()
      devolve None tanto para usuario inexistente quanto para senha errada.
    - Credenciais do banco SO via variaveis de ambiente (Aula 8 - A02).

Niveis de acesso (1-5):
    1 leitor | 2 analista | 3 analista senior | 4 gestor | 5 administrador
"""

import hashlib
import hmac
import os
import secrets

import mysql.connector
from mysql.connector import Error

NIVEIS_ACESSO = {
    1: "leitor",
    2: "analista",
    3: "analista_senior",
    4: "gestor",
    5: "administrador",
}

# Permissao -> nivel minimo exigido (usado pela API/dashboard)
PERMISSOES = {
    "ler_eventos": 1,
    "ler_alertas": 1,
    "criar_alerta": 2,
    "analisar_logs": 3,
    "gerenciar_usuarios": 5,
}

ITERACOES_HASH = 260_000
CAMPOS_PUBLICOS = "id, nome, email, nivel_acesso, ativo, criado_em"

# Mesmo modelo da Aula 1.2, com as restricoes de integridade da GS
SQL_CRIAR_TABELA = """
    CREATE TABLE IF NOT EXISTS usuarios (
        id           INT AUTO_INCREMENT PRIMARY KEY,
        nome         VARCHAR(100) NOT NULL,
        email        VARCHAR(150) NOT NULL UNIQUE,
        senha_hash   VARCHAR(255) NOT NULL,
        nivel_acesso INT NOT NULL DEFAULT 1,
        ativo        BOOLEAN NOT NULL DEFAULT TRUE,
        criado_em    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CHECK (nivel_acesso BETWEEN 1 AND 5)
    )
"""


# ============================================================
# Excecoes (mensagens seguras: nunca levam a query nem o traceback)
# ============================================================

class MySQLRepoErro(Exception):
    """Erro generico de persistencia."""


class BancoIndisponivelError(MySQLRepoErro):
    """MySQL fora do ar / credenciais erradas (API devolve 500/503 amigavel)."""


class EmailDuplicadoError(MySQLRepoErro):
    """Email ja cadastrado (API devolve 409 Conflict)."""


class DadosInvalidosError(MySQLRepoErro):
    """Entrada invalida (API devolve 400)."""


class UsuarioNaoEncontradoError(MySQLRepoErro):
    """Usuario inexistente (API devolve 404)."""


# ============================================================
# Conexao (Aula 3.1) — credenciais por variavel de ambiente
# ============================================================

def conectar():
    """Abre uma conexao com o MySQL usando as variaveis de ambiente."""
    try:
        return mysql.connector.connect(
            host=os.environ.get("MYSQL_HOST", "localhost"),
            port=int(os.environ.get("MYSQL_PORT", "3306")),
            user=os.environ.get("MYSQL_USER", "root"),
            password=os.environ.get("MYSQL_PASSWORD", ""),
            database=os.environ.get("MYSQL_DATABASE", "securapy"),
            connection_timeout=5,
        )
    except Error as erro:
        raise BancoIndisponivelError("Servico de banco indisponivel") from erro


def _executar(sql, parametros=(), buscar=None):
    """Executa UMA query parametrizada seguindo o fluxo da Aula 3.

    buscar=None    -> escrita: faz commit e devolve (lastrowid, rowcount)
    buscar="um"    -> devolve fetchone() (dict ou None)
    buscar="todos" -> devolve fetchall() (lista de dicts)

    Qualquer erro faz rollback (Aula 3.3) e a conexao eh sempre fechada.
    """
    conexao = conectar()
    cursor = conexao.cursor(dictionary=True)     # acesso por nome de coluna
    try:
        cursor.execute(sql, parametros)           # %s + tupla = parametrizado
        if buscar == "um":
            return cursor.fetchone()
        if buscar == "todos":
            return cursor.fetchall()
        conexao.commit()                          # sem commit a escrita NAO persiste
        return cursor.lastrowid, cursor.rowcount
    except Error:
        conexao.rollback()
        raise
    finally:
        cursor.close()
        conexao.close()


def verificar_conexao():
    """True se o MySQL responde (health check do docker-compose)."""
    try:
        _executar("SELECT 1 AS ok", buscar="um")
        return True
    except (MySQLRepoErro, Error):
        return False


def criar_tabela():
    try:
        _executar(SQL_CRIAR_TABELA)
    except Error as erro:
        raise MySQLRepoErro("Falha ao criar a tabela usuarios") from erro


# ============================================================
# Senhas (hashlib — 1º semestre, Aula 11.4)
# ============================================================

def gerar_hash_senha(senha):
    """Gera 'pbkdf2_sha256$iteracoes$salt$hash'.

    SHA-256 puro (hashlib.sha256(senha).hexdigest()) eh rapido demais para
    senhas: um atacante testa bilhoes por segundo. O PBKDF2 aplica o SHA-256
    milhares de vezes com um salt aleatorio por usuario.
    """
    salt = secrets.token_bytes(16)
    derivada = hashlib.pbkdf2_hmac("sha256", senha.encode(), salt, ITERACOES_HASH)
    return f"pbkdf2_sha256${ITERACOES_HASH}${salt.hex()}${derivada.hex()}"


def verificar_senha(senha, senha_hash):
    try:
        algoritmo, iteracoes, salt_hex, hash_hex = senha_hash.split("$")
        if algoritmo != "pbkdf2_sha256":
            return False
        derivada = hashlib.pbkdf2_hmac("sha256", senha.encode(), bytes.fromhex(salt_hex), int(iteracoes))
    except (ValueError, AttributeError):
        return False
    return hmac.compare_digest(derivada.hex(), hash_hex)   # comparacao em tempo constante


# Hash "isca" usado quando o email nao existe: o tempo de resposta fica igual
_HASH_ISCA = gerar_hash_senha(secrets.token_hex(16))


# ============================================================
# Validacao de entrada ("valide a entrada" — Aula 8)
# ============================================================

def _validar_email(email):
    if not isinstance(email, str):
        raise DadosInvalidosError("Email invalido")
    email = email.strip().lower()
    partes = email.split("@")
    if len(partes) != 2 or not partes[0] or "." not in partes[1] or " " in email or len(email) > 150:
        raise DadosInvalidosError("Email invalido")
    return email


def _validar_nome(nome):
    if not isinstance(nome, str) or not nome.strip() or len(nome.strip()) > 100:
        raise DadosInvalidosError("Nome obrigatorio (ate 100 caracteres)")
    return nome.strip()


def _validar_nivel(nivel):
    """Exercicio 3.1: nivel entre 1 e 5."""
    if isinstance(nivel, bool) or not isinstance(nivel, int) or nivel not in NIVEIS_ACESSO:
        raise DadosInvalidosError("Nivel de acesso deve ser inteiro de 1 a 5")
    return nivel


def _validar_senha(senha):
    if not isinstance(senha, str) or len(senha) < 8:
        raise DadosInvalidosError("Senha deve ter ao menos 8 caracteres")
    return senha


def _publico(linha):
    """Remove o hash da senha antes de devolver o usuario."""
    if linha is None:
        return None
    usuario = {chave: valor for chave, valor in linha.items() if chave != "senha_hash"}
    usuario["ativo"] = bool(usuario.get("ativo", True))
    usuario["perfil"] = NIVEIS_ACESSO.get(usuario.get("nivel_acesso"))
    if hasattr(usuario.get("criado_em"), "strftime"):
        usuario["criado_em"] = usuario["criado_em"].strftime("%Y-%m-%d %H:%M:%S")
    return usuario


# ============================================================
# CRUD (Aula 3.2 / Exercicio 3.1) — tudo parametrizado
# ============================================================

def criar_usuario(nome, email, senha, nivel_acesso=1):
    """INSERT parametrizado. Retorna o id. Email duplicado -> EmailDuplicadoError."""
    nome = _validar_nome(nome)
    email = _validar_email(email)
    nivel_acesso = _validar_nivel(nivel_acesso)
    senha_hash = gerar_hash_senha(_validar_senha(senha))
    try:
        novo_id, _ = _executar(
            "INSERT INTO usuarios (nome, email, senha_hash, nivel_acesso) VALUES (%s, %s, %s, %s)",
            (nome, email, senha_hash, nivel_acesso),
        )
        return novo_id
    except mysql.connector.IntegrityError as erro:       # UNIQUE(email) violado
        raise EmailDuplicadoError("Email ja cadastrado") from erro
    except Error as erro:
        raise MySQLRepoErro("Falha ao criar usuario") from erro


def inserir_usuarios_lote(usuarios):
    """INSERT em lote com executemany (Aula 3.2).

    usuarios: lista de tuplas (nome, email, senha, nivel). Tudo ou nada:
    se UM email ja existir, faz rollback e nenhum eh inserido (Aula 3.3).
    """
    dados = [(_validar_nome(n), _validar_email(e), gerar_hash_senha(_validar_senha(s)), _validar_nivel(nv))
             for n, e, s, nv in usuarios]
    conexao = conectar()
    cursor = conexao.cursor()
    try:
        cursor.executemany(
            "INSERT INTO usuarios (nome, email, senha_hash, nivel_acesso) VALUES (%s, %s, %s, %s)", dados)
        conexao.commit()
        return cursor.rowcount
    except mysql.connector.IntegrityError as erro:
        conexao.rollback()
        raise EmailDuplicadoError("Email ja cadastrado (nenhum usuario do lote foi inserido)") from erro
    except Error as erro:
        conexao.rollback()
        raise MySQLRepoErro("Falha ao inserir usuarios") from erro
    finally:
        cursor.close()
        conexao.close()


def buscar_usuario_por_id(usuario_id):
    try:
        linha = _executar(f"SELECT {CAMPOS_PUBLICOS} FROM usuarios WHERE id = %s",
                          (int(usuario_id),), buscar="um")
    except (TypeError, ValueError):
        return None
    except Error as erro:
        raise MySQLRepoErro("Falha ao buscar usuario") from erro
    return _publico(linha)


def buscar_usuario_por_email(email):
    try:
        linha = _executar(f"SELECT {CAMPOS_PUBLICOS} FROM usuarios WHERE email = %s",
                          (str(email).strip().lower(),), buscar="um")
    except Error as erro:
        raise MySQLRepoErro("Falha ao buscar usuario") from erro
    return _publico(linha)


def listar_usuarios(apenas_ativos=False):
    sql = f"SELECT {CAMPOS_PUBLICOS} FROM usuarios"
    parametros = ()
    if apenas_ativos:
        sql += " WHERE ativo = %s"
        parametros = (True,)
    sql += " ORDER BY id"
    try:
        return [_publico(linha) for linha in _executar(sql, parametros, buscar="todos")]
    except Error as erro:
        raise MySQLRepoErro("Falha ao listar usuarios") from erro


def atualizar_usuario(usuario_id, nome=None, email=None, senha=None, nivel_acesso=None, ativo=None):
    """UPDATE so dos campos informados. Retorna o usuario atualizado.

    Os NOMES das colunas vem de uma lista fixa do codigo (nunca do usuario);
    os VALORES vao sempre como parametros %s.
    """
    colunas, valores = [], []
    if nome is not None:
        colunas.append("nome = %s")
        valores.append(_validar_nome(nome))
    if email is not None:
        colunas.append("email = %s")
        valores.append(_validar_email(email))
    if senha is not None:
        colunas.append("senha_hash = %s")
        valores.append(gerar_hash_senha(_validar_senha(senha)))
    if nivel_acesso is not None:
        colunas.append("nivel_acesso = %s")
        valores.append(_validar_nivel(nivel_acesso))
    if ativo is not None:
        colunas.append("ativo = %s")
        valores.append(bool(ativo))
    if not colunas:
        raise DadosInvalidosError("Nenhum campo para atualizar")

    if buscar_usuario_por_id(usuario_id) is None:
        raise UsuarioNaoEncontradoError("Usuario nao encontrado")
    valores.append(int(usuario_id))
    try:
        _executar(f"UPDATE usuarios SET {', '.join(colunas)} WHERE id = %s", tuple(valores))
    except mysql.connector.IntegrityError as erro:
        raise EmailDuplicadoError("Email ja cadastrado") from erro
    except Error as erro:
        raise MySQLRepoErro("Falha ao atualizar usuario") from erro
    return buscar_usuario_por_id(usuario_id)


def alterar_nivel(email, novo_nivel):
    """Promover/rebaixar pelo email (Exercicio 3.1). Retorna True se alterou."""
    novo_nivel = _validar_nivel(novo_nivel)
    try:
        _, alteradas = _executar("UPDATE usuarios SET nivel_acesso = %s WHERE email = %s",
                                 (novo_nivel, _validar_email(email)))
    except Error as erro:
        raise MySQLRepoErro("Falha ao alterar nivel") from erro
    return alteradas > 0


def remover_usuario(usuario_id):
    """DELETE parametrizado. True se removeu, False se nao existia."""
    try:
        _, removidas = _executar("DELETE FROM usuarios WHERE id = %s", (int(usuario_id),))
    except Error as erro:
        raise MySQLRepoErro("Falha ao remover usuario") from erro
    return removidas > 0


def contagem_por_nivel():
    """Relatorio com GROUP BY (Aula 1.2 / Exercicio 3.3): {nivel: total}."""
    try:
        linhas = _executar("SELECT nivel_acesso, COUNT(*) AS total FROM usuarios "
                           "GROUP BY nivel_acesso ORDER BY nivel_acesso", buscar="todos")
    except Error as erro:
        raise MySQLRepoErro("Falha ao gerar relatorio") from erro
    return {linha["nivel_acesso"]: linha["total"] for linha in linhas}


# ============================================================
# Autenticacao e permissoes (Aula 8 — Exercicio 8.2)
# ============================================================

def autenticar(email, senha):
    """Retorna o usuario (sem hash) se email+senha conferem e ele esta ativo; senao None.

    Mesmo resultado (None) para usuario inexistente e senha errada:
    evita user enumeration (A07). A API responde sempre "Credenciais invalidas".
    """
    if not isinstance(email, str) or not isinstance(senha, str) or not email or not senha:
        return None
    try:
        linha = _executar(f"SELECT {CAMPOS_PUBLICOS}, senha_hash FROM usuarios WHERE email = %s",
                          (email.strip().lower(),), buscar="um")
    except Error as erro:
        raise MySQLRepoErro("Falha ao autenticar") from erro

    if linha is None:
        verificar_senha(senha, _HASH_ISCA)    # gasta o mesmo tempo de uma senha errada
        return None
    if not verificar_senha(senha, linha["senha_hash"]) or not linha.get("ativo"):
        return None
    return _publico(linha)


def tem_permissao(usuario, permissao):
    """tem_permissao(usuario, 'analisar_logs') -> bool (controle de acesso, A01)."""
    if not usuario or permissao not in PERMISSOES:
        return False
    return bool(usuario.get("ativo", True)) and usuario.get("nivel_acesso", 0) >= PERMISSOES[permissao]
