"""
scripts/usuarios.py — Utilitario de linha de comando para o MySQL (Modulo B)

    python -m scripts.usuarios init     # cria a tabela + admin (ADMIN_EMAIL/ADMIN_SENHA do ambiente)
    python -m scripts.usuarios listar
    python -m scripts.usuarios criar "Nome" email@x.com SenhaForte123 3
    python -m scripts.usuarios demo     # roteiro para o video: B3, B4 e Exercicios 3.1 / 3.2

Todas as operacoes usam db/mysql_repo.py (queries parametrizadas).
A UNICA query concatenada deste projeto esta em _buscar_inseguro(), dentro
da demo, de proposito, para provar o ataque (Exercicio 3.2 — defensivo, so
roda no banco local de laboratorio).
"""

import os
import sys

from db import mysql_repo as repo

ENTRADA_MALICIOSA = "' OR '1'='1"

USUARIOS_INICIAIS = [   # dados iniciais do Exercicio 3.1 da apostila
    ("Carlos Silva", "carlos@empresa.com", "SenhaCarlos#1", 3),
    ("Ana Costa", "ana@empresa.com", "SenhaAna#2025", 5),
    ("Bruno Lima", "bruno@empresa.com", "SenhaBruno#1", 1),
]


def init():
    repo.criar_tabela()
    print("[OK] Tabela 'usuarios' pronta.")
    email, senha = os.environ.get("ADMIN_EMAIL"), os.environ.get("ADMIN_SENHA")
    if not email or not senha:
        print("[INFO] ADMIN_EMAIL/ADMIN_SENHA nao definidos — nenhum admin criado.")
        return
    try:
        uid = repo.criar_usuario("Administrador", email, senha, 5)
        print(f"[OK] Admin criado (id={uid}).")
    except repo.EmailDuplicadoError:
        print("[INFO] Admin ja existia.")


def _buscar_inseguro(nome):
    """❌ VULNERAVEL de proposito (Aula 3.2): concatena a entrada na query."""
    conexao = repo.conectar()
    cursor = conexao.cursor(dictionary=True)
    try:
        cursor.execute("SELECT nome, email FROM usuarios WHERE nome = '" + nome + "'")
        return cursor.fetchall()
    finally:
        cursor.close()
        conexao.close()


def _buscar_seguro(nome):
    """✅ SEGURO (Aula 3.2): %s + tupla, o driver trata a entrada como texto."""
    conexao = repo.conectar()
    cursor = conexao.cursor(dictionary=True)
    try:
        cursor.execute("SELECT nome, email FROM usuarios WHERE nome = %s", (nome,))
        return cursor.fetchall()
    finally:
        cursor.close()
        conexao.close()


def demo():
    repo.criar_tabela()

    print("\n=== Exercicio 3.1 — cadastro em lote (executemany) ===")
    try:
        print(f"{repo.inserir_usuarios_lote(USUARIOS_INICIAIS)} usuarios cadastrados")
    except repo.EmailDuplicadoError:
        print("Usuarios iniciais ja existiam (lote revertido com rollback)")

    print("\n=== B3 — cadastrar email duplicado ===")
    try:
        repo.criar_usuario("Carlos Silva", "carlos@empresa.com", "OutraSenha#1", 3)
        print("Cadastrado (inesperado!)")
    except repo.EmailDuplicadoError as erro:
        print(f"Erro: {erro}  -> tratado, o programa continua")

    ana = repo.buscar_usuario_por_email("ana@empresa.com")
    print(f"\nBuscar ana@empresa.com -> nivel {ana['nivel_acesso']} ({ana['perfil']})")
    if repo.alterar_nivel("bruno@empresa.com", 4):
        print("Promover Bruno para nivel 4 -> Nivel atualizado!")
    print()
    for u in repo.listar_usuarios():
        print(f"{u['nome']:<13}| {u['email']:<20}| nivel {u['nivel_acesso']}")
    print(f"Usuarios por nivel (GROUP BY): {repo.contagem_por_nivel()}")

    print(f"\n=== B4 / Exercicio 3.2 — SQL Injection com a entrada {ENTRADA_MALICIOSA} ===")
    inseguro = _buscar_inseguro(ENTRADA_MALICIOSA)
    seguro = _buscar_seguro(ENTRADA_MALICIOSA)
    print(f"[INSEGURO] -> {len(inseguro)} usuarios retornados (VAZAMENTO!)")
    print(f"[SEGURO]   -> {len(seguro)} usuarios retornados (defesa OK)")

    print("\n=== B4 — login com SQL Injection (mysql_repo.autenticar) ===")
    for email, senha in [(ENTRADA_MALICIOSA, ENTRADA_MALICIOSA),
                         ("ana@empresa.com", ENTRADA_MALICIOSA),
                         ("naoexiste@empresa.com", "qualquer"),
                         ("ana@empresa.com", "SenhaAna#2025")]:
        usuario = repo.autenticar(email, senha)
        status = f"200 Login OK ({usuario['email']})" if usuario else "401 Credenciais invalidas"
        print(f"email={email!r:<26} senha={senha!r:<17} -> {status}")
    print("Conclusao: a query parametrizada tratou a entrada como texto literal,")
    print("e o login responde igual para usuario inexistente e senha errada (A07).")


def main(argv):
    if not argv:
        print(__doc__)
        return 1
    comando = argv[0]
    try:
        if comando == "init":
            init()
        elif comando == "listar":
            for u in repo.listar_usuarios():
                print(f"{u['id']:>3}  {u['email']:<35} nivel={u['nivel_acesso']} ({u['perfil']}) ativo={u['ativo']}")
        elif comando == "criar" and len(argv) == 5:
            uid = repo.criar_usuario(argv[1], argv[2], argv[3], int(argv[4]))
            print(f"[OK] Usuario criado id={uid}")
        elif comando == "demo":
            demo()
        else:
            print(__doc__)
            return 1
    except repo.MySQLRepoErro as erro:
        print(f"[ERRO] {erro}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
