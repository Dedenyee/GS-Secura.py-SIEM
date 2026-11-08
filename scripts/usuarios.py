"""
scripts/usuarios.py — Utilitario de linha de comando para o MySQL (Modulo B)

    python -m scripts.usuarios init           # cria a tabela + admin (ADMIN_EMAIL/ADMIN_SENHA do ambiente)
    python -m scripts.usuarios listar
    python -m scripts.usuarios criar "Nome" email@x.com SenhaForte123 3
    python -m scripts.usuarios demo           # demonstra os cenarios B3 e B4
"""

import os
import sys

from db import mysql_repo as repo


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


def demo():
    repo.criar_tabela()
    email = "analista.demo@cybershield.com"
    print("\n--- B3: email duplicado ---")
    for tentativa in (1, 2):
        try:
            uid = repo.criar_usuario("Analista Demo", email, "SenhaDemo#2025", 2)
            print(f"Tentativa {tentativa}: criado id={uid}")
        except repo.EmailDuplicadoError as erro:
            print(f"Tentativa {tentativa}: erro tratado -> {erro}")

    print("\n--- B4: SQL Injection no login ---")
    for email_teste, senha in [("' OR '1'='1", "' OR '1'='1"), (email, "' OR '1'='1"),
                               (email, "SenhaDemo#2025")]:
        resultado = repo.autenticar(email_teste, senha)
        status = f"LOGADO como {resultado['email']}" if resultado else "NEGADO"
        print(f"email={email_teste!r:<35} senha={senha!r:<18} -> {status}")


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
