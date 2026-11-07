# db/mysql_repo.py
# Repositorio de usuarios/operadores da plataforma no MySQL.
#
# AVISO: versao provisoria, so pra o Docker Compose ter os 3 servicos
# de pe (api + mongo + mysql). O CRUD completo de usuarios e autenticacao
# de operadores e o Modulo B (Pessoa A).

import os
import mysql.connector

MYSQL_HOST = os.environ.get("MYSQL_HOST", "localhost")
MYSQL_USER = os.environ.get("MYSQL_USER", "root")
MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "senha")
MYSQL_DATABASE = os.environ.get("MYSQL_DATABASE", "securapy")


def conectar():
    return mysql.connector.connect(
        host=MYSQL_HOST,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DATABASE,
    )


def verificar_conexao():
    try:
        conexao = conectar()
        conexao.close()
        return True
    except Exception as erro:
        print("[ERRO] Falha ao conectar no MySQL:", str(erro))
        return False
