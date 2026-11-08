"""
Executa SÓ o dashboard em modo demo (sem MongoDB/MySQL), para desenvolver e testar.

    SECURAPY_DEMO=1 python run_web_demo.py
    -> http://localhost:5000   login: operador@securapy.local / SecuraPy@2026
"""
import os

from flask import Flask

from web import registrar_web

os.environ.setdefault("SECURAPY_DEMO", "1")
os.environ.setdefault("ASSISTENTE_MODO", "mock")  # sem gastar créditos de API

app = registrar_web(Flask(__name__))

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
