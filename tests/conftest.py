"""
conftest.py — Fixtures compartilhadas entre todos os testes.

O pytest carrega este arquivo automaticamente antes de rodar qualquer teste.
As fixtures aqui definem os "dados de exemplo" que os testes usam.
"""

import os
import json
import pytest


# ============================================================
# Helpers para localizar arquivos do projeto
# ============================================================

def _raiz_projeto():
    """
    Localiza a pasta raiz do projeto (onde estao coletor.py e regras.py).
    Sobe na arvore de diretorios a partir deste conftest.py ate achar coletor.py.
    """
    pasta_atual = os.path.dirname(os.path.abspath(__file__))
    for _ in range(4):
        if os.path.isfile(os.path.join(pasta_atual, "coletor.py")):
            return pasta_atual
        pasta_atual = os.path.dirname(pasta_atual)
    return os.getcwd()


def _encontrar_pasta(raiz, candidatos):
    """
    Retorna o primeiro caminho de pasta que existir dentre os candidatos.
    candidatos: lista de nomes como ["Logs", "logs", "LOGS"]
    """
    for nome in candidatos:
        caminho = os.path.join(raiz, nome)
        if os.path.isdir(caminho):
            return caminho
    return os.path.join(raiz, candidatos[0])


def _encontrar_arquivo(raiz, candidatos):
    """
    Retorna o primeiro caminho de arquivo que existir dentre os candidatos.
    candidatos: lista de tuplas (pasta, arquivo)
    """
    for pasta, arquivo in candidatos:
        caminho = os.path.join(raiz, pasta, arquivo)
        if os.path.isfile(caminho):
            return caminho
    pasta, arquivo = candidatos[0]
    return os.path.join(raiz, pasta, arquivo)


# ============================================================
# Fixtures de linhas de log brutas (strings)
# ============================================================

@pytest.fixture
def linha_auth_fail():
    return "2025-02-20 08:15:01 FAIL usuario=admin ip=185.220.101.1"

@pytest.fixture
def linha_auth_ok():
    return "2025-02-20 08:15:03 OK usuario=carlos ip=192.168.1.10"

@pytest.fixture
def linha_firewall_block():
    return "2025-02-20 08:10:02 BLOCK proto=TCP src=185.220.101.1 dst=10.0.0.1 dport=22"

@pytest.fixture
def linha_firewall_allow():
    return "2025-02-20 08:10:01 ALLOW proto=TCP src=192.168.1.10 dst=10.0.0.1 dport=443"

@pytest.fixture
def linha_web_get():
    return "2025-02-20 08:20:01 GET url=/index.html ip=192.168.1.10 status=200"

@pytest.fixture
def linha_web_xss():
    return "2025-02-20 08:20:15 GET url=/search?q=<script>alert(1)</script> ip=45.33.32.156 status=400"

@pytest.fixture
def linha_web_traversal():
    return "2025-02-20 08:20:08 GET url=/../../etc/passwd ip=91.240.118.172 status=400"


# ============================================================
# Fixtures de eventos normalizados (dicionarios prontos)
# ============================================================

@pytest.fixture
def evento_auth_fail():
    return {
        "timestamp": "2025-02-20 08:15:01",
        "fonte": "auth",
        "tipo": "FAIL",
        "ip": "185.220.101.1",
        "detalhes": "usuario=admin",
        "linha_original": "2025-02-20 08:15:01 FAIL usuario=admin ip=185.220.101.1"
    }

@pytest.fixture
def evento_auth_ok():
    return {
        "timestamp": "2025-02-20 08:15:03",
        "fonte": "auth",
        "tipo": "OK",
        "ip": "192.168.1.10",
        "detalhes": "usuario=carlos",
        "linha_original": "2025-02-20 08:15:03 OK usuario=carlos ip=192.168.1.10"
    }

@pytest.fixture
def evento_firewall_block():
    return {
        "timestamp": "2025-02-20 08:10:02",
        "fonte": "firewall",
        "tipo": "BLOCK",
        "ip": "185.220.101.1",
        "detalhes": "proto=TCP dst=10.0.0.1 dport=22",
        "linha_original": "2025-02-20 08:10:02 BLOCK proto=TCP src=185.220.101.1 dst=10.0.0.1 dport=22"
    }

@pytest.fixture
def evento_web_normal():
    return {
        "timestamp": "2025-02-20 08:20:01",
        "fonte": "web",
        "tipo": "GET",
        "ip": "192.168.1.10",
        "detalhes": "url=/index.html status=200",
        "linha_original": "2025-02-20 08:20:01 GET url=/index.html ip=192.168.1.10 status=200"
    }

@pytest.fixture
def evento_web_xss():
    return {
        "timestamp": "2025-02-20 08:20:15",
        "fonte": "web",
        "tipo": "GET",
        "ip": "45.33.32.156",
        "detalhes": "url=/search?q=<script>alert(1)</script> status=400",
        "linha_original": "2025-02-20 08:20:15 GET url=/search?q=<script>alert(1)</script> ip=45.33.32.156 status=400"
    }

@pytest.fixture
def evento_web_traversal():
    return {
        "timestamp": "2025-02-20 08:20:08",
        "fonte": "web",
        "tipo": "GET",
        "ip": "91.240.118.172",
        "detalhes": "url=/../../etc/passwd status=400",
        "linha_original": "2025-02-20 08:20:08 GET url=/../../etc/passwd ip=91.240.118.172 status=400"
    }

@pytest.fixture
def evento_web_recon():
    return {
        "timestamp": "2025-02-20 08:20:18",
        "fonte": "web",
        "tipo": "GET",
        "ip": "91.240.118.172",
        "detalhes": "url=/wp-admin status=404",
        "linha_original": "2025-02-20 08:20:18 GET url=/wp-admin ip=91.240.118.172 status=404"
    }


# ============================================================
# Fixtures de caminhos de arquivos reais do projeto
# Aceita tanto "Logs"/"Regras" (Windows, letra maiuscula)
# quanto "logs"/"config" (Linux/padrao do enunciado)
# ============================================================

@pytest.fixture
def pasta_logs():
    """Retorna o caminho da pasta de logs, aceitando 'Logs' ou 'logs'."""
    raiz = _raiz_projeto()
    return _encontrar_pasta(raiz, ["Logs", "logs", "LOGS"])


@pytest.fixture
def caminho_regras():
    """Retorna o caminho do regras.json, aceitando 'Regras/regras.json' ou 'config/regras.json'."""
    raiz = _raiz_projeto()
    return _encontrar_arquivo(raiz, [
        ("Regras", "regras.json"),
        ("config", "regras.json"),
        ("regras", "regras.json"),
    ])


# ============================================================
# Fixtures de arquivos temporarios (criados e destruidos por teste)
# ============================================================

@pytest.fixture
def pasta_temporaria(tmp_path):
    """Fornece uma pasta temporaria limpa para cada teste."""
    return str(tmp_path)

@pytest.fixture
def criar_arquivo_log(tmp_path):
    """
    Factory fixture: retorna uma funcao que cria arquivos temporarios.
    Uso: caminho = criar_arquivo_log("meu.log", "conteudo aqui")
    """
    def _criar(nome_arquivo, conteudo):
        caminho = os.path.join(str(tmp_path), nome_arquivo)
        with open(caminho, "w", encoding="utf-8") as f:
            f.write(conteudo)
        return caminho
    return _criar

@pytest.fixture
def criar_regras_json(tmp_path):
    """
    Factory fixture: cria um regras.json temporario com as regras passadas.
    Uso: caminho = criar_regras_json([{"id": "R001", ...}])
    """
    def _criar(lista_regras):
        caminho = os.path.join(str(tmp_path), "regras_temp.json")
        with open(caminho, "w", encoding="utf-8") as f:
            json.dump({"regras": lista_regras}, f)
        return caminho
    return _criar


# ============================================================
# Fixture de regras de teste (as 5 regras do projeto)
# ============================================================

@pytest.fixture
def regras_teste():
    """Retorna as 5 regras padrao do projeto como lista de dicionarios."""
    return [
        {
            "id": "R001",
            "nome": "Login com Usuario Privilegiado",
            "fonte": "auth",
            "condicao": "usuario_privilegiado",
            "usuarios_alvo": ["root", "admin", "sa", "oracle", "administrator"],
            "severidade_base": 6,
            "ativa": True
        },
        {
            "id": "R002",
            "nome": "Acesso a Porta Critica Bloqueado",
            "fonte": "firewall",
            "condicao": "porta_critica",
            "portas_criticas": [22, 23, 3389, 445, 3306, 5432, 1433],
            "severidade_base": 7,
            "ativa": True
        },
        {
            "id": "R003",
            "nome": "Tentativa de Path Traversal",
            "fonte": "web",
            "condicao": "path_traversal",
            "padroes": ["../", "..\\", "/etc/passwd", "/etc/shadow"],
            "severidade_base": 9,
            "ativa": True
        },
        {
            "id": "R004",
            "nome": "Tentativa de XSS",
            "fonte": "web",
            "condicao": "xss",
            "padroes": ["<script>", "javascript:", "onerror=", "onload="],
            "severidade_base": 8,
            "ativa": True
        },
        {
            "id": "R005",
            "nome": "Reconhecimento Web",
            "fonte": "web",
            "condicao": "reconhecimento",
            "urls_suspeitas": ["/wp-admin", "/phpmyadmin", "/shell.php", "/.env", "/admin", "/wp-login.php"],
            "severidade_base": 5,
            "ativa": True
        }
    ]
