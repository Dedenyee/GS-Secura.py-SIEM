# api/app.py — Modulo D: API REST do SecuraPy Platform
#
# Rotas:
#   GET  /api/eventos              -> lista eventos (filtros: fonte, tipo, ip; paginacao: pagina, tamanho)
#   GET  /api/alertas              -> lista alertas (filtro: severidade; paginacao: pagina, tamanho)
#   GET  /api/alertas/<id>         -> um alerta especifico
#   POST /api/alertas              -> cria alerta manual (exige token)
#   POST /api/analisar             -> roda nucleo + regras + detector + ML sobre os logs e persiste (exige token)
#   GET  /api/ip/<ip>              -> eventos, alertas, geolocalizacao e score de ML de um IP
#
# Autenticacao: rotas de escrita (POST) exigem header "Authorization: Bearer <token>".
#
# Como rodar (da raiz do projeto, pra os imports de core/db/ml funcionarem):
#   python -m api.app
#
# Teste rapido (com o servidor no ar):
#   GET  /api/alertas?severidade=critica&pagina=1&tamanho=5  -> alertas criticos paginados
#   GET  /api/ip/185.220.101.1                                -> eventos + alertas + geo + score
#   POST /api/alertas sem token                                -> 401
#   POST /api/alertas com corpo invalido                       -> 400
#   GET  /api/ip/abc                                           -> 400 (IP malformado)

from datetime import datetime

from flask import Flask, request, jsonify

from core.coletor import carregar_todos_os_logs
from core.regras import carregar_regras, aplicar_regras
from core.detector import detectar_brute_force, detectar_port_scan, verificar_blacklist, gerar_resumo_ameacas
from core.enriquecimento import consultar_ip
from db import mongo_repo
from ml import classificar
from api.auth import validar_token

app = Flask(__name__)

PASTA_LOGS = "logs"
ARQUIVO_REGRAS = "config/regras.json"
BLACKLIST = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}
cache_geo = {}


def ip_valido(ip):
    partes = ip.split(".")
    if len(partes) != 4:
        return False
    for parte in partes:
        if not parte.isdigit() or int(parte) > 255:
            return False
    return True


@app.route("/api/eventos", methods=["GET"])
def listar_eventos():
    fonte = request.args.get("fonte")
    tipo = request.args.get("tipo")
    ip = request.args.get("ip")

    try:
        pagina = int(request.args.get("pagina", 1))
        tamanho = int(request.args.get("tamanho", 20))
    except ValueError:
        return jsonify({"erro": "pagina e tamanho devem ser numeros"}), 400

    eventos = mongo_repo.buscar_eventos(fonte=fonte, tipo=tipo, ip=ip, pagina=pagina, tamanho=tamanho)
    return jsonify({"pagina": pagina, "tamanho": tamanho, "total": len(eventos), "eventos": eventos}), 200


@app.route("/api/alertas", methods=["GET"])
def listar_alertas():
    severidade = request.args.get("severidade")

    try:
        pagina = int(request.args.get("pagina", 1))
        tamanho = int(request.args.get("tamanho", 20))
    except ValueError:
        return jsonify({"erro": "pagina e tamanho devem ser numeros"}), 400

    alertas = mongo_repo.buscar_alertas(severidade=severidade, pagina=pagina, tamanho=tamanho)
    return jsonify({"pagina": pagina, "tamanho": tamanho, "total": len(alertas), "alertas": alertas}), 200


@app.route("/api/alertas/<alerta_id>", methods=["GET"])
def obter_alerta(alerta_id):
    alerta = mongo_repo.buscar_alerta_por_id(alerta_id)
    if alerta is None:
        return jsonify({"erro": "Alerta nao encontrado"}), 404

    return jsonify(alerta), 200


@app.route("/api/alertas", methods=["POST"])
def criar_alerta():
    if not validar_token(request.headers.get("Authorization")):
        return jsonify({"erro": "Token invalido ou ausente"}), 401

    corpo = request.get_json(silent=True)
    if not corpo:
        return jsonify({"erro": "Corpo da requisicao invalido"}), 400

    for campo in ("ip", "severidade", "descricao"):
        if campo not in corpo:
            return jsonify({"erro": "Campo obrigatorio ausente: " + campo}), 400

    alerta = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "regra_id": corpo.get("regra_id", "MANUAL"),
        "regra_nome": corpo.get("regra_nome", "Alerta manual"),
        "severidade": corpo["severidade"].upper(),
        "ip": corpo["ip"],
        "descricao": corpo["descricao"],
    }

    alerta_id = mongo_repo.salvar_alerta(alerta)
    if alerta_id is None:
        return jsonify({"erro": "Falha ao salvar o alerta"}), 500

    alerta["id"] = alerta_id
    return jsonify(alerta), 201


@app.route("/api/analisar", methods=["POST"])
def analisar():
    if not validar_token(request.headers.get("Authorization")):
        return jsonify({"erro": "Token invalido ou ausente"}), 401

    corpo = request.get_json(silent=True) or {}
    pasta_logs = corpo.get("pasta_logs", PASTA_LOGS)

    eventos = carregar_todos_os_logs(pasta_logs)
    if not eventos:
        return jsonify({"erro": "Nenhum evento encontrado em " + pasta_logs}), 400

    regras = carregar_regras(ARQUIVO_REGRAS)
    alertas = aplicar_regras(eventos, regras)

    brute_force = detectar_brute_force(eventos)
    port_scan = detectar_port_scan(eventos)
    ips_blacklist, _ = verificar_blacklist(eventos, BLACKLIST)
    resumo = gerar_resumo_ameacas(brute_force, port_scan, ips_blacklist)
    resumo_pontuado = classificar.pontuar(resumo)

    mongo_repo.salvar_eventos(eventos)
    mongo_repo.salvar_alertas(alertas)

    return jsonify({
        "eventos_processados": len(eventos),
        "alertas_gerados": len(alertas),
        "ips_suspeitos": resumo_pontuado,
    }), 200


@app.route("/api/ip/<ip>", methods=["GET"])
def buscar_por_ip(ip):
    if not ip_valido(ip):
        return jsonify({"erro": "IP invalido"}), 400

    eventos_ip = mongo_repo.buscar_eventos_por_ip(ip)
    alertas_ip = mongo_repo.buscar_alertas_por_ip(ip)
    geo = consultar_ip(ip, cache_geo)
    score_ml = classificar.classificar_ip(ip, alertas_ip)

    return jsonify({
        "ip": ip,
        "eventos": eventos_ip,
        "alertas": alertas_ip,
        "geo": geo,
        "ml": score_ml,
    }), 200


@app.errorhandler(404)
def nao_encontrado(erro):
    return jsonify({"erro": "Rota nao existe"}), 404


@app.errorhandler(500)
def erro_interno(erro):
    return jsonify({"erro": "Erro interno no servidor"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
