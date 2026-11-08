"""
core/regras.py — Motor de Regras (reaproveitado do 1º semestre)

Carrega regras de config/regras.json, avalia cada evento e gera alertas:

{
    "timestamp": "2025-02-20 08:15:01",
    "regra_id": "R001",
    "regra_nome": "Login com Usuario Privilegiado",
    "severidade": "MEDIA",
    "ip": "185.220.101.1",
    "descricao": "...",
    "fonte": "auth"
}
"""

import json


def carregar_regras(caminho_config):
    """Le o JSON de regras e retorna apenas as ativas. Erro -> []."""
    try:
        with open(caminho_config, "r", encoding="utf-8") as f:
            dados = json.load(f)
    except FileNotFoundError:
        print(f"[ERRO] Arquivo de regras nao encontrado: {caminho_config}")
        return []
    except json.JSONDecodeError as erro:
        print(f"[ERRO] JSON de regras invalido: {erro}")
        return []

    regras = dados.get("regras", []) if isinstance(dados, dict) else []
    return [r for r in regras if isinstance(r, dict) and r.get("ativa", False)]


def classificar_severidade(pontuacao):
    if pontuacao >= 9:
        return "CRITICA"
    if pontuacao >= 7:
        return "ALTA"
    if pontuacao >= 5:
        return "MEDIA"
    if pontuacao >= 3:
        return "BAIXA"
    return "INFO"


def extrair_campo(detalhes, chave):
    """extrair_campo('proto=TCP dport=22', 'dport') -> '22'.

    Para 'url' pega tudo ate ' status=' (a URL pode conter espacos).
    """
    marcador = f"{chave}="
    if marcador not in detalhes:
        return None
    valor = detalhes.split(marcador, 1)[1]
    if chave == "url":
        return valor.rsplit(" status=", 1)[0]
    return valor.split()[0] if valor.split() else ""


def _condicao_violada(regra, evento):
    """Retorna a descricao da violacao, ou None se a regra nao se aplica."""
    condicao = regra.get("condicao")
    detalhes = evento.get("detalhes", "")

    if condicao == "usuario_privilegiado":
        usuario = extrair_campo(detalhes, "usuario")
        if usuario in set(regra.get("usuarios_alvo", [])):
            return f"Tentativa de login ({evento.get('tipo')}) com usuario privilegiado '{usuario}'"

    elif condicao == "porta_critica":
        if evento.get("tipo") != "BLOCK":
            return None
        try:
            porta = int(extrair_campo(detalhes, "dport") or -1)
        except ValueError:
            return None
        if porta in set(regra.get("portas_criticas", [])):
            return f"Firewall bloqueou acesso a porta critica {porta}"

    elif condicao in ("path_traversal", "xss"):
        url = extrair_campo(detalhes, "url") or ""
        padrao = next((p for p in regra.get("padroes", []) if p.lower() in url.lower()), None)
        if padrao:
            return f"URL suspeita ({condicao}): {url}"

    elif condicao == "reconhecimento":
        url = extrair_campo(detalhes, "url") or ""
        caminho = url.split("?", 1)[0]
        if caminho in set(regra.get("urls_suspeitas", [])):
            return f"Acesso a URL de reconhecimento: {caminho}"

    return None


def avaliar_regra(regra, evento):
    """Retorna um alerta (dict) se o evento viola a regra, senao None."""
    if evento.get("fonte") != regra.get("fonte"):
        return None
    descricao = _condicao_violada(regra, evento)
    if descricao is None:
        return None
    return {
        "timestamp": evento.get("timestamp"),
        "regra_id": regra.get("id"),
        "regra_nome": regra.get("nome"),
        "severidade": classificar_severidade(regra.get("severidade_base", 0)),
        "ip": evento.get("ip"),
        "descricao": descricao,
        "fonte": evento.get("fonte"),
    }


def aplicar_regras(eventos, regras):
    """Aplica todas as regras a todos os eventos; um evento pode gerar varios alertas."""
    alertas = []
    for evento in eventos or []:
        for regra in regras or []:
            alerta = avaliar_regra(regra, evento)
            if alerta is not None:
                alertas.append(alerta)
    return alertas
