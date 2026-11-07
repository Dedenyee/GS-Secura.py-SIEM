"""
Módulo 6 — Dashboard CLI e Relatórios (relatorios.py)
Interface principal do SecuraPy SIEM: menu interativo, filtros, buscas e exportação.
"""

import json
import os
from datetime import datetime


# ---------------------------------------------------------------------------
# 1. Menu principal interativo
# ---------------------------------------------------------------------------

def exibir_menu() -> int:
    """Exibe o menu principal e retorna a opção escolhida (validada)."""
    largura = 42
    borda = "+" + "-" * largura + "+"
    print("\n" + borda)
    print(f"|{'SecuraPy SIEM — Menu':^{largura}}|")
    print(borda)
    opcoes = [
        "1. Carregar e processar logs",
        "2. Resumo geral",
        "3. Filtrar eventos",
        "4. Buscar IP",
        "5. Top 10 IPs suspeitos",
        "6. Alertas por severidade",
        "7. Enriquecer IPs suspeitos",
        "8. Exportar relatório JSON",
        "9. Iniciar servidor de alertas",
        "0. Sair",
    ]
    for opcao in opcoes:
        print(f"| {opcao:<{largura - 1}}|")
    print(borda)

    while True:
        try:
            escolha = int(input("\n  Escolha uma opção: "))
            if 0 <= escolha <= 9:
                return escolha
            print("  [!] Opção inválida. Digite um número entre 0 e 9.")
        except ValueError:
            print("  [!] Opção inválida. Digite um número inteiro.")


# ---------------------------------------------------------------------------
# 2. Resumo geral
# ---------------------------------------------------------------------------

def resumo_geral(eventos: list, alertas: list) -> None:
    """Exibe contadores gerais: eventos por fonte, alertas por severidade."""
    print("\n" + "=" * 45)
    print("  RESUMO GERAL")
    print("=" * 45)

    # Contagem por fonte
    contadores_fonte: dict = {}
    for evento in eventos:
        fonte = evento.get("fonte", "desconhecido")
        contadores_fonte[fonte] = contadores_fonte.get(fonte, 0) + 1

    print(f"\n  Total de eventos: {len(eventos)}")
    print("  Por fonte:")
    for fonte, qtd in sorted(contadores_fonte.items()):
        print(f"    {fonte:<12}: {qtd} eventos")

    # Contagem de alertas por severidade
    contadores_sev: dict = {}
    for alerta in alertas:
        sev = alerta.get("severidade", "DESCONHECIDO")
        contadores_sev[sev] = contadores_sev.get(sev, 0) + 1

    print(f"\n  Total de alertas: {len(alertas)}")
    if contadores_sev:
        print("  Por severidade:")
        for sev, qtd in sorted(contadores_sev.items()):
            print(f"    {sev:<12}: {qtd} alerta(s)")
    else:
        print("  Nenhum alerta gerado.")

    print("=" * 45)


# ---------------------------------------------------------------------------
# 3. Filtrar eventos
# ---------------------------------------------------------------------------

def filtrar_eventos(eventos: list, fonte=None, tipo=None, ip=None) -> list:
    """
    Retorna eventos filtrados pelos critérios. None = sem filtro.
    Filtra por: fonte (auth/firewall/web), tipo (FAIL/BLOCK), IP específico.
    """
    resultado = [
        e for e in eventos
        if (fonte is None or e.get("fonte") == fonte)
        and (tipo is None or e.get("tipo") == tipo)
        and (ip is None or e.get("ip") == ip)
    ]
    return resultado


def menu_filtrar_eventos(eventos: list) -> None:
    """Interação do menu para filtrar eventos."""
    print("\n  Filtrar por fonte (auth/firewall/web) ou Enter para ignorar:")
    fonte_input = input("  Fonte: ").strip() or None

    print("  Filtrar por tipo (FAIL/BLOCK/etc.) ou Enter para ignorar:")
    tipo_input = input("  Tipo: ").strip().upper() or None

    print("  Filtrar por IP específico ou Enter para ignorar:")
    ip_input = input("  IP: ").strip() or None

    resultado = filtrar_eventos(eventos, fonte=fonte_input, tipo=tipo_input, ip=ip_input)

    if resultado:
        colunas = ["timestamp", "ip", "fonte", "tipo", "usuario"]
        exibir_tabela(resultado, colunas)
        print(f"\n  Total encontrado: {len(resultado)} evento(s).")
    else:
        print("  Nenhum evento encontrado com esses filtros.")


# ---------------------------------------------------------------------------
# 4. Buscar IP
# ---------------------------------------------------------------------------

def buscar_ip(ip: str, eventos: list, alertas: list, cache_enriquecimento: dict) -> None:
    """Exibe relatório completo de um IP: eventos, alertas, geolocalização."""
    print(f"\n{'=' * 45}")
    print(f"  RELATÓRIO DO IP: {ip}")
    print("=" * 45)

    # Eventos do IP
    eventos_ip = [e for e in eventos if e.get("ip") == ip]
    print(f"\n  Eventos ({len(eventos_ip)}):")
    if eventos_ip:
        colunas = ["timestamp", "fonte", "tipo", "usuario"]
        exibir_tabela(eventos_ip, colunas)
    else:
        print("  Nenhum evento encontrado.")

    # Alertas do IP
    alertas_ip = [a for a in alertas if a.get("ip") == ip]
    print(f"\n  Alertas ({len(alertas_ip)}):")
    if alertas_ip:
        colunas_a = ["regra", "severidade", "descricao"]
        exibir_tabela(alertas_ip, colunas_a)
    else:
        print("  Nenhum alerta associado.")

    # Geolocalização
    geo = cache_enriquecimento.get(ip)
    if geo:
        print("\n  Geolocalização:")
        print(f"    Cidade  : {geo.get('cidade', 'N/A')}")
        print(f"    Região  : {geo.get('regiao', 'N/A')}")
        print(f"    País    : {geo.get('pais', 'N/A')}")
        print(f"    Org     : {geo.get('org', 'N/A')}")
        print(f"    Hostname: {geo.get('hostname', 'N/A')}")
    else:
        print("\n  Geolocalização: não disponível (execute opção 7 primeiro).")

    print("=" * 45)


# ---------------------------------------------------------------------------
# 5. Top N IPs mais ativos
# ---------------------------------------------------------------------------

def top_ips(eventos: list, n: int = 10) -> list:
    """
    Retorna os N IPs com mais eventos, com contagem e classificação.
    Indicador visual de ameaça: ★ para IPs com muitos eventos.
    """
    contagem: dict = {}
    for evento in eventos:
        ip = evento.get("ip", "desconhecido")
        contagem[ip] = contagem.get(ip, 0) + 1

    ranking = sorted(contagem.items(), key=lambda x: x[1], reverse=True)[:n]

    print(f"\n{'=' * 45}")
    print(f"  TOP {n} IPs MAIS ATIVOS")
    print("=" * 45)
    print(f"  {'#':<4} {'IP':<18} {'Eventos':<10} {'Ameaça'}")
    print("  " + "-" * 40)

    resultado = []
    for i, (ip, qtd) in enumerate(ranking, start=1):
        ameaca = "★★★" if qtd >= 10 else ("★★ " if qtd >= 5 else "★  ")
        print(f"  {i:<4} {ip:<18} {qtd:<10} {ameaca}")
        resultado.append({"ip": ip, "eventos": qtd, "ameaca": ameaca.strip()})

    print("=" * 45)
    return resultado


# ---------------------------------------------------------------------------
# 6. Exportar relatório JSON
# ---------------------------------------------------------------------------

def exportar_relatorio_json(dados: dict, caminho: str) -> None:
    """Salva relatório completo em JSON formatado."""
    try:
        os.makedirs(os.path.dirname(caminho) if os.path.dirname(caminho) else ".", exist_ok=True)
        with open(caminho, "w", encoding="utf-8") as arquivo:
            json.dump(dados, arquivo, indent=2, ensure_ascii=False)
        print(f"\n  [✓] Relatório salvo em: {caminho}")
    except OSError as e:
        print(f"\n  [!] Erro ao salvar relatório: {e}")


def menu_exportar_json(eventos: list, alertas: list, cache_enriquecimento: dict) -> None:
    """Gera e salva o relatório JSON completo."""
    os.makedirs("saida", exist_ok=True)
    timestamp = datetime.now().strftime("relatorio_%Y%m%d_%H%M%S.json")
    caminho = os.path.join("saida", timestamp)

    dados = {
        "gerado_em": datetime.now().isoformat(),
        "total_eventos": len(eventos),
        "total_alertas": len(alertas),
        "eventos": eventos,
        "alertas": alertas,
        "enriquecimento": cache_enriquecimento,
    }

    exportar_relatorio_json(dados, caminho)


# ---------------------------------------------------------------------------
# 7. Exibir tabela formatada no terminal
# ---------------------------------------------------------------------------

def exibir_tabela(dados: list, colunas: list) -> None:
    """Exibe uma lista de dicts como tabela formatada no terminal."""
    if not dados:
        print("  (sem dados)")
        return

    # Largura mínima = nome da coluna
    larguras = {col: len(col) for col in colunas}
    for item in dados:
        for col in colunas:
            valor = str(item.get(col, ""))
            if len(valor) > larguras[col]:
                larguras[col] = len(valor)

    # Cabeçalho
    cabecalho = "  " + "  ".join(f"{col:<{larguras[col]}}" for col in colunas)
    separador = "  " + "  ".join("-" * larguras[col] for col in colunas)
    print(cabecalho)
    print(separador)

    # Linhas
    for item in dados:
        linha = "  " + "  ".join(
            f"{str(item.get(col, '')):<{larguras[col]}}" for col in colunas
        )
        print(linha)


# ---------------------------------------------------------------------------
# 8. Alertas por severidade
# ---------------------------------------------------------------------------

def exibir_alertas_por_severidade(alertas: list) -> None:
    """Agrupa e exibe alertas organizados por nível de severidade."""
    grupos: dict = {}
    for alerta in alertas:
        sev = alerta.get("severidade", "DESCONHECIDO")
        grupos.setdefault(sev, []).append(alerta)

    ordem = ["CRITICO", "ALTO", "MEDIO", "BAIXO", "DESCONHECIDO"]
    colunas = ["ip", "regra", "descricao"]

    print(f"\n{'=' * 45}")
    print("  ALERTAS POR SEVERIDADE")
    print("=" * 45)

    for sev in ordem:
        if sev in grupos:
            print(f"\n  [{sev}] — {len(grupos[sev])} alerta(s)")
            exibir_tabela(grupos[sev], colunas)

    # Severidades não previstas na ordem
    for sev, items in grupos.items():
        if sev not in ordem:
            print(f"\n  [{sev}] — {len(items)} alerta(s)")
            exibir_tabela(items, colunas)

    print("=" * 45)
