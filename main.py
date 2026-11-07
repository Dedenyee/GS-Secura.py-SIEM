"""
SecuraPy SIEM — Ponto de entrada e menu principal
"""

from coletor import carregar_todos_os_logs
from regras import carregar_regras, aplicar_regras
from detector import detectar_brute_force, detectar_port_scan, verificar_blacklist, gerar_resumo_ameacas
from enriquecimento import enriquecer_alertas
from relatorios import resumo_geral, filtrar_eventos, buscar_ip, top_ips, exportar_relatorio_json

PASTA_LOGS = "logs"
ARQUIVO_REGRAS = "config/regras.json"
BLACKLIST = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}


def mostrar_menu():
    print("\n+------------------------------------------+")
    print("|         SecuraPy SIEM - Menu             |")
    print("+------------------------------------------+")
    print("|  1. Carregar e processar logs            |")
    print("|  2. Resumo geral                         |")
    print("|  3. Filtrar eventos                      |")
    print("|  4. Buscar IP                            |")
    print("|  5. Top 10 IPs suspeitos                 |")
    print("|  6. Ver alertas por severidade           |")
    print("|  7. Enriquecer IPs suspeitos             |")
    print("|  8. Exportar relatorio JSON              |")
    print("|  9. Iniciar servidor de alertas          |")
    print("|  0. Sair                                 |")
    print("+------------------------------------------+")


def carregar_tudo():
    eventos = carregar_todos_os_logs(PASTA_LOGS)
    if len(eventos) == 0:
        print("[!] Nenhum evento foi carregado.")
        return [], [], {}

    total_auth = 0
    total_firewall = 0
    total_web = 0
    for evento in eventos:
        if evento["fonte"] == "auth":
            total_auth += 1
        elif evento["fonte"] == "firewall":
            total_firewall += 1
        elif evento["fonte"] == "web":
            total_web += 1

    print("    auth:", total_auth, "eventos")
    print("    firewall:", total_firewall, "eventos")
    print("    web:", total_web, "eventos")
    print("    Total:", len(eventos), "eventos carregados.")

    regras = carregar_regras(ARQUIVO_REGRAS)
    alertas = aplicar_regras(eventos, regras)
    print("   ", len(alertas), "alerta(s) gerado(s).")

    brute_force = detectar_brute_force(eventos)
    port_scan = detectar_port_scan(eventos)
    ips_blacklist, contagem_blacklist = verificar_blacklist(eventos, BLACKLIST)
    resumo = gerar_resumo_ameacas(brute_force, port_scan, ips_blacklist)

    print("    Brute Force:", len(brute_force), "IP(s) detectado(s).")
    print("    Port Scan:", len(port_scan), "IP(s) detectado(s).")
    print("    Blacklist:", len(ips_blacklist), "IP(s) encontrado(s).")
    print("    Total de IPs suspeitos:", len(resumo))

    return eventos, alertas, resumo


def opcao_filtrar(eventos):
    fonte = input("Fonte (auth / firewall / web): ").strip()
    tipo = input("Tipo  (FAIL / BLOCK / OK / ALLOW): ").strip()
    ip = input("IP    (ex: 185.220.101.1): ").strip()

    fonte = fonte or None
    tipo = tipo or None
    ip = ip or None

    resultado = filtrar_eventos(eventos, fonte, tipo, ip)
    if len(resultado) == 0:
        print("[*] Nenhum evento encontrado.")
        return

    print("\n", len(resultado), "evento(s) encontrado(s):\n")
    print(f"{'Timestamp':<22} {'Fonte':<10} {'Tipo':<8} {'IP':<18} {'Detalhes'}")
    print("-" * 80)
    for evento in resultado:
        print(
            f"{evento['timestamp']:<22} {evento['fonte']:<10} "
            f"{evento['tipo']:<8} {evento['ip']:<18} {evento['detalhes']}"
        )


def opcao_ver_alertas(alertas):
    if len(alertas) == 0:
        print("[*] Nenhum alerta registrado.")
        return

    ordem_severidade = ["CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO"]
    for severidade in ordem_severidade:
        grupo = [a for a in alertas if a["severidade"] == severidade]
        if len(grupo) > 0:
            print("\n[" + severidade + "] - " + str(len(grupo)) + " alerta(s)")
            print("-" * 60)
            for alerta in grupo:
                print(" ", alerta["timestamp"], " ", alerta["regra_nome"], " IP:", alerta["ip"])


def opcao_enriquecer(alertas, cache):
    if len(alertas) == 0:
        print("[*] Nenhum alerta para enriquecer.")
        return

    alertas_enriquecidos = enriquecer_alertas(alertas, cache)
    ips_mostrados = []
    for alerta in alertas_enriquecidos:
        ip = alerta["ip"]
        if ip not in ips_mostrados:
            ips_mostrados.append(ip)
            geo = alerta.get("geo", {})
            pais = geo.get("pais", "?")
            cidade = geo.get("cidade", "?")
            org = geo.get("org", "?")
            print(f"  {ip:<18} {pais:<5} {cidade:<20} {org}")


def main():
    eventos = []
    alertas = []
    resumo_ameacas = {}
    cache_enriquecimento = {}

    while True:
        mostrar_menu()
        try:
            opcao = int(input("\nEscolha uma opcao: ").strip())
        except ValueError:
            print("[!] Opcao invalida. Digite um numero entre 0 e 9.")
            continue

        if opcao == 1:
            eventos, alertas, resumo_ameacas = carregar_tudo()

        elif opcao == 2:
            if len(eventos) == 0:
                print("[!] Carregue os logs primeiro (opcao 1).")
            else:
                resumo_geral(eventos, alertas)

        elif opcao == 3:
            if len(eventos) == 0:
                print("[!] Carregue os logs primeiro (opcao 1).")
            else:
                opcao_filtrar(eventos)

        elif opcao == 4:
            if len(eventos) == 0:
                print("[!] Carregue os logs primeiro (opcao 1).")
            else:
                ip_busca = input("Digite o IP que deseja buscar: ").strip()
                if ip_busca:
                    buscar_ip(ip_busca, eventos, alertas, cache_enriquecimento)
                else:
                    print("[!] Voce nao digitou nenhum IP.")

        elif opcao == 5:
            if len(eventos) == 0:
                print("[!] Carregue os logs primeiro (opcao 1).")
            else:
                ranking = top_ips(eventos, 10)
                print(f"\n{'#':<4} {'IP':<20} {'Eventos':>8}  {'Blacklist?'}")
                print("-" * 50)
                for posicao, item in enumerate(ranking, start=1):
                    aviso = "*** BLACKLIST ***" if item["ip"] in BLACKLIST else ""
                    print(f"{posicao:<4} {item['ip']:<20} {item['eventos']:>8}  {aviso}")

        elif opcao == 6:
            if len(eventos) == 0:
                print("[!] Carregue os logs primeiro (opcao 1).")
            else:
                opcao_ver_alertas(alertas)

        elif opcao == 7:
            if len(eventos) == 0:
                print("[!] Carregue os logs primeiro (opcao 1).")
            else:
                opcao_enriquecer(alertas, cache_enriquecimento)

        elif opcao == 8:
            if len(eventos) == 0:
                print("[!] Carregue os logs primeiro (opcao 1).")
            else:
                dados_para_exportar = {
                    "eventos": eventos,
                    "alertas": alertas,
                    "resumo_ameacas": resumo_ameacas,
                }
                exportar_relatorio_json(dados_para_exportar, "saida/relatorio.json")

        elif opcao == 9:
            print("\n[*] Para iniciar o servidor, abra outro terminal e execute:")
            print("      python servidor_alertas.py")
            print("\n[*] Para conectar um cliente, abra mais um terminal e execute:")
            print("      python cliente_alertas.py")

        elif opcao == 0:
            print("\nEncerrando SecuraPy. Ate logo!")
            break

        else:
            print("[!] Opcao invalida. Escolha um numero entre 0 e 9.")


if __name__ == "__main__":
    main()
