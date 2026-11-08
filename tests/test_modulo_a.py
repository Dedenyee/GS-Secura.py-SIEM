"""Cenarios de teste A1-A4 do enunciado (nucleo integrado na nova arquitetura)."""

import socket
import time

from alertas import servidor_alertas
from core.coletor import carregar_log, carregar_todos_os_logs
from core.detector import detectar_brute_force_janela
from core.pipeline import analisar_eventos, processar_logs

IPS_MALICIOSOS = {"185.220.101.1", "45.33.32.156", "91.240.118.172"}


def test_a1_carrega_3_logs_com_fonte_correta(pasta_logs):
    eventos = carregar_todos_os_logs(pasta_logs)
    assert len(eventos) == 58
    contagem = {}
    for e in eventos:
        contagem[e["fonte"]] = contagem.get(e["fonte"], 0) + 1
    assert contagem == {"auth": 23, "firewall": 17, "web": 18}


def test_a2_brute_force_185_alta():
    r = processar_logs()
    bf = r["brute_force"]["185.220.101.1"]
    assert bf["tentativas"] >= 10
    assert bf["severidade"] == "ALTA"


def test_a3_port_scan_185_sete_portas():
    r = processar_logs()
    assert r["port_scan"]["185.220.101.1"]["quantidade"] == 7


def test_a4_blacklist_intersecao_3_ips():
    r = processar_logs()
    assert set(r["blacklist"]) == IPS_MALICIOSOS


def test_ameaca_mais_grave_e_185_com_3_deteccoes():
    topo = processar_logs()["ameacas"][0]
    assert topo["ip"] == "185.220.101.1"
    assert set(topo["deteccoes"]) == {"brute_force", "port_scan", "blacklist"}


def test_log_malformado_nao_trava(criar_arquivo_log):
    caminho = criar_arquivo_log("auth.log", "lixo\n\n2025-02-20 08:15:01 FAIL usuario=a ip=1.2.3.4\n%%%\n")
    assert len(carregar_log(caminho, "auth")) == 1


def test_pasta_inexistente_retorna_vazio():
    assert carregar_todos_os_logs("nao/existe") == []
    assert analisar_eventos([])["ameacas"] == []


def test_bonus_brute_force_em_janela_de_tempo():
    r = processar_logs()
    janela = detectar_brute_force_janela(r["eventos"], threshold=5, janela_segundos=30)
    assert "185.220.101.1" in janela
    assert "45.33.32.156" not in janela


def test_servidor_background_faz_broadcast():
    servidor = servidor_alertas.iniciar_em_background("127.0.0.1", 19899)
    try:
        cliente = socket.create_connection(("127.0.0.1", 19899), timeout=3)
        assert "Bem-vindo" in cliente.recv(1024).decode()
        time.sleep(0.2)
        servidor_alertas.broadcast_alerta({"timestamp": "2025-02-20 08:15:01", "severidade": "CRITICA",
                                           "regra_nome": "Teste", "ip": "1.2.3.4", "descricao": "x"})
        assert "CRITICA" in cliente.recv(1024).decode()
        cliente.sendall(b"/sair")
        cliente.close()
    finally:
        servidor.close()


def test_resumo_aceita_set_da_blacklist_como_a_api_chama():
    """api/app.py chama gerar_resumo_ameacas(brute, scan, ips_blacklist) so com o set."""
    from core.detector import detectar_brute_force, detectar_port_scan, gerar_resumo_ameacas, verificar_blacklist
    r = processar_logs()
    ips, _ = verificar_blacklist(r["eventos"], IPS_MALICIOSOS)
    resumo = gerar_resumo_ameacas(detectar_brute_force(r["eventos"]), detectar_port_scan(r["eventos"]), ips)
    assert resumo[0]["ip"] == "185.220.101.1"
    assert set(resumo[0]["deteccoes"]) == {"brute_force", "port_scan", "blacklist"}
