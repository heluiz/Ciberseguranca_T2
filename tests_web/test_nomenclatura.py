"""Padrão de nomes e portas do servidor compartilhado (card S5_20)."""

import re
from pathlib import Path

import pytest
import yaml

ID = "trab02_2026_2_12621cbs200"
PORTA = 2000 + 200  # 2000 + os três últimos dígitos da matrícula 12621CBS200
# Letras minúsculas, dígitos e sublinhado: sem espaços, acentos ou hífens.
PADRAO = re.compile(rf"^{ID}(_[a-z0-9]+)*$")


def carregar(nome):
    return yaml.safe_load(Path(nome).read_text(encoding="utf-8"))


@pytest.mark.parametrize("arquivo", ["compose.servidor.yaml", "compose.yaml"])
def test_projeto_containers_imagens_e_volumes_seguem_o_identificador(arquivo):
    compose = carregar(arquivo)
    assert compose["name"] == ID
    for nome, servico in compose["services"].items():
        assert PADRAO.match(servico["container_name"]), (nome, servico)
        if "build" in servico:
            imagem, _, versao = servico["image"].partition(":")
            assert PADRAO.match(imagem) and versao, (nome, servico["image"])
    for volume in compose["volumes"].values():
        assert PADRAO.match(volume["name"]), volume


def test_so_a_web_publica_porta_e_e_a_da_matricula():
    servicos = carregar("compose.servidor.yaml")["services"]
    publicam = {n: s["ports"] for n, s in servicos.items() if s.get("ports")}
    assert list(publicam) == ["app"]
    assert publicam["app"] == ["${SENTINEL_PORT:-%d}:8000" % PORTA]
    assert servicos["app"]["container_name"] == ID
    # O menu de terminal não mapeia porta (o card proíbe para apps de terminal).
    assert "ports" not in servicos["terminal"]
    assert servicos["terminal"]["stdin_open"] and servicos["terminal"]["tty"]


def test_todos_os_servicos_tem_endurecimento_e_limites():
    for arquivo in ("compose.servidor.yaml", "compose.yaml"):
        for nome, servico in carregar(arquivo)["services"].items():
            assert "no-new-privileges:true" in servico["security_opt"], nome
            assert servico.get("mem_limit") and servico.get("pids_limit"), nome
            if nome != "db":
                assert servico.get("read_only") is True, nome
                assert servico.get("cap_drop") == ["ALL"], nome


def test_scripts_do_servidor_usam_a_porta_e_os_nomes_do_padrao():
    subir = Path("ops/servidor/subir.sh").read_text(encoding="utf-8")
    assert "SENTINEL_PORT=${SENTINEL_PORT:-%d}" % PORTA in subir
    assert f"'{ID}_db_data'" in subir
    verificar = Path("ops/servidor/verificar.sh").read_text(encoding="utf-8")
    assert f"{ID}_terminal" in verificar and str(PORTA) in verificar


class _ComTagsDoCompose(yaml.SafeLoader):
    """Aceita a marca !reset do Compose (vira uma lista vazia)."""


_ComTagsDoCompose.add_constructor("!reset", lambda loader, node: [])


def test_laboratorio_tls_so_no_computador_e_com_os_nomes():
    """compose.tls.yaml (S5_11): proxy só em 127.0.0.1, app sem porta própria."""
    texto = Path("compose.tls.yaml").read_text(encoding="utf-8")
    tls = yaml.load(texto, Loader=_ComTagsDoCompose)
    assert "ports: !reset []" in texto
    proxy = tls["services"]["proxy"]
    assert PADRAO.match(proxy["container_name"])
    assert all(p.startswith("127.0.0.1:") for p in proxy["ports"])
    assert proxy["read_only"] and proxy["cap_drop"] == ["ALL"]
    assert tls["services"]["app"]["environment"]["DJANGO_HTTPS"] == "1"
    for volume in tls["volumes"].values():
        assert PADRAO.match(volume["name"]), volume
    caddy = Path("ops/Caddyfile.lab").read_text(encoding="utf-8")
    assert "tls internal" in caddy and "redir https://{host}:8443{uri}" in caddy
