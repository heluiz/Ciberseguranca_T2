"""Senhas: Argon2id com sal, recálculo do hash e política (card S5_08).

A política está em docs/SENHAS-E-ACESSO.md; aqui cada regra é conferida.
"""

import pytest
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import (
    Argon2PasswordHasher,
    check_password,
    identify_hasher,
    make_password,
)
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.test import RequestFactory, override_settings

from academic import senhas_lab

SENHA = "uma-frase-longa-de-teste-2026"


def entrar(username, password):
    """authenticate() com um pedido, como exige o django-axes."""
    return authenticate(RequestFactory().post("/entrar/"), username=username,
                        password=password)


def test_mesma_senha_hashes_diferentes_e_ambos_conferem():
    um, outro = make_password(SENHA), make_password(SENHA)
    assert um != outro
    assert um.startswith("argon2$argon2id$")
    assert check_password(SENHA, um) and check_password(SENHA, outro)
    assert not check_password(SENHA + "x", um)


def test_sha256_e_deterministico_e_mais_rapido():
    assert senhas_lab.sha256(SENHA) == senhas_lab.sha256(SENHA)
    t_sha = senhas_lab.medir(lambda: senhas_lab.sha256(SENHA), 1000)
    t_argon = senhas_lab.medir(lambda: senhas_lab.argon2id(SENHA), 3)
    assert t_argon > 100 * t_sha


@pytest.mark.django_db
def test_hash_antigo_e_recalculado_no_proximo_login():
    """Conta com hash PBKDF2 (anterior) passa a Argon2id ao entrar."""
    user = User.objects.create_user("antiga")
    user.password = make_password(SENHA, hasher="pbkdf2_sha256")
    user.save()
    assert entrar("antiga", SENHA) is not None
    user.refresh_from_db()
    assert identify_hasher(user.password).algorithm == "argon2"


class Argon2MaisCaro(Argon2PasswordHasher):
    """Como se o projeto aumentasse o custo do Argon2 numa versão nova."""

    time_cost = Argon2PasswordHasher.time_cost + 1


@pytest.mark.django_db
def test_parametros_novos_recalculam_o_hash():
    user = User.objects.create_user("conta", password=SENHA)
    antes = user.password
    with override_settings(
        PASSWORD_HASHERS=["tests_web.test_senhas.Argon2MaisCaro"]
    ):
        assert entrar("conta", SENHA) is not None
        user.refresh_from_db()
        assert user.password != antes
        assert f"t={Argon2MaisCaro.time_cost}" in user.password


@pytest.mark.parametrize(
    "senha",
    ["curta1", "123456789012345", "password1234", "conta-leitor-1"],
)
def test_politica_recusa(senha):
    usuario = User(username="conta-leitor-1", email="leitor@example.org")
    with pytest.raises(ValidationError):
        validate_password(senha, usuario)


def test_politica_aceita_frase_longa_sem_regra_de_composicao():
    """NIST SP 800-63B: comprimento, não mistura obrigatória de símbolos."""
    validate_password("cavalo correto bateria grampo", User(username="x"))


@pytest.mark.django_db
def test_hash_nunca_aparece_em_resposta(client):
    User.objects.create_superuser("chefe", password=SENHA)
    user = User.objects.get(username="chefe")
    client.force_login(user)
    for caminho in ("/", "/auditoria/", "/dados/exportar/"):
        resposta = client.get(caminho)
        assert user.password.encode() not in resposta.content
        assert SENHA.encode() not in resposta.content


@pytest.mark.django_db
def test_cookie_de_sessao_httponly_samesite_e_validade(client, settings):
    """S5_10: atributos do cookie de sessão depois da entrada."""
    User.objects.create_user("analista", password=SENHA)
    resposta = client.post("/entrar/", {"username": "analista", "password": SENHA})
    assert resposta.status_code == 302
    cookie = resposta.cookies[settings.SESSION_COOKIE_NAME]
    assert cookie["httponly"] is True
    assert cookie["samesite"] == "Lax"
    assert int(cookie["max-age"]) == 3600
    # Secure acompanha o HTTPS (DJANGO_HTTPS=1); sem HTTPS o navegador
    # não mandaria o cookie de volta.
    assert bool(cookie["secure"]) == settings.SESSION_COOKIE_SECURE
