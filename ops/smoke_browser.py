"""Verifica navegação real e gera capturas com dados de exemplo (execução local)."""

import os
import sys
import secrets
import subprocess
import time
from pathlib import Path
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "sentinel.settings")
import django

django.setup()
from django.contrib.auth import get_user_model
from playwright.sync_api import sync_playwright

root = Path(__file__).resolve().parent.parent
out = root / "docs/web/screenshots"
out.mkdir(parents=True, exist_ok=True)
password = secrets.token_urlsafe(32)
user = get_user_model().objects.create_superuser(
    "browser-" + secrets.token_hex(4), password=password
)
server = subprocess.Popen(
    [
        str(root / ".venv/bin/python"),
        "manage.py",
        "runserver",
        "127.0.0.1:8765",
        "--noreload",
    ],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
try:
    for _ in range(80):
        try:
            urllib.request.urlopen("http://127.0.0.1:8765/health/", timeout=1)
            break
        except Exception:
            time.sleep(0.1)
    with sync_playwright() as p:
        browser = p.chromium.launch(
            executable_path=os.environ.get(
                "CHROMIUM_EXECUTABLE", "/usr/bin/chromium"
            ),
            args=[
                "--no-sandbox",
                "--no-process-singleton",
                "--no-zygote",
                "--single-process",
                "--disable-gpu",
            ],
        )
        page = browser.new_page(
            viewport={"width": 1440, "height": 1080},
            device_scale_factor=1,
            reduced_motion="reduce",
        )
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto("http://127.0.0.1:8765/entrar/")
        page.locator("[name=username]").fill(user.username)
        page.locator("[name=password]").fill(password)
        page.get_by_role("button", name="Entrar").click()
        page.wait_for_url("http://127.0.0.1:8765/")
        assert page.get_by_role("heading", name="Visão geral.").is_visible()
        page.screenshot(path=str(out / "painel-desktop.png"), full_page=True)
        page.goto("http://127.0.0.1:8765/mapa/")
        page.get_by_text("76 ativos ·", exact=False).wait_for()
        page.wait_for_timeout(800)
        page.screenshot(path=str(out / "mapa-desktop.png"), full_page=True)
        page.locator("#graph-search").fill("BANCO")
        for route in ["asset", "vulnerability", "finding", "dependency"]:
            page.goto(f"http://127.0.0.1:8765/registros/{route}/")
            assert page.locator("table").is_visible()
        page.goto("http://127.0.0.1:8765/registros/asset/novo/")
        page.locator("[name=hostname]").fill("PC-BROWSER-TESTE")
        page.locator("[name=tipo]").select_option("1")
        page.locator("[name=custodiante]").fill("Suporte")
        page.locator("[name=lotacao]").fill("Laboratório")
        page.locator("[name=descricao]").fill("Teste de cadastro no navegador")
        page.get_by_role("button", name="Salvar registro").click()
        page.wait_for_url("**/registros/asset/")
        page.locator("[name=q]").fill("PC-BROWSER-TESTE")
        page.get_by_role("button", name="Buscar").click()
        assert page.get_by_text("PC-BROWSER-TESTE", exact=True).is_visible()
        page.get_by_role("link", name="Editar", exact=True).click()
        page.locator("[name=descricao]").fill("Edição pelo navegador")
        page.get_by_role("button", name="Salvar registro").click()
        page.locator("[name=q]").fill("PC-BROWSER-TESTE")
        page.get_by_role("button", name="Buscar").click()
        page.get_by_role("link", name="Excluir", exact=True).click()
        page.get_by_role("button", name="Confirmar exclusão").click()
        page.set_viewport_size({"width": 390, "height": 844})
        page.goto("http://127.0.0.1:8765/")
        assert page.evaluate(
            "document.documentElement.scrollWidth <= window.innerWidth"
        ), "Overflow horizontal no celular"
        page.screenshot(path=str(out / "painel-mobile.png"), full_page=True)
        assert not errors, errors
        browser.close()
        print(
            "Navegação, grafo, CRUD, viewport móvel e JavaScript: OK. Capturas geradas."
        )
finally:
    server.terminate()
    server.wait(timeout=10)
    user.delete()
