"""Verifica navegação real e gera capturas com dados de exemplo (execução local)."""

import os
import sys
import secrets
import subprocess
import time
from pathlib import Path
import urllib.request
import tempfile
import re

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
test_hostname = "PC-BROWSER-" + secrets.token_hex(3).upper()
user = get_user_model().objects.create_superuser(
    "browser-" + secrets.token_hex(4), password=password, first_name="Heluiz"
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
            viewport={"width": 1600, "height": 1000},
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
        if os.environ.get("CAPTURE_EFFECTS") == "1":
            page.emulate_media(reduced_motion="no-preference")
            page.locator("#motion-toggle").click()
            with tempfile.TemporaryDirectory() as frame_dir:
                for frame in range(32):
                    page.screenshot(
                        path=str(Path(frame_dir) / f"frame-{frame:03d}.png")
                    )
                    page.wait_for_timeout(90)
                subprocess.run(
                    [
                        "ffmpeg",
                        "-y",
                        "-loglevel",
                        "error",
                        "-framerate",
                        "8",
                        "-i",
                        str(Path(frame_dir) / "frame-%03d.png"),
                        "-vf",
                        "scale=1280:-2",
                        "-c:v",
                        "libx264",
                        "-pix_fmt",
                        "yuv420p",
                        "-movflags",
                        "+faststart",
                        str(out / "sentinel-neon.mp4"),
                    ],
                    check=True,
                )
            page.locator("#motion-toggle").click()
            page.emulate_media(reduced_motion="reduce")
        assert page.locator(".asset-node").count() > 1
        assert (
            page.locator(".node-card").count()
            == page.locator(".asset-node").count()
        )
        page.get_by_role("button", name="Simular correção").click()
        page.get_by_text("Nenhum dado foi alterado.", exact=False).wait_for()
        page.locator("#motion-toggle").click()
        page.locator("#graph-scope").select_option("all")
        assert page.locator(".asset-node").count() == 76
        # Confere a geometria desenhada: o caminho começa no emissor de risco
        # e termina no ativo que o herda, inclusive nas relações recíprocas.
        data = page.request.get("http://127.0.0.1:8765/api/grafo/").json()
        drawn_paths = {}
        api_edges = [
            item["data"]
            for item in data["elements"]
            if "source" in item["data"]
        ]
        assert page.locator(".connection").count() == len(api_edges)
        for edge in api_edges:
            group = page.locator(f'.connection[data-edge-id="{edge["id"]}"]')
            assert group.get_attribute("data-risk-source") == edge["target"]
            assert group.get_attribute("data-risk-target") == edge["source"]
            path = group.locator(".wire-line").get_attribute("d")
            numbers = [float(n) for n in re.findall(r"-?\d+(?:\.\d+)?", path)]
            source_transform = page.locator(
                f'.asset-node[data-id="{edge["target"]}"]'
            ).get_attribute("transform")
            target_transform = page.locator(
                f'.asset-node[data-id="{edge["source"]}"]'
            ).get_attribute("transform")
            sx, sy = [
                float(n)
                for n in re.findall(r"-?\d+(?:\.\d+)?", source_transform)
            ]
            tx, ty = [
                float(n)
                for n in re.findall(r"-?\d+(?:\.\d+)?", target_transform)
            ]
            assert abs(numbers[0] - (sx + 99)) == 96
            assert numbers[1] == sy + 43
            assert abs(numbers[-2] - (tx + 99)) == 104
            assert numbers[-1] == ty + 43
            assert group.locator(".wire-line").get_attribute("marker-end")
            drawn_paths[(edge["source"], edge["target"])] = path
        reciprocal = [(a, b) for a, b in drawn_paths if (b, a) in drawn_paths]
        assert reciprocal
        for a, b in reciprocal:
            assert drawn_paths[(a, b)] != drawn_paths[(b, a)]
        page.locator("#graph-scope").select_option("focus")
        page.locator("#graph-search").fill("BANCO")
        assert page.locator("#graph-results button").count() > 0
        page.locator("#graph-results button").first.click()
        page.screenshot(path=str(out / "mapa-foco.png"), full_page=True)
        page.set_viewport_size({"width": 390, "height": 844})
        assert page.evaluate(
            "document.documentElement.scrollWidth <= window.innerWidth"
        )
        page.screenshot(path=str(out / "mapa-mobile.png"), full_page=True)
        page.set_viewport_size({"width": 1600, "height": 1000})
        for route in ["asset", "vulnerability", "finding", "dependency"]:
            page.goto(f"http://127.0.0.1:8765/registros/{route}/")
            assert page.locator("table").is_visible()
        page.goto("http://127.0.0.1:8765/registros/asset/novo/")
        page.locator("[name=hostname]").fill(test_hostname)
        page.locator("[name=tipo]").select_option("1")
        page.locator("[name=custodiante]").fill("Suporte")
        page.locator("[name=lotacao]").fill("Laboratório")
        page.locator("[name=descricao]").fill("Teste de cadastro no navegador")
        page.get_by_role("button", name="Salvar registro").click()
        page.wait_for_url("**/registros/asset/")
        page.locator("#q").fill(test_hostname)
        page.get_by_role("button", name="Buscar", exact=True).last.click()
        assert page.get_by_text(test_hostname, exact=True).is_visible()
        page.get_by_role("link", name="Editar", exact=True).click()
        page.locator("[name=descricao]").fill("Edição pelo navegador")
        page.get_by_role("button", name="Salvar registro").click()
        page.locator("#q").fill(test_hostname)
        page.get_by_role("button", name="Buscar", exact=True).last.click()
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
    from inventory.models import Asset

    Asset.objects.filter(hostname=test_hostname).delete()
    user.delete()
