"""Preparação de uma instalação: esquema, grupos, primeira conta e dados de exemplo.

Pode ser executado quantas vezes for preciso: cada etapa só age se ainda
não foi feita. Nenhuma senha é escrita na saída.
"""

import os

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError

from inventory.models import Asset, Vulnerability
from inventory.services import import_json

EXAMPLE = "dados_exemplo/inventario_exemplo.json"


class Command(BaseCommand):
    help = (
        "Aplica migrações, cria os grupos, cria o administrador inicial "
        "(SENTINEL_ADMIN_USER/SENTINEL_ADMIN_PASSWORD) e, com SENTINEL_DEMO=1, "
        "carrega os dados de exemplo em uma base vazia."
    )

    def handle(self, *args, **options):
        call_command("migrate", interactive=False, verbosity=0)
        self.stdout.write("Esquema do banco atualizado.")
        call_command("setup_roles", verbosity=0)
        self.stdout.write(
            "Grupos Administrador, Analista e Leitor conferidos."
        )
        self.create_admin()
        self.load_example()

    def create_admin(self):
        User = get_user_model()
        if User.objects.filter(is_superuser=True, is_active=True).exists():
            self.stdout.write("Administrador já existe; nada a criar.")
            return
        username = os.getenv("SENTINEL_ADMIN_USER", "").strip()
        password = os.getenv("SENTINEL_ADMIN_PASSWORD", "")
        if not username or not password:
            self.stdout.write(
                "Sem SENTINEL_ADMIN_USER/SENTINEL_ADMIN_PASSWORD: crie a conta "
                "com 'python manage.py createsuperuser'."
            )
            return
        if len(password) < 12:
            raise CommandError(
                "SENTINEL_ADMIN_PASSWORD precisa ter 12 caracteres ou mais."
            )
        User.objects.create_superuser(username=username, password=password)
        self.stdout.write(f"Administrador inicial '{username}' criado.")

    def load_example(self):
        if os.getenv("SENTINEL_DEMO", "0") != "1":
            return
        if Asset.objects.exists() or Vulnerability.objects.exists():
            self.stdout.write(
                "Inventário já tem dados; exemplo não carregado."
            )
            return
        with open(EXAMPLE, "rb") as file:
            self.stdout.write(import_json(file.read()))
