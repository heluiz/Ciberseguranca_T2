"""Provisionamento local de MFA sem expor a semente nos logs do servidor."""

import json
import os
import secrets
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.plugins.otp_static.models import StaticDevice, StaticToken


class Command(BaseCommand):
    help = "Gera URI TOTP e 8 códigos de recuperação em arquivo privado novo (modo 0600)."

    def add_arguments(self, parser):
        parser.add_argument("username")
        parser.add_argument("--output", required=True)

    def handle(self, *args, **options):
        user = get_user_model().objects.get(username=options["username"])
        if TOTPDevice.objects.filter(user=user).exists():
            raise CommandError(
                "Já existe dispositivo. Revogue-o com procedimento administrativo antes de reprovisionar."
            )
        fd = os.open(
            options["output"], os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
        )
        try:
            with transaction.atomic():
                device = TOTPDevice.objects.create(
                    user=user, name="Autenticador", confirmed=True
                )
                backup = StaticDevice.objects.create(
                    user=user, name="Recuperação"
                )
                codes = [secrets.token_hex(8) for _ in range(8)]
                for code in codes:
                    StaticToken.objects.create(device=backup, token=code)
                with os.fdopen(fd, "w") as file:
                    json.dump(
                        {
                            "totp_uri": device.config_url,
                            "recovery_codes": codes,
                        },
                        file,
                    )
        except Exception:
            os.unlink(options["output"])
            raise
        self.stdout.write(
            "Arquivo privado criado. Entregue ao titular por canal seguro e remova a cópia após configurar."
        )
