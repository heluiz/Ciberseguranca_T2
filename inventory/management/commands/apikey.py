"""Chaves de API (card S5_09).

    python manage.py apikey criar CONTA NOME     mostra a chave uma única vez
    python manage.py apikey listar               prefixo, conta, nome, situação
    python manage.py apikey revogar PREFIXO      a chave deixa de valer na hora

Para trocar uma chave (rotação): crie a nova, atualize quem a usa e revogue a
antiga. O banco guarda só o SHA-256 da chave, nunca o texto.
"""

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from inventory.api_v1 import create_api_key
from inventory.models import ApiKey
from inventory.services import audit


class Command(BaseCommand):
    help = "Cria, lista e revoga chaves de API."

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest="acao", required=True)
        criar = sub.add_parser("criar")
        criar.add_argument("conta")
        criar.add_argument("nome")
        sub.add_parser("listar")
        revogar = sub.add_parser("revogar")
        revogar.add_argument("prefixo")

    def handle(self, *args, **options):
        acao = options["acao"]
        if acao == "criar":
            user = get_user_model().objects.filter(username=options["conta"]).first()
            if user is None or not user.is_active:
                raise CommandError("Conta inexistente ou desativada.")
            record, key = create_api_key(user, options["nome"])
            audit(user, "add_apikey", record.pk)
            self.stdout.write(
                "Chave criada. Guarde-a agora: ela não será mostrada de novo.\n"
                f"  {key}\n"
                "Use no cabeçalho: X-API-Key: <chave>"
            )
        elif acao == "listar":
            for record in ApiKey.objects.select_related("user"):
                self.stdout.write(
                    f"{record.prefix}  {record.user.get_username():<20} {record.name:<30} "
                    + ("revogada" if record.revoked_at else "ativa")
                )
        else:
            count = ApiKey.objects.filter(
                prefix=options["prefixo"], revoked_at__isnull=True
            ).update(revoked_at=timezone.now())
            if not count:
                raise CommandError("Nenhuma chave ativa com esse prefixo.")
            self.stdout.write("Chave revogada.")
