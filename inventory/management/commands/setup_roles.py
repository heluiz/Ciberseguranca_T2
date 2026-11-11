from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group, Permission


class Command(BaseCommand):
    help = "Cria/atualiza grupos Administrador, Analista e Leitor sem criar senhas."

    def handle(self, *args, **options):
        perms = Permission.objects.filter(content_type__app_label="inventory")
        for name in ("Administrador", "Analista", "Leitor"):
            group, _ = Group.objects.get_or_create(name=name)
            selected = perms
            if name == "Leitor":
                selected = perms.filter(codename__startswith="view_").exclude(
                    codename="view_auditevent"
                )
            elif name == "Analista":
                selected = perms.exclude(
                    content_type__model__in=["auditevent", "importreceipt"]
                )
            group.permissions.set(selected)
        self.stdout.write(
            "Grupos configurados. Use createsuperuser para a primeira conta."
        )
