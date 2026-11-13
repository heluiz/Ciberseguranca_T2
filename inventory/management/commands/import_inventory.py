from pathlib import Path
from django.core.management.base import BaseCommand, CommandError
from inventory.services import import_json


class Command(BaseCommand):
    help = "Importação inicial transacional e idempotente do JSON legado."

    def add_arguments(self, parser):
        parser.add_argument("path")
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, **options):
        path = Path(options["path"])
        if path.stat().st_size > 2 * 1024 * 1024:
            raise CommandError("Arquivo excede 2 MB.")
        try:
            self.stdout.write(
                import_json(path.read_bytes(), dry_run=options["dry_run"])
            )
        except (ValueError, UnicodeDecodeError) as error:
            raise CommandError(str(error)) from error
