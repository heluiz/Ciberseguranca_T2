"""Esquema relacional; domínio e cálculo continuam nos módulos Python originais."""

from django.conf import settings
from django.db import models
from django.db.models import Q, F
from django.db.models.functions import Lower
from classificacoes import (
    TipoEquipamento,
    OrigemVulnerabilidade,
    SituacaoTratamento,
)


def choices(enum):
    return [(x.value, x.rotulo) for x in enum]


class Asset(models.Model):
    hostname = models.CharField(max_length=63)
    tipo = models.PositiveSmallIntegerField(choices=choices(TipoEquipamento))
    custodiante = models.CharField(max_length=240)
    lotacao = models.CharField(max_length=240)
    descricao = models.CharField(max_length=2000)
    fabricante = models.CharField(max_length=60, blank=True)
    modelo = models.CharField(max_length=60, blank=True)
    numero_serie = models.CharField(max_length=60, blank=True)
    patrimonio = models.CharField(max_length=60, blank=True)
    patrimonio_key = models.CharField(
        max_length=120, null=True, unique=True, editable=False
    )
    sistema = models.CharField(max_length=60, blank=True)
    versao = models.CharField(max_length=60, blank=True)
    version = models.PositiveIntegerField(default=1)

    class Meta:
        ordering = ["id"]
        constraints = [
            models.UniqueConstraint(Lower("hostname"), name="unique_hostname"),
            models.CheckConstraint(
                condition=Q(tipo__gte=1, tipo__lte=7), name="asset_type_range"
            ),
        ]
        indexes = [models.Index(fields=["lotacao"])]

    def __str__(self):
        return self.hostname


class Vulnerability(models.Model):
    descricao = models.CharField(max_length=2000)
    origem = models.PositiveSmallIntegerField(
        choices=choices(OrigemVulnerabilidade)
    )
    cvss = models.DecimalField(max_digits=3, decimal_places=1)
    cve = models.CharField(max_length=32, null=True, blank=True, unique=True)
    cwe = models.CharField(max_length=12, null=True, blank=True)
    vetor = models.CharField(max_length=256, null=True, blank=True)
    version = models.PositiveIntegerField(default=1)

    class Meta:
        ordering = ["id"]
        constraints = [
            models.CheckConstraint(
                condition=Q(cvss__gte=0.1, cvss__lte=10), name="cvss_range"
            ),
            models.CheckConstraint(
                condition=Q(origem__gte=1, origem__lte=6), name="origin_range"
            ),
        ]
        indexes = [models.Index(fields=["cvss"])]

    def __str__(self):
        return f"{self.cve or self.pk} · {self.descricao[:70]}"


class Finding(models.Model):
    asset = models.ForeignKey(
        Asset, on_delete=models.CASCADE, related_name="findings"
    )
    vulnerability = models.ForeignKey(
        Vulnerability, on_delete=models.CASCADE, related_name="findings"
    )
    situacao = models.PositiveSmallIntegerField(
        choices=choices(SituacaoTratamento), default=1
    )
    version = models.PositiveIntegerField(default=1)
    detected_at = models.DateTimeField(null=True, blank=True, db_index=True)
    corrected_at = models.DateTimeField(null=True, blank=True, db_index=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["asset", "vulnerability"], name="unique_finding"
            ),
            models.CheckConstraint(
                condition=Q(situacao__gte=1, situacao__lte=4),
                name="status_range",
            ),
            models.CheckConstraint(
                condition=Q(corrected_at__isnull=True) | Q(situacao=3),
                name="correction_requires_corrected_status",
            ),
            models.CheckConstraint(
                condition=Q(corrected_at__isnull=True)
                | Q(detected_at__isnull=True)
                | Q(corrected_at__gte=F("detected_at")),
                name="correction_after_detection",
            ),
        ]

    def __str__(self):
        vulnerability = (
            self.vulnerability.cve
            or f"vulnerabilidade #{self.vulnerability_id}"
        )
        return f"{self.asset} · {vulnerability}"


class FindingHistory(models.Model):
    """Linha do tempo preservada mesmo após exclusão da ocorrência."""

    finding = models.ForeignKey(
        Finding, null=True, on_delete=models.SET_NULL, related_name="history"
    )
    asset_ref = models.PositiveBigIntegerField()
    vulnerability_ref = models.PositiveBigIntegerField()
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL
    )
    occurred_at = models.DateTimeField(auto_now_add=True, db_index=True)
    event = models.CharField(
        max_length=20,
        choices=[
            ("created", "Registrada"),
            ("updated", "Atualizada"),
            ("corrected", "Corrigida"),
            ("reopened", "Reaberta"),
            ("deleted", "Excluída"),
            ("imported", "Importada sem datas históricas"),
        ],
    )
    old_status = models.PositiveSmallIntegerField(
        null=True, choices=choices(SituacaoTratamento)
    )
    new_status = models.PositiveSmallIntegerField(
        null=True, choices=choices(SituacaoTratamento)
    )
    old_detected_at = models.DateTimeField(null=True)
    new_detected_at = models.DateTimeField(null=True)
    old_corrected_at = models.DateTimeField(null=True)
    new_corrected_at = models.DateTimeField(null=True)

    class Meta:
        ordering = ["-id"]
        default_permissions = ("view",)


class Dependency(models.Model):
    source = models.ForeignKey(
        Asset, on_delete=models.CASCADE, related_name="dependencies"
    )
    target = models.ForeignKey(
        Asset, on_delete=models.CASCADE, related_name="dependents"
    )
    fracao = models.DecimalField(max_digits=5, decimal_places=4)
    version = models.PositiveIntegerField(default=1)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["source", "target"], name="unique_dependency"
            ),
            models.CheckConstraint(
                condition=~Q(source=F("target")), name="no_self_dependency"
            ),
            models.CheckConstraint(
                condition=Q(fracao__gt=0, fracao__lt=1), name="fraction_range"
            ),
        ]

    def __str__(self):
        fraction = format(self.fracao.normalize(), "f").replace(".", ",")
        return f"{self.source} depende de {self.target} (fração {fraction})"


# Rótulos da auditoria em português.
AUDIT_VERBS = {
    "add": "Cadastro",
    "change": "Alteração",
    "delete": "Exclusão",
    "view": "Consulta",
}
AUDIT_NOUNS = {
    "asset": "ativo",
    "vulnerability": "vulnerabilidade",
    "finding": "tratamento",
    "dependency": "dependência",
    "auditevent": "auditoria",
    "findinghistory": "histórico de tratamentos",
    "importreceipt": "importação",
    "apikey": "chave de API",
}
AUDIT_FIXED = {
    "login": "Entrada no sistema",
    "logout": "Saída do sistema",
    "login_failed": "Tentativa de entrada recusada",
    "import": "Importação do inventário (JSON)",
    "token": "Emissão de token da API",  # nosec B105
}


def describe_permission(code):
    """'add_asset' -> 'Cadastro de ativo'."""
    verb, _, noun = code.partition("_")
    return f"{AUDIT_VERBS.get(verb, verb)} de {AUDIT_NOUNS.get(noun, noun)}"


class AuditEvent(models.Model):
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL
    )
    occurred_at = models.DateTimeField(auto_now_add=True, db_index=True)
    action = models.CharField(max_length=64)
    target = models.CharField(max_length=80)

    @property
    def descricao(self):
        """Ação em português, para a tela de auditoria."""
        if self.action in AUDIT_FIXED:
            return AUDIT_FIXED[self.action]
        if self.action == "denied":
            return "Acesso negado: " + describe_permission(self.target).lower()
        return describe_permission(self.action)

    @property
    def alvo(self):
        """Registro afetado, quando a ação se refere a um."""
        if self.action in ("login", "logout", "login_failed", "denied", "token"):
            return "—"
        if self.action == "import":
            return f"arquivo {self.target[:12]}…"
        return f"#{self.target}"

    # Sem senhas, tokens, nomes de pessoas nem conteúdo de inventário no log.
    class Meta:
        ordering = ["-id"]
        default_permissions = ("view",)


class ImportReceipt(models.Model):
    digest = models.CharField(max_length=64, unique=True)
    imported_at = models.DateTimeField(auto_now_add=True)
    assets = models.PositiveIntegerField()


class ApiKey(models.Model):
    """Chave de API de uma conta (card S5_09).

    A chave tem 256 bits aleatórios (módulo secrets) e só aparece uma vez,
    ao ser criada. O banco guarda o SHA-256 dela: para um segredo aleatório
    desse tamanho, um hash rápido basta (não há dicionário a atacar), ao
    contrário das senhas, que usam Argon2. O prefixo identifica a chave em
    listas e na revogação sem revelar o segredo.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="api_keys"
    )
    name = models.CharField(max_length=80)
    prefix = models.CharField(max_length=12, unique=True)
    key_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["id"]

    def __str__(self):
        situacao = "revogada" if self.revoked_at else "ativa"
        return f"{self.prefix}… ({self.name}, {situacao})"
