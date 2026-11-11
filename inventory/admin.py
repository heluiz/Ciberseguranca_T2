"""Admin somente para contas/grupos/MFA. Inventário passa pelos serviços validados."""

from django.contrib import admin
from .models import AuditEvent


@admin.register(AuditEvent)
class AuditAdmin(admin.ModelAdmin):
    list_display = ["occurred_at", "actor", "action", "target"]
    readonly_fields = ["occurred_at", "actor", "action", "target"]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
