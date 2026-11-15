"""Dados exibidos em todas as páginas."""

from classificacoes import SituacaoTratamento

from .models import Finding


def alerts(request):
    """Número de tratamentos em aberto, para o sino do cabeçalho."""
    user = getattr(request, "user", None)
    if not (
        user
        and user.is_authenticated
        and user.has_perm("inventory.view_finding")
    ):
        return {}
    return {
        "open_findings": Finding.objects.filter(
            situacao=SituacaoTratamento.ABERTA.value
        ).count()
    }
