from django.contrib import admin
from django.contrib.auth.views import (
    LogoutView,
    PasswordChangeView,
    PasswordChangeDoneView,
)
from django.urls import path, re_path
from inventory import api_v1, views

urlpatterns = [
    path(
        "tratamentos/<int:pk>/historico/",
        views.finding_history,
        name="finding_history",
    ),
    path(
        "auditoria/tratamentos.csv",
        views.export_finding_history,
        name="finding_history_export",
    ),
    path("admin/", admin.site.urls),
    path("entrar/", views.SignIn.as_view(), name="login"),
    path("sair/", LogoutView.as_view(), name="logout"),
    path("mfa/", views.mfa, name="mfa"),
    path(
        "senha/",
        PasswordChangeView.as_view(
            template_name="registration/password.html",
            success_url="/senha/pronta/",
        ),
        name="password_change",
    ),
    path(
        "senha/pronta/",
        PasswordChangeDoneView.as_view(
            template_name="registration/password_done.html"
        ),
    ),
    path("health/", views.health, name="health"),
    path("", views.dashboard, name="dashboard"),
    path("ativos/<int:pk>/", views.asset_detail, name="asset_detail"),
    path(
        "api/simular/<int:pk>/",
        views.simulate_correction,
        name="simulate_correction",
    ),
    path("mapa/", views.graph, name="graph"),
    path("api/grafo/", views.graph_data, name="graph_data"),
    path("analise/", views.risk_analysis, name="risk_analysis"),
    path("api/risco/", views.risk_data, name="risk_data"),
    path("relatorios/", views.reports, name="reports"),
    path("auditoria/", views.audit_log, name="audit"),
    path("dados/", views.transfer, name="transfer"),
    path("dados/exportar/", views.export, name="export"),
    path("cve/", views.cve_search, name="cve"),
    # API pública versionada (cards S5_03, S5_04 e S5_09). Antes das rotas
    # sem versão, que as telas usam com a sessão do navegador.
    path("api/v1/", api_v1.index, name="api_v1"),
    path("api/v1/openapi.yaml", api_v1.openapi, name="api_v1_openapi"),
    path("api/v1/docs/", api_v1.docs, name="api_v1_docs"),
    path("api/v1/auth/token", api_v1.token, name="api_v1_token"),
    path("api/v1/problemas/<slug:slug>", api_v1.problem_type, name="api_v1_problem"),
    path("api/v1/risk", api_v1.risk, name="api_v1_risk"),
    path("api/v1/audit-events", api_v1.audit_events, name="api_v1_audit"),
    path(
        "api/v1/vulnerabilities/<int:pk>/assets",
        api_v1.vulnerability_assets,
        name="api_v1_vulnerability_assets",
    ),
    path(
        "api/v1/assets/<int:pk>/findings",
        api_v1.asset_findings,
        name="api_v1_asset_findings",
    ),
    path("api/v1/<str:resource>", api_v1.collection, name="api_v1_collection"),
    path(
        "api/v1/<str:resource>/<int:pk>", api_v1.detail, name="api_v1_detail"
    ),
    re_path(r"^api/v1/(?P<rest>.*)$", api_v1.not_found),
    path("api/<str:kind>/", views.rest, name="rest_collection"),
    path("api/<str:kind>/<int:pk>/", views.rest, name="rest_detail"),
    path("registros/<str:kind>/", views.collection, name="collection"),
    path("registros/<str:kind>/novo/", views.edit, name="create"),
    path("registros/<str:kind>/<int:pk>/", views.edit, name="edit"),
    path(
        "registros/<str:kind>/<int:pk>/excluir/", views.remove, name="delete"
    ),
]
