from django.contrib import admin
from django.contrib.auth.views import (
    LogoutView,
    PasswordChangeView,
    PasswordChangeDoneView,
)
from django.urls import path
from inventory import views

urlpatterns = [
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
    path("relatorios/", views.reports, name="reports"),
    path("auditoria/", views.audit_log, name="audit"),
    path("dados/", views.transfer, name="transfer"),
    path("dados/exportar/", views.export, name="export"),
    path("cve/", views.cve_search, name="cve"),
    path("api/<str:kind>/", views.rest, name="rest_collection"),
    path("api/<str:kind>/<int:pk>/", views.rest, name="rest_detail"),
    path("registros/<str:kind>/", views.collection, name="collection"),
    path("registros/<str:kind>/novo/", views.edit, name="create"),
    path("registros/<str:kind>/<int:pk>/", views.edit, name="edit"),
    path(
        "registros/<str:kind>/<int:pk>/excluir/", views.remove, name="delete"
    ),
]
