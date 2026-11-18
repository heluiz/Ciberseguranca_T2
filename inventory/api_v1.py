"""API REST pública, versão 1 (cards S5_03, S5_04, S5_09 e S5_12).

Diferenças para as rotas /api/... sem versão, que as telas usam com a
sessão do navegador:

- autenticação sem estado: JWT (``Authorization: Bearer``) emitido por
  /api/v1/auth/token ou chave de API (``X-API-Key``); não usa cookie, por
  isso não depende de CSRF;
- recursos no plural, com recursos aninhados (/vulnerabilities/{id}/assets);
- 201 com cabeçalho ``Location`` na criação, ``ETag`` com a versão do
  registro e ``If-Match`` na exclusão;
- erros no formato Problem Details (RFC 9457, application/problem+json);
- paginação com links, filtros e ordenação por risco.

O contrato completo está em docs/web/openapi.yaml, servido em
/api/v1/openapi.yaml e navegável em /api/v1/docs/.
"""

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone as dt_timezone
from decimal import Decimal
from functools import wraps
from pathlib import Path
from urllib.parse import urlencode

import jwt
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import IntegrityError
from django.forms.models import model_to_dict
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from . import analysis
from .forms import FORMS
from .models import ApiKey, Asset, AuditEvent, Finding, Vulnerability
from .repository import SnapshotRepository
from .services import Conflict, MODELS, audit, authorize, delete_entity, save_entity

API_VERSION = "1.0.0"
PREFIX = "/api/v1"
JWT_ALGORITHM = "HS256"
JWT_ISSUER = "sentinel"
JWT_AUDIENCE = "sentinel-api"
JWT_LIFETIME = timedelta(minutes=15)
ADMIN_ROLE = "Administrador"
SPEC = Path(settings.BASE_DIR) / "docs" / "web" / "openapi.yaml"

# Recurso da URL (plural, em inglês, como as tabelas) -> tipo interno.
RESOURCES = {
    "assets": "asset",
    "vulnerabilities": "vulnerability",
    "findings": "finding",
    "dependencies": "dependency",
}
KIND_TO_RESOURCE = {kind: name for name, kind in RESOURCES.items()}

PROBLEMS = {
    "requisicao-invalida": (400, "Requisição inválida"),
    "nao-autenticado": (401, "Não autenticado"),
    "sem-permissao": (403, "Sem permissão"),
    "nao-encontrado": (404, "Recurso não encontrado"),
    "metodo-nao-permitido": (405, "Método não permitido"),
    "conflito": (409, "Conflito com o estado atual"),
    "versao-obrigatoria": (428, "Versão do registro obrigatória"),
    "dados-invalidos": (422, "Dados inválidos"),
    "sistema-singular": (422, "Sistema do modelo de risco recusado"),
    "muitas-tentativas": (429, "Muitas tentativas"),
}
PROBLEM_DESCRIPTIONS = {
    "requisicao-invalida": "O corpo não é JSON válido ou um parâmetro de consulta está fora do formato.",
    "nao-autenticado": "Falta a credencial, ou o token ou a chave de API é inválido, expirou ou foi revogado.",
    "sem-permissao": "A conta está autenticada, mas o perfil dela não permite esta operação.",
    "nao-encontrado": "Não existe registro com este identificador.",
    "metodo-nao-permitido": "O endereço existe, mas não aceita este método HTTP (veja o cabeçalho Allow).",
    "conflito": "O registro mudou depois de lido (versão diferente) ou a operação repetiria um valor único.",
    "versao-obrigatoria": "Informe a versão do registro no corpo (version) ou no cabeçalho If-Match.",
    "dados-invalidos": "Um ou mais campos não passaram na validação; veja a extensão errors.",
    "sistema-singular": "I − A não é invertível ou é mal condicionada: o risco não é calculado.",
    "muitas-tentativas": "A conta foi bloqueada por senhas erradas seguidas; tente depois.",
}


class ApiError(Exception):
    """Erro que vira uma resposta Problem Details."""

    def __init__(self, slug, detail, headers=None, **extensions):
        super().__init__(detail)
        self.slug = slug
        self.detail = detail
        self.headers = headers or {}
        self.extensions = extensions


def _json(data, status=200, content_type="application/json"):
    return JsonResponse(
        data,
        status=status,
        content_type=content_type,
        json_dumps_params={"ensure_ascii": False},
    )


def problem(request, error):
    status, title = PROBLEMS[error.slug]
    response = _json(
        {
            "type": f"{PREFIX}/problemas/{error.slug}",
            "title": title,
            "status": status,
            "detail": error.detail,
            "instance": request.path,
            **error.extensions,
        },
        status=status,
        content_type="application/problem+json",
    )
    for name, value in error.headers.items():
        response[name] = value
    return response


# ---------------------------------------------------------------- credenciais


def jwt_secret():
    """Segredo do JWT: JWT_SECRET_KEY, ou derivado da chave do Django."""
    explicit = getattr(settings, "JWT_SECRET_KEY", "")
    if explicit:
        return explicit
    return hmac.new(
        settings.SECRET_KEY.encode(), b"sentinel-jwt-v1", hashlib.sha256
    ).hexdigest()


def roles_of(user):
    roles = sorted(user.groups.values_list("name", flat=True))
    if user.is_superuser and ADMIN_ROLE not in roles:
        roles.append(ADMIN_ROLE)
    return roles


def issue_token(user, now=None):
    now = now or datetime.now(dt_timezone.utc)
    payload = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "sub": str(user.pk),
        "username": user.get_username(),
        "roles": roles_of(user),
        "iat": int(now.timestamp()),
        "exp": int((now + JWT_LIFETIME).timestamp()),
        "jti": secrets.token_hex(8),
    }
    return jwt.encode(payload, jwt_secret(), algorithm=JWT_ALGORITHM)


def decode_token(token):
    """Valida assinatura, algoritmo, emissor, público e expiração."""
    return jwt.decode(
        token,
        jwt_secret(),
        algorithms=[JWT_ALGORITHM],  # nunca "none" nem o que vier no cabeçalho
        audience=JWT_AUDIENCE,
        issuer=JWT_ISSUER,
        options={"require": ["exp", "iat", "sub", "iss", "aud"]},
        leeway=5,
    )


def _key_hash(key):
    return hashlib.sha256(key.encode()).hexdigest()


def create_api_key(user, name):
    """Cria a chave e devolve (registro, chave em texto). O texto não é guardado."""
    prefix = secrets.token_hex(4)
    key = f"snt_{prefix}_{secrets.token_urlsafe(32)}"
    record = ApiKey.objects.create(
        user=user, name=name[:80], prefix=prefix, key_hash=_key_hash(key)
    )
    return record, key


def _user_from_api_key(key):
    parts = key.split("_")
    if len(parts) < 3 or parts[0] != "snt":
        return None
    record = (
        ApiKey.objects.select_related("user")
        .filter(prefix=parts[1], revoked_at__isnull=True)
        .first()
    )
    # Comparação em tempo constante: o tempo da resposta não revela quantos
    # caracteres do hash coincidem.
    if record is None or not hmac.compare_digest(record.key_hash, _key_hash(key)):
        return None
    ApiKey.objects.filter(pk=record.pk).update(last_used_at=timezone.now())
    return record.user


def authenticate_request(request):
    """Devolve (usuário, papéis). Sem credencial válida, ApiError 401."""
    bearer = 'Bearer realm="sentinel"'
    header = request.headers.get("Authorization", "")
    key = request.headers.get("X-API-Key", "")
    user, roles = None, None
    if header.startswith("Bearer "):
        try:
            claims = decode_token(header[7:].strip())
        except jwt.ExpiredSignatureError:
            raise ApiError(
                "nao-autenticado",
                "O token expirou; peça outro em /api/v1/auth/token.",
                {"WWW-Authenticate": bearer + ', error="invalid_token"'},
            )
        except jwt.InvalidTokenError:
            raise ApiError(
                "nao-autenticado",
                "Token inválido.",
                {"WWW-Authenticate": bearer + ', error="invalid_token"'},
            )
        user = get_user_model().objects.filter(pk=claims["sub"]).first()
        roles = claims.get("roles", [])
    elif key:
        user = _user_from_api_key(key)
        if user is None:
            raise ApiError("nao-autenticado", "Chave de API inválida ou revogada.")
    else:
        raise ApiError(
            "nao-autenticado",
            "Envie Authorization: Bearer <token> ou X-API-Key: <chave>.",
            {"WWW-Authenticate": bearer},
        )
    if user is None or not user.is_active:
        raise ApiError("nao-autenticado", "Conta inexistente ou desativada.")
    return user, roles if roles is not None else roles_of(user)


# ------------------------------------------------------------------ decorador


def endpoint(*methods, public=False):
    """Método permitido, autenticação e conversão de erros em Problem Details."""

    def wrap(view):
        @csrf_exempt  # sem cookie de sessão, não há CSRF a explorar
        @wraps(view)
        def inner(request, *args, **kwargs):
            try:
                if request.method not in methods:
                    raise ApiError(
                        "metodo-nao-permitido",
                        f"Use {', '.join(methods)} neste endereço.",
                        {"Allow": ", ".join(methods)},
                    )
                if not public:
                    request.api_user, request.api_roles = authenticate_request(
                        request
                    )
                return view(request, *args, **kwargs)
            except ApiError as error:
                return problem(request, error)
            except PermissionDenied:
                return problem(
                    request,
                    ApiError("sem-permissao", "O perfil da conta não permite esta operação."),
                )
            except Http404:
                return problem(
                    request, ApiError("nao-encontrado", "Registro não encontrado.")
                )
            except Conflict as error:
                return problem(request, ApiError("conflito", str(error)))
            except IntegrityError:
                return problem(
                    request,
                    ApiError("conflito", "Duplicidade ou conflito de integridade."),
                )
            except (ValueError, ValidationError) as error:
                detail = "; ".join(getattr(error, "messages", [str(error)]))
                return problem(request, ApiError("dados-invalidos", detail))

        return inner

    return wrap


# ------------------------------------------------------------ representação


def _plain(value):
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def represent(kind, obj, risk=None):
    fields = FORMS[kind]._meta.fields
    data = {"id": obj.pk}
    for name in fields:
        field = obj._meta.get_field(name)
        value = getattr(obj, field.attname)
        data[name] = _plain(value)
    if kind == "asset" and risk is not None:
        own, effective = risk.get(obj.pk, (None, None))
        data["risco"] = {"proprio": own, "efetivo": effective}
    if kind == "finding":
        data["situacao_rotulo"] = obj.get_situacao_display()
    data["links"] = {"self": f"{PREFIX}/{KIND_TO_RESOURCE[kind]}/{obj.pk}"}
    return data


def risk_by_asset():
    """{id: (próprio, efetivo)}; vazio se o sistema for recusado."""
    result = analysis.risk_analysis(SnapshotRepository())
    if result["error"]:
        return {}
    return {
        row["equipamento"].id: (round(row["proprio"], 6), round(row["efetivo"], 6))
        for row in result["rows"]
    }


def _int_param(request, name, default, low, high):
    raw = request.GET.get(name, str(default))
    try:
        value = int(raw)
    except ValueError:
        value = None
    if value is None or not low <= value <= high:
        raise ApiError(
            "requisicao-invalida", f"O parâmetro {name} deve ser inteiro entre {low} e {high}."
        )
    return value


def paginate(request, items, represent_one):
    limit = _int_param(request, "limit", 20, 1, 100)
    offset = _int_param(request, "offset", 0, 0, 2_147_483_647)
    count = len(items) if isinstance(items, list) else items.count()
    page = items[offset : offset + limit]

    def link(new_offset):
        query = request.GET.copy()
        query["offset"] = new_offset
        query["limit"] = limit
        return f"{request.path}?{urlencode(sorted(query.items()))}"

    return {
        "count": count,
        "limit": limit,
        "offset": offset,
        "results": [represent_one(item) for item in page],
        "links": {
            "self": link(offset),
            "next": link(offset + limit) if offset + limit < count else None,
            "prev": link(max(offset - limit, 0)) if offset > 0 else None,
        },
    }


def _body(request):
    try:
        data = json.loads(request.body or b"{}")
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ApiError("requisicao-invalida", "O corpo não é JSON válido.")
    if not isinstance(data, dict):
        raise ApiError("requisicao-invalida", "Envie um objeto JSON.")
    return data


def _type_errors(kind, data):
    """Tipos do JSON conferidos antes do formulário.

    O formulário converte o que recebe (um objeto vira o texto "{}", 4.0
    vira 4); numa API, o tipo errado é erro do cliente e precisa voltar 422.
    """
    model = MODELS[kind]
    errors = {}
    for name, value in data.items():
        if name == "version" or value is None:
            if name == "version" and (isinstance(value, bool) or not isinstance(value, int)):
                errors[name] = ["Deve ser um número inteiro."]
            continue
        field = model._meta.get_field(name)
        kind_name = field.get_internal_type()
        if kind_name == "CharField":
            ok = isinstance(value, str)
            expected = "texto"
        elif kind_name == "DecimalField":
            ok = isinstance(value, (int, float)) and not isinstance(value, bool)
            expected = "um número"
        elif kind_name == "DateTimeField":
            ok = isinstance(value, str)
            expected = "data e hora em texto (ISO 8601)"
        else:  # inteiros e chaves estrangeiras (identificadores)
            ok = isinstance(value, int) and not isinstance(value, bool)
            expected = "um número inteiro"
        if not ok:
            errors[name] = [f"Deve ser {expected}."]
    return errors


def _check_client(kind, data):
    """Campos e tipos do que o cliente enviou (antes de completar o PATCH)."""
    allowed = set(FORMS[kind]._meta.fields)
    extra = sorted(set(data) - allowed)
    if extra:
        raise ApiError(
            "dados-invalidos",
            "O corpo contém campos não permitidos.",
            errors={name: ["Campo não permitido."] for name in extra},
        )
    wrong = _type_errors(kind, data)
    if wrong:
        raise ApiError("dados-invalidos", "Há campos com o tipo errado.", errors=wrong)


def _validated(kind, data, instance=None):
    form = FORMS[kind](data, instance=instance)
    if not form.is_valid():
        raise ApiError(
            "dados-invalidos",
            "Corrija os campos indicados em errors.",
            errors={k: [e["message"] for e in v] for k, v in form.errors.get_json_data().items()},
        )
    return form.cleaned_data


def _version(request, data=None):
    raw = (data or {}).get("version")
    if raw is None:
        raw = request.headers.get("If-Match", "").strip('"W/ ') or request.GET.get(
            "version"
        )
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ApiError(
            "versao-obrigatoria",
            "Informe a versão do registro (campo version ou cabeçalho If-Match).",
        )
    return value


def _with_etag(response, obj):
    response["ETag"] = f'"{obj.version}"'
    return response


# ----------------------------------------------------------------- endereços


@endpoint("GET", public=True)
def index(request):
    return _json(
        {
            "version": API_VERSION,
            "links": {
                **{name: f"{PREFIX}/{name}" for name in RESOURCES},
                "risk": f"{PREFIX}/risk",
                "token": f"{PREFIX}/auth/token",
                "openapi": f"{PREFIX}/openapi.yaml",
                "docs": f"{PREFIX}/docs/",
            },
        }
    )


@endpoint("GET", "POST", "PUT", "PATCH", "DELETE", public=True)
def not_found(request, rest=""):
    """Qualquer outro endereço sob /api/v1/: 404 também em Problem Details."""
    raise ApiError("nao-encontrado", "Endereço inexistente na API v1.")


@endpoint("GET", public=True)
def problem_type(request, slug):
    if slug not in PROBLEMS:
        raise ApiError("nao-encontrado", "Tipo de problema desconhecido.")
    status, title = PROBLEMS[slug]
    return _json(
        {
            "type": f"{PREFIX}/problemas/{slug}",
            "title": title,
            "status": status,
            "description": PROBLEM_DESCRIPTIONS[slug],
        }
    )


@endpoint("GET", public=True)
def openapi(request):
    return HttpResponse(
        SPEC.read_text(encoding="utf-8"),
        content_type="application/yaml; charset=utf-8",
    )


def docs(request):
    """Swagger UI com os arquivos servidos pelo próprio site (sem CDN)."""
    return render(request, "inventory/api_docs.html")


@endpoint("POST", public=True)
def token(request):
    data = _body(request)
    username, password = data.get("username"), data.get("password")
    if (
        not isinstance(username, str)
        or not isinstance(password, str)
        or not 1 <= len(username) <= 150
        or not 1 <= len(password) <= 4096
    ):
        raise ApiError(
            "requisicao-invalida",
            "Envie username (até 150 caracteres) e password em texto.",
        )
    if set(data) - {"username", "password", "otp"}:
        raise ApiError("requisicao-invalida", "Campos aceitos: username, password e otp.")
    # Passa pelo django-axes: senhas erradas contam para o bloqueio, como
    # na tela de entrada. A senha não é registrada em lugar nenhum.
    user = authenticate(request, username=username, password=password)
    if getattr(request, "axes_locked_out", False):
        raise ApiError("muitas-tentativas", "Conta bloqueada por tentativas erradas.")
    if user is None:
        raise ApiError(
            "nao-autenticado",
            "Usuário ou senha incorretos.",
            {"WWW-Authenticate": 'Bearer realm="sentinel"'},
        )
    if settings.REQUIRE_ADMIN_MFA and (
        user.is_staff or user.is_superuser or ADMIN_ROLE in roles_of(user)
    ):
        from django_otp import match_token

        code = data.get("otp")
        if not isinstance(code, str) or match_token(user, code) is None:
            raise ApiError(
                "nao-autenticado",
                "Contas de administrador precisam do código do segundo fator (otp).",
            )
    audit(user, "token", "api")
    return _json(
        {
            "access_token": issue_token(user),
            "token_type": "Bearer",  # nosec B105
            "expires_in": int(JWT_LIFETIME.total_seconds()),
        },
        status=201,
    )


def _kind(resource):
    if resource not in RESOURCES:
        raise ApiError("nao-encontrado", "Recurso desconhecido.")
    return RESOURCES[resource]


ASSET_ORDERING = {
    "id": lambda a, r: a.pk,
    "hostname": lambda a, r: a.hostname.lower(),
    "risco": lambda a, r: (r.get(a.pk, (0, 0))[1], -a.pk),
}


@endpoint("GET", "POST")
def collection(request, resource):
    kind = _kind(resource)
    user = request.api_user
    if request.method == "POST":
        data = _body(request)
        data.setdefault("version", 1)
        _check_client(kind, data)
        cleaned = _validated(kind, data)
        obj = save_entity(user, kind, cleaned, None)
        response = _json(represent(kind, obj), status=201)
        response["Location"] = f"{PREFIX}/{resource}/{obj.pk}"
        return _with_etag(response, obj)
    authorize(user, "view_" + kind)
    queryset = MODELS[kind].objects.all().order_by("pk")
    if kind == "asset":
        tipo = request.GET.get("tipo")
        if tipo:
            queryset = queryset.filter(tipo=_int_param(request, "tipo", 0, 1, 7))
        if request.GET.get("lotacao"):
            if len(request.GET["lotacao"]) > 240:
                raise ApiError("requisicao-invalida", "lotacao tem no máximo 240 caracteres.")
            queryset = queryset.filter(lotacao=request.GET["lotacao"])
        ordering = request.GET.get("ordering", "id")
        field = ordering.lstrip("-")
        if field not in ASSET_ORDERING:
            raise ApiError(
                "requisicao-invalida",
                "ordering aceita id, hostname ou risco, com - para decrescente.",
            )
        risk = risk_by_asset()
        items = sorted(
            queryset,
            key=lambda a: ASSET_ORDERING[field](a, risk),
            reverse=ordering.startswith("-"),
        )
        return _json(paginate(request, items, lambda a: represent(kind, a, risk)))
    if kind == "finding":
        queryset = queryset.select_related("asset", "vulnerability")
        if request.GET.get("situacao"):
            queryset = queryset.filter(
                situacao=_int_param(request, "situacao", 1, 1, 4)
            )
    return _json(paginate(request, queryset, lambda o: represent(kind, o)))


@endpoint("GET", "PUT", "PATCH", "DELETE")
def detail(request, resource, pk):
    kind = _kind(resource)
    user = request.api_user
    model = MODELS[kind]
    if request.method == "GET":
        authorize(user, "view_" + kind)
        obj = model.objects.filter(pk=pk).first()
        if obj is None:
            raise Http404
        risk = risk_by_asset() if kind == "asset" else None
        return _with_etag(_json(represent(kind, obj, risk)), obj)
    if request.method == "DELETE":
        authorize(user, "delete_" + kind)
        delete_entity(user, kind, pk, _version(request))
        return HttpResponse(status=204)
    authorize(user, "change_" + kind)
    obj = model.objects.filter(pk=pk).first()
    if obj is None:
        raise Http404
    data = _body(request)
    _check_client(kind, data)
    version = _version(request, data)
    if request.method == "PATCH":
        merged = model_to_dict(obj, fields=FORMS[kind]._meta.fields)
        merged.update(data)
        data = merged
    data["version"] = version
    cleaned = _validated(kind, data, instance=obj)
    saved = save_entity(user, kind, cleaned, pk)
    risk = risk_by_asset() if kind == "asset" else None
    return _with_etag(_json(represent(kind, saved, risk)), saved)


@endpoint("GET")
def vulnerability_assets(request, pk):
    """Equipamentos afetados por uma vulnerabilidade (recurso aninhado)."""
    user = request.api_user
    for permission in ("view_vulnerability", "view_finding", "view_asset"):
        authorize(user, permission)
    if not Vulnerability.objects.filter(pk=pk).exists():
        raise Http404
    findings = (
        Finding.objects.filter(vulnerability_id=pk)
        .select_related("asset")
        .order_by("asset_id")
    )
    risk = risk_by_asset()

    def one(finding):
        data = represent("asset", finding.asset, risk)
        data["tratamento"] = represent("finding", finding)
        return data

    return _json(paginate(request, findings, one))


@endpoint("GET")
def asset_findings(request, pk):
    """Tratamentos de um equipamento (recurso aninhado)."""
    user = request.api_user
    for permission in ("view_asset", "view_finding", "view_vulnerability"):
        authorize(user, permission)
    if not Asset.objects.filter(pk=pk).exists():
        raise Http404
    findings = (
        Finding.objects.filter(asset_id=pk)
        .select_related("vulnerability")
        .order_by("vulnerability_id")
    )

    def one(finding):
        data = represent("finding", finding)
        data["vulnerabilidade"] = represent("vulnerability", finding.vulnerability)
        return data

    return _json(paginate(request, findings, one))


@endpoint("GET")
def risk(request):
    user = request.api_user
    for permission in ("view_asset", "view_vulnerability", "view_finding", "view_dependency"):
        authorize(user, permission)
    # "?cenario=" vazio também é recusado: um parâmetro presente tem de
    # ser um dos cenários (achado do schemathesis, ST201).
    scenario = request.GET.get("cenario")
    if scenario is not None and scenario not in analysis.SCENARIOS:
        raise ApiError(
            "requisicao-invalida",
            "cenario aceita: " + ", ".join(sorted(analysis.SCENARIOS)),
        )
    from .views import _analysis_repository

    result = analysis.risk_analysis(_analysis_repository(scenario))
    if result["error"]:
        raise ApiError("sistema-singular", result["error"])
    return _json(
        {
            "total": round(result["total"], 6),
            "residuo": result["residual"],
            "results": [
                {
                    "id": row["equipamento"].id,
                    "hostname": row["equipamento"].hostname,
                    "soma_cvss": round(row["soma_cvss"], 6),
                    "fator": row["fator"],
                    "proprio": round(row["proprio"], 6),
                    "herdado": round(row["herdado"], 6),
                    "efetivo": round(row["efetivo"], 6),
                }
                for row in result["rows"]
            ],
        }
    )


@endpoint("GET")
def audit_events(request):
    """Rota administrativa: exige o papel Administrador no token (S5_09)."""
    user = request.api_user
    if ADMIN_ROLE not in request.api_roles:
        audit(user, "denied", "view_auditevent")
        raise PermissionDenied
    authorize(user, "view_auditevent")
    events = AuditEvent.objects.select_related("actor").order_by("-id")
    return _json(
        paginate(
            request,
            events,
            lambda e: {
                "id": e.pk,
                "quando": e.occurred_at.isoformat(),
                "conta": e.actor.get_username() if e.actor else None,
                "acao": e.descricao,
                "registro": e.alvo,
            },
        )
    )
