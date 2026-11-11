from django.conf import settings
from django.shortcuts import redirect


class AdminMFA:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if (
            settings.REQUIRE_ADMIN_MFA
            and request.user.is_authenticated
            and (
                request.user.is_staff
                or request.user.is_superuser
                or request.user.groups.filter(name="Administrador").exists()
            )
            and not request.user.is_verified()
            and request.path not in ("/mfa/", "/sair/")
            and not request.path.startswith("/static/")
        ):
            return redirect("/mfa/")
        return self.get_response(request)


class SecurityHeaders:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        )
        response["Referrer-Policy"] = "same-origin"
        response["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )
        if not request.path.startswith("/static/"):
            response["Cache-Control"] = "no-store"
        return response
