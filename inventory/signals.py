from django.contrib.auth.signals import (
    user_logged_in,
    user_logged_out,
    user_login_failed,
)
from django.dispatch import receiver
from .models import AuditEvent


@receiver(user_logged_in)
def logged_in(sender, request, user, **kwargs):
    AuditEvent.objects.create(actor=user, action="login", target="session")


@receiver(user_logged_out)
def logged_out(sender, request, user, **kwargs):
    if user and user.pk:
        AuditEvent.objects.create(
            actor=user, action="logout", target="session"
        )


@receiver(user_login_failed)
def login_failed(sender, credentials, request, **kwargs):
    AuditEvent.objects.create(action="login_failed", target="session")
