from celery import shared_task
from django.core.mail import send_mail
from django.conf import settings

@shared_task(
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_kwargs={'max_retries': 3}
)
def send_email_task(subject, message, recipient):
    return send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [recipient],
        fail_silently=False
    )

@shared_task(
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_kwargs={'max_retries': 3}
)
def send_welcome_email_task(name, email):
    subject = "Welcome to Authentication System"
    message = f"""
Hello {name},

Congratulations!
Your email has been successfully verified.
Your account has been created successfully.
You can now login to your account.

Thank you!
Authentication System Team
"""
    return send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [email],
        fail_silently=False
    )

@shared_task(
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_kwargs={'max_retries': 3}
)
def send_password_reset_confirmation_task(name, email):
    subject = "Password Reset Successful"
    message = f"""
Hello {name},

Your password has been reset successfully.
You can now login to your account using your new password.
If you did not make this change, please contact us immediately.

Thank you!
Authentication System Team
"""

    return send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [email],
        fail_silently=False
    )
