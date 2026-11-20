import secrets
import hashlib
from django.core.cache import cache
from .tasks import send_email_task
# Generate 6 digit OTP
def generate_otp():
    return str(secrets.randbelow(900000) + 100000)

# Hash OTP for secure Redis storage
def hash_otp(otp):
    return hashlib.sha256(otp.encode()).hexdigest()

# Send OTP to user's email using Celery
def send_otp_email(email):
    email = email.lower()
    otp = generate_otp()
    # Save hashed OTP in Redis for 5 minutes
    cache.set(f"otp_{email}",hash_otp(otp),timeout=300)

    # Reset incorrect attempts
    cache.delete(f"otp_attempts_{email}")
    subject = "Email Verification OTP"
    message = f"""
Hello,

Your email verification OTP is: {otp}
This OTP will expire in 5 minutes.
Do not share this code with anyone.
"""
    # Send email through Celery background task
    send_email_task.delay(subject, message, email)
    return True

# Verify OTP
def verify_otp(email, otp):
    email = email.lower()
    # Get OTP from Redis
    saved_otp = cache.get(f"otp_{email}")
    if saved_otp is None:
        return "expired"
    # Get incorrect attempts
    attempts_key = f"otp_attempts_{email}"
    attempts = cache.get(attempts_key, 0)
    # Maximum 5 incorrect attempts
    if attempts >= 5:
        return "blocked"
    # Compare hashed OTP
    if saved_otp != hash_otp(otp):
        attempts += 1
        cache.set(attempts_key,attempts,timeout=300)
        return "invalid"

    # Delete OTP after successful verification
    cache.delete(f"otp_{email}")
    cache.delete(attempts_key)
    return "verified"

# Check OTP resend limit
def can_resend_otp(email):
    email = email.lower()
    resend_key = f"otp_resend_{email}"
    if cache.get(resend_key):
        return False
    # Allow one resend every 60 seconds
    cache.set(resend_key,True,timeout=60)
    return True

# Send Reset Password OTP using Celery
def send_reset_otp_email(email):
    email = email.lower()
    otp = generate_otp()
    cache.set( f"reset_otp_{email}",hash_otp(otp),timeout=300)
    cache.delete(f"reset_otp_attempts_{email}")
    cache.delete(f"reset_otp_verified_{email}")
    subject = "Reset Password OTP"
    message = f"""
Hello,

Your password reset OTP is: {otp}
This OTP will expire in 5 minutes.
Do not share this code with anyone.
"""
    # Send email through Celery background task
    send_email_task.delay(subject, message, email)
    return True
# Verify Reset Password OTP
def verify_reset_otp(email, otp):
    email = email.lower()
    saved_otp = cache.get(f"reset_otp_{email}")
    if saved_otp is None:
        return "expired"
    attempts_key = f"reset_otp_attempts_{email}"
    attempts = cache.get(attempts_key, 0)
    if attempts >= 5:
        return "blocked"
    if saved_otp != hash_otp(otp):
        attempts += 1
        cache.set(attempts_key,attempts,timeout=300)
        return "invalid"
    cache.delete(f"reset_otp_{email}")
    cache.delete(attempts_key)
    # Save OTP verification status for 10 minutes
    cache.set(f"reset_otp_verified_{email}",True,timeout=600)
    return "verified"

# Check Reset OTP Verification
def reset_password_otp_verified(email):
    return bool(
        cache.get(f"reset_otp_verified_{email.lower()}")
    )
