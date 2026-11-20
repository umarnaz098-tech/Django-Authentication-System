from django.contrib.auth.models import User
from django.core.cache import cache
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from drf_spectacular.utils import extend_schema
from .serializer import (
    RegisterSerializer,
    VerifyOTPSerializer,
    ResendOTPSerializer,
    LoginSerializer,
    LogoutSerializer,
    ForgotPasswordSerializer,
    VerifyResetOTPSerializer,
    ResetPasswordSerializer
)

from .utils import (
    send_otp_email,
    verify_otp,
    can_resend_otp,
    send_reset_otp_email,
    verify_reset_otp,
    reset_password_otp_verified
)

from .tasks import (
    send_welcome_email_task,
    send_password_reset_confirmation_task
)


class AuthViewSet(viewsets.ViewSet):

    # REGISTER API
    @extend_schema(request=RegisterSerializer)
    @action(
        detail=False,
        methods=['post'],
        permission_classes=[AllowAny]
    )
    def register(self, request):

        serializer = RegisterSerializer(data=request.data)

        if serializer.is_valid():

            name = serializer.validated_data['name']
            email = serializer.validated_data['email'].lower()
            password = serializer.validated_data['password']

            if User.objects.filter(email__iexact=email).exists():
                return Response(
                    {
                        "message": "Email already registered."
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            user = User.objects.create_user(
                username=email,
                email=email,
                password=password,
                first_name=name,
                is_active=False
            )

            try:
                send_otp_email(email)

            except Exception:
                return Response(
                    {
                        "message": "Email task could not be queued. Please resend OTP."
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            return Response(
                {
                    "message": "Registration successful. OTP email queued. Check your email."
                },
                status=status.HTTP_201_CREATED
            )

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )

    # VERIFY EMAIL OTP API
    @extend_schema(request=VerifyOTPSerializer)
    @action(
        detail=False,
        methods=['post'],
        permission_classes=[AllowAny]
    )
    def verify_otp(self, request):

        serializer = VerifyOTPSerializer(data=request.data)

        if serializer.is_valid():

            email = serializer.validated_data['email'].lower()
            otp = serializer.validated_data['otp']

            try:
                user = User.objects.get(email__iexact=email)

            except User.DoesNotExist:
                return Response(
                    {
                        "message": "User not found."
                    },
                    status=status.HTTP_404_NOT_FOUND
                )

            if user.is_active:
                return Response(
                    {
                        "message": "Email already verified."
                    },
                    status=status.HTTP_200_OK
                )

            result = verify_otp(email, otp)

            if result == "expired":
                return Response(
                    {
                        "message": "OTP expired. Please request a new OTP."
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            if result == "blocked":
                return Response(
                    {
                        "message": "Too many incorrect attempts. Please request a new OTP."
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            if result == "invalid":
                return Response(
                    {
                        "message": "Invalid OTP."
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Activate user account
            user.is_active = True
            user.save()

            # Send welcome email through Celery
            send_welcome_email_task.delay(
                user.first_name,
                user.email
            )

            return Response(
                {
                    "message": "Email verified successfully. Welcome email queued. You can now login."
                },
                status=status.HTTP_200_OK
            )

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )

    # RESEND OTP API
    @extend_schema(request=ResendOTPSerializer)
    @action(
        detail=False,
        methods=['post'],
        permission_classes=[AllowAny]
    )
    def resend_otp(self, request):

        serializer = ResendOTPSerializer(data=request.data)

        if serializer.is_valid():

            email = serializer.validated_data['email'].lower()

            try:
                user = User.objects.get(email__iexact=email)

            except User.DoesNotExist:
                return Response(
                    {
                        "message": "User not found."
                    },
                    status=status.HTTP_404_NOT_FOUND
                )

            if user.is_active:
                return Response(
                    {
                        "message": "Email already verified."
                    },
                    status=status.HTTP_200_OK
                )

            if not can_resend_otp(email):
                return Response(
                    {
                        "message": "Please wait before requesting another OTP."
                    },
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                )

            try:
                send_otp_email(email)

            except Exception:
                cache.delete(f"otp_resend_{email}")

                return Response(
                    {
                        "message": "OTP task could not be queued. Please try again."
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            return Response(
                {
                    "message": "New OTP email queued successfully. Check your email."
                },
                status=status.HTTP_200_OK
            )

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )

    # LOGIN API
    @extend_schema(request=LoginSerializer)
    @action(
        detail=False,
        methods=['post'],
        permission_classes=[AllowAny]
    )
    def login(self, request):

        serializer = LoginSerializer(data=request.data)

        if serializer.is_valid():

            email = serializer.validated_data['email'].lower()
            password = serializer.validated_data['password']

            try:
                user = User.objects.get(email__iexact=email)

            except User.DoesNotExist:
                return Response(
                    {
                        "message": "Invalid email or password."
                    },
                    status=status.HTTP_401_UNAUTHORIZED
                )

            if not user.check_password(password):
                return Response(
                    {
                        "message": "Invalid email or password."
                    },
                    status=status.HTTP_401_UNAUTHORIZED
                )

            if not user.is_active:
                return Response(
                    {
                        "message": "Please verify your email first."
                    },
                    status=status.HTTP_403_FORBIDDEN
                )

            refresh = RefreshToken.for_user(user)

            return Response(
                {
                    "message": "Login successful.",
                    "refresh": str(refresh),
                    "access": str(refresh.access_token)
                },
                status=status.HTTP_200_OK
            )

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )

    # LOGOUT API
    @extend_schema(request=LogoutSerializer)
    @action(
        detail=False,
        methods=['post'],
        permission_classes=[IsAuthenticated]
    )
    def logout(self, request):

        serializer = LogoutSerializer(data=request.data)

        if serializer.is_valid():

            refresh_token = serializer.validated_data['refresh']

            try:
                token = RefreshToken(refresh_token)
                token.blacklist()

                return Response(
                    {
                        "message": "Logout successful."
                    },
                    status=status.HTTP_200_OK
                )

            except TokenError:
                return Response(
                    {
                        "message": "Invalid or expired refresh token."
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )

    # FORGOT PASSWORD API
    @extend_schema(request=ForgotPasswordSerializer)
    @action(
        detail=False,
        methods=['post'],
        permission_classes=[AllowAny]
    )
    def forgot_password(self, request):

        serializer = ForgotPasswordSerializer(data=request.data)

        if serializer.is_valid():

            email = serializer.validated_data['email'].lower()

            try:
                user = User.objects.get(email__iexact=email)

            except User.DoesNotExist:
                return Response(
                    {
                        "message": "User not found."
                    },
                    status=status.HTTP_404_NOT_FOUND
                )

            if not user.is_active:
                return Response(
                    {
                        "message": "Please verify your email first."
                    },
                    status=status.HTTP_403_FORBIDDEN
                )

            try:
                send_reset_otp_email(email)

            except Exception:
                return Response(
                    {
                        "message": "Reset OTP task could not be queued."
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            return Response(
                {
                    "message": "Password reset OTP email queued successfully. Check your email."
                },
                status=status.HTTP_200_OK
            )

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )

    # VERIFY RESET PASSWORD OTP API
    @extend_schema(request=VerifyResetOTPSerializer)
    @action(
        detail=False,
        methods=['post'],
        permission_classes=[AllowAny]
    )
    def verify_reset_otp(self, request):

        serializer = VerifyResetOTPSerializer(data=request.data)

        if serializer.is_valid():

            email = serializer.validated_data['email'].lower()
            otp = serializer.validated_data['otp']

            try:
                user = User.objects.get(email__iexact=email)

            except User.DoesNotExist:
                return Response(
                    {
                        "message": "User not found."
                    },
                    status=status.HTTP_404_NOT_FOUND
                )

            result = verify_reset_otp(email, otp)

            if result == "expired":
                return Response(
                    {
                        "message": "OTP expired. Please request a new OTP."
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            if result == "blocked":
                return Response(
                    {
                        "message": "Too many incorrect attempts. Please request a new OTP."
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            if result == "invalid":
                return Response(
                    {
                        "message": "Invalid OTP."
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            return Response(
                {
                    "message": "OTP verified successfully. You can now reset your password."
                },
                status=status.HTTP_200_OK
            )

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )

    # RESET PASSWORD API
    @extend_schema(request=ResetPasswordSerializer)
    @action(
        detail=False,
        methods=['post'],
        permission_classes=[AllowAny]
    )
    def reset_password(self, request):

        serializer = ResetPasswordSerializer(data=request.data)

        if serializer.is_valid():

            email = serializer.validated_data['email'].lower()
            new_password = serializer.validated_data['new_password']

            try:
                user = User.objects.get(email__iexact=email)

            except User.DoesNotExist:
                return Response(
                    {
                        "message": "User not found."
                    },
                    status=status.HTTP_404_NOT_FOUND
                )

            if not reset_password_otp_verified(email):
                return Response(
                    {
                        "message": "Please verify your OTP first."
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Update password
            user.set_password(new_password)
            user.save()

            # Delete OTP verification status
            cache.delete(f"reset_otp_verified_{email}")

            # Send confirmation email through Celery
            send_password_reset_confirmation_task.delay(
                user.first_name,
                user.email
            )

            return Response(
                {
                    "message": "Password reset successfully. Confirmation email queued."
                },
                status=status.HTTP_200_OK
            )

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )
