import logging
from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import IntegrityError, transaction
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import (AllowAny,IsAuthenticated,BasePermission,SAFE_METHODS)
from rest_framework.response import Response
from rest_framework.parsers import (MultiPartParser,FormParser,JSONParser)
from rest_framework.exceptions import ValidationError
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
    ResetPasswordSerializer,
    UserSerializer,
    ProfileSerializer,
    ProfileViewSerializer,
    CommunitySerializer,
    PostSerializer,
    CommentSerializer,
    FollowSerializer,
    FollowActionSerializer,
    CommunityMemberSerializer,
    ReactionSerializer,
    ReactionCreateSerializer,
    ShareSerializer,
    SavePostSerializer,
    ReportSerializer,
    PostViewSerializer,
)

from .models import (
    Profile,
    ProfileView,
    Community,
    Post,
    Comment,
    Follow,
    CommunityMember,
    Reaction,
    Share,
    SavePost,
    Report,
    PostView,
)

from .utils import (
    send_otp_email,
    verify_otp,
    can_resend_otp,
    send_reset_otp_email,
    verify_reset_otp,
    reset_password_otp_verified,
)

from .tasks import (
    send_welcome_email_task,
    send_password_reset_confirmation_task,
    send_email_task,
)


logger = logging.getLogger(__name__)


# ============================================================
# AUTHENTICATION VIEWSET
# ============================================================

class AuthViewSet(viewsets.ViewSet):

    # REGISTER API
    @extend_schema(request=RegisterSerializer)
    @action(detail=False, methods=["post"], permission_classes=[AllowAny])
    def register(self, request):

        serializer = RegisterSerializer(data=request.data)

        if serializer.is_valid():

            name = serializer.validated_data["name"]
            email = serializer.validated_data["email"].lower()
            password = serializer.validated_data["password"]

            if User.objects.filter(email__iexact=email).exists():
                return Response(
                    {"message": "Email already registered."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            try:
                user = User.objects.create_user(
                    username=email,
                    email=email,
                    password=password,
                    first_name=name,
                    is_active=False,
                )

                send_otp_email(email)

            except IntegrityError:
                return Response(
                    {"message": "Email already registered."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            except Exception:
                logger.exception("Registration OTP queue failed.")

                return Response(
                    {
                        "message": (
                            "Email task could not be queued. "
                            "Please resend OTP."
                        )
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

            return Response(
                {
                    "message": (
                        "Registration successful. OTP email queued. "
                        "Check your email."
                    )
                },
                status=status.HTTP_201_CREATED,
            )

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST,
        )

    # VERIFY EMAIL OTP API
    @extend_schema(request=VerifyOTPSerializer)
    @action(detail=False, methods=["post"], permission_classes=[AllowAny])
    def verify_otp(self, request):

        serializer = VerifyOTPSerializer(data=request.data)

        if serializer.is_valid():

            email = serializer.validated_data["email"].lower()
            otp = serializer.validated_data["otp"]

            try:
                user = User.objects.get(email__iexact=email)

            except User.DoesNotExist:
                return Response(
                    {"message": "User not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            if user.is_active:
                return Response(
                    {"message": "Email already verified."},
                    status=status.HTTP_200_OK,
                )

            result = verify_otp(email, otp)

            if result == "expired":
                return Response(
                    {"message": "OTP expired. Please request a new OTP."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if result == "blocked":
                return Response(
                    {
                        "message": (
                            "Too many incorrect attempts. "
                            "Please request a new OTP."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if result == "invalid":
                return Response(
                    {"message": "Invalid OTP."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user.is_active = True
            user.save(update_fields=["is_active"])

            try:
                send_welcome_email_task.delay(
                    user.first_name,
                    user.email,
                )
            except Exception:
                logger.exception("Welcome email task queue failed.")

            return Response(
                {
                    "message": (
                        "Email verified successfully. "
                        "You can now login."
                    )
                },
                status=status.HTTP_200_OK,
            )

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST,
        )

    # RESEND OTP API
    @extend_schema(request=ResendOTPSerializer)
    @action(detail=False, methods=["post"], permission_classes=[AllowAny])
    def resend_otp(self, request):

        serializer = ResendOTPSerializer(data=request.data)

        if serializer.is_valid():

            email = serializer.validated_data["email"].lower()

            try:
                user = User.objects.get(email__iexact=email)

            except User.DoesNotExist:
                return Response(
                    {"message": "User not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            if user.is_active:
                return Response(
                    {"message": "Email already verified."},
                    status=status.HTTP_200_OK,
                )

            if not can_resend_otp(email):
                return Response(
                    {
                        "message": (
                            "Please wait before requesting another OTP."
                        )
                    },
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )

            try:
                send_otp_email(email)

            except Exception:
                cache.delete(f"otp_resend_{email}")

                logger.exception("Resend OTP task queue failed.")

                return Response(
                    {
                        "message": (
                            "OTP task could not be queued. "
                            "Please try again."
                        )
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

            return Response(
                {
                    "message": (
                        "New OTP email queued successfully. "
                        "Check your email."
                    )
                },
                status=status.HTTP_200_OK,
            )

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST,
        )

    # LOGIN API
    @extend_schema(request=LoginSerializer)
    @action(detail=False, methods=["post"], permission_classes=[AllowAny])
    def login(self, request):

        serializer = LoginSerializer(data=request.data)

        if serializer.is_valid():

            email = serializer.validated_data["email"].lower()
            password = serializer.validated_data["password"]

            try:
                user = User.objects.get(email__iexact=email)

            except User.DoesNotExist:
                return Response(
                    {"message": "Invalid email or password."},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            if not user.check_password(password):
                return Response(
                    {"message": "Invalid email or password."},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            if not user.is_active:
                if not can_resend_otp(email):
                    return Response(
                        {
                            "message": (
                                "Email is not verified. A verification email "
                                "was sent recently. Please check your inbox."
                            )
                        },
                        status=status.HTTP_403_FORBIDDEN,
                    )

                try:
                    send_otp_email(email)
                except Exception:
                    cache.delete(f"otp_resend_{email}")
                    logger.exception("Login verification OTP queue failed.")

                    return Response(
                        {
                            "message": (
                                "Email is not verified. The verification "
                                "email could not be sent. Please try again."
                            )
                        },
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    )

                return Response(
                    {
                        "message": (
                            "Email is not verified. A verification OTP was "
                            "sent. Please verify your email before logging in."
                        )
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )

            refresh = RefreshToken.for_user(user)

            return Response(
                {
                    "message": "Login successful.",
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                },
                status=status.HTTP_200_OK,
            )

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST,
        )

    # LOGOUT API
    @extend_schema(request=LogoutSerializer)
    @action(
        detail=False,
        methods=["post"],
        permission_classes=[IsAuthenticated],
    )
    def logout(self, request):

        serializer = LogoutSerializer(data=request.data)

        if serializer.is_valid():

            refresh_token = serializer.validated_data["refresh"]

            try:
                token = RefreshToken(refresh_token)

                token_user_id = token.get("user_id")

                if str(token_user_id) != str(request.user.pk):
                    return Response(
                        {
                            "message": (
                                "This refresh token does not belong to you."
                            )
                        },
                        status=status.HTTP_403_FORBIDDEN,
                    )

                token.blacklist()

                return Response(
                    {"message": "Logout successful."},
                    status=status.HTTP_200_OK,
                )

            except (TokenError, KeyError, TypeError, ValueError):
                return Response(
                    {"message": "Invalid or expired refresh token."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST,
        )

    # FORGOT PASSWORD API
    @extend_schema(request=ForgotPasswordSerializer)
    @action(detail=False, methods=["post"], permission_classes=[AllowAny])
    def forgot_password(self, request):

        serializer = ForgotPasswordSerializer(data=request.data)

        if serializer.is_valid():

            email = serializer.validated_data["email"].lower()

            try:
                user = User.objects.get(email__iexact=email)

            except User.DoesNotExist:
                return Response(
                    {"message": "User not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            if not user.is_active:
                return Response(
                    {"message": "Please verify your email first."},
                    status=status.HTTP_403_FORBIDDEN,
                )

            try:
                send_reset_otp_email(email)

            except Exception:
                logger.exception("Password reset OTP queue failed.")

                return Response(
                    {"message": "Reset OTP task could not be queued."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

            return Response(
                {
                    "message": (
                        "Password reset OTP email queued successfully. "
                        "Check your email."
                    )
                },
                status=status.HTTP_200_OK,
            )

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST,
        )

    # VERIFY RESET PASSWORD OTP API
    @extend_schema(request=VerifyResetOTPSerializer)
    @action(detail=False, methods=["post"], permission_classes=[AllowAny])
    def verify_reset_otp(self, request):

        serializer = VerifyResetOTPSerializer(data=request.data)

        if serializer.is_valid():

            email = serializer.validated_data["email"].lower()
            otp = serializer.validated_data["otp"]

            try:
                User.objects.get(email__iexact=email)

            except User.DoesNotExist:
                return Response(
                    {"message": "User not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            result = verify_reset_otp(email, otp)

            if result == "expired":
                return Response(
                    {"message": "OTP expired. Please request a new OTP."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if result == "blocked":
                return Response(
                    {
                        "message": (
                            "Too many incorrect attempts. "
                            "Please request a new OTP."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if result == "invalid":
                return Response(
                    {"message": "Invalid OTP."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            return Response(
                {
                    "message": (
                        "OTP verified successfully. "
                        "You can now reset your password."
                    )
                },
                status=status.HTTP_200_OK,
            )

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST,
        )

    # RESET PASSWORD API
    @extend_schema(request=ResetPasswordSerializer)
    @action(detail=False, methods=["post"], permission_classes=[AllowAny])
    def reset_password(self, request):

        serializer = ResetPasswordSerializer(data=request.data)

        if serializer.is_valid():

            email = serializer.validated_data["email"].lower()
            new_password = serializer.validated_data["new_password"]

            try:
                user = User.objects.get(email__iexact=email)

            except User.DoesNotExist:
                return Response(
                    {"message": "User not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            if not reset_password_otp_verified(email):
                return Response(
                    {"message": "Please verify your OTP first."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user.set_password(new_password)
            user.save(update_fields=["password"])

            cache.delete(f"reset_otp_verified_{email}")

            try:
                send_password_reset_confirmation_task.delay(
                    user.first_name,
                    user.email,
                )
            except Exception:
                logger.exception(
                    "Password reset confirmation email queue failed."
                )

            return Response(
                {
                    "message": (
                        "Password reset successfully."
                    )
                },
                status=status.HTTP_200_OK,
            )

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST,
        )


# ============================================================
# SOCIAL MEDIA EMAIL NOTIFICATION HELPER
# ============================================================

def send_social_notification(user, subject, message):

    if not user or not user.email:
        return

    def queue_email():
        try:
            send_email_task.delay(
                subject,
                message,
                user.email,
            )
        except Exception:
            logger.exception(
                "Social notification email task queue failed."
            )

    transaction.on_commit(queue_email)


# ============================================================
# SOCIAL MEDIA PERMISSIONS
# ============================================================

class IsOwnerOrReadOnly(BasePermission):

    def has_object_permission(self, request, view, obj):

        if request.method in SAFE_METHODS:
            return True

        owner = getattr(obj, "user", None)

        if owner is None:
            owner = getattr(obj, "author", None)

        if owner is None:
            owner = getattr(obj, "creator", None)

        if owner is None and isinstance(obj, Profile):
            owner = obj.user

        return owner == request.user


# ============================================================
# USER VIEWSET
# ============================================================

class UserViewSet(viewsets.ReadOnlyModelViewSet):

    queryset = User.objects.filter(is_active=True)
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]


# ============================================================
# PROFILE VIEWSET
# ============================================================

class ProfileViewSet(viewsets.ModelViewSet):

    queryset = Profile.objects.select_related("user").all()
    serializer_class = ProfileSerializer

    permission_classes = [
        IsAuthenticated,
        IsOwnerOrReadOnly,
    ]

    def get_permissions(self):
        if self.action == "follow":
            return [IsAuthenticated()]
        return super().get_permissions()

    parser_classes = [
        MultiPartParser,
        FormParser,
        JSONParser,
    ]

    def perform_create(self, serializer):

        if Profile.objects.filter(user=self.request.user).exists():
            raise ValidationError(
                {"detail": "You already have a profile."}
            )

        serializer.save(user=self.request.user)

    def retrieve(self, request, *args, **kwargs):

        profile = self.get_object()

        if profile.user != request.user:
            self.record_profile_view(profile)

        serializer = self.get_serializer(profile)

        return Response(serializer.data)

    def record_profile_view(self, profile):

        profile_view, created = ProfileView.objects.get_or_create(
            viewer=self.request.user,
            profile=profile,
        )

        if created:
            send_social_notification(
                profile.user,
                "Your profile was viewed",
                (
                    f"Hello {profile.user.first_name or profile.user.username},\n\n"
                    f"{self.request.user.username} viewed your profile."
                ),
            )

        return profile_view

    @extend_schema(responses=ProfileViewSerializer(many=True))
    @action(detail=True, methods=["get"])
    def views(self, request, pk=None):

        profile = self.get_object()

        if profile.user != request.user:
            return Response(
                {"message": "You can only view your own profile views."},
                status=status.HTTP_403_FORBIDDEN,
            )

        queryset = ProfileView.objects.filter(
            profile=profile
        ).select_related("viewer", "profile").order_by("-created_at")
        serializer = ProfileViewSerializer(queryset, many=True)

        return Response(serializer.data)

    @extend_schema(responses=ProfileViewSerializer(many=True))
    @action(detail=True, methods=["get"])
    def views_made(self, request, pk=None):

        profile = self.get_object()

        if profile.user != request.user:
            return Response(
                {"message": "You can only view your own profile history."},
                status=status.HTTP_403_FORBIDDEN,
            )

        queryset = ProfileView.objects.filter(
            viewer=profile.user
        ).select_related("viewer", "profile").order_by("-created_at")
        serializer = ProfileViewSerializer(queryset, many=True)

        return Response(serializer.data)

    @action(detail=True, methods=["get"])
    def followers(self, request, pk=None):

        profile = self.get_object()
        follows = Follow.objects.filter(
            following=profile.user
        ).select_related("follower", "following")
        serializer = FollowSerializer(follows, many=True)

        return Response(serializer.data)

    @action(detail=True, methods=["get"])
    def following(self, request, pk=None):

        profile = self.get_object()
        follows = Follow.objects.filter(
            follower=profile.user
        ).select_related("follower", "following")
        serializer = FollowSerializer(follows, many=True)

        return Response(serializer.data)

    @extend_schema(
        request=None,
        responses={
            200: FollowActionSerializer,
            201: FollowActionSerializer,
        },
    )
    @action(detail=True, methods=["post"])
    def follow(self, request, pk=None):

        profile = self.get_object()
        following = profile.user

        if following == request.user:
            raise ValidationError(
                {"detail": "You cannot follow yourself."}
            )

        if not following.is_active:
            raise ValidationError(
                {"detail": "You cannot follow an inactive user."}
            )

        try:
            with transaction.atomic():
                follow, created = Follow.objects.get_or_create(
                    follower=request.user,
                    following=following,
                )
        except IntegrityError:
            raise ValidationError(
                {"detail": "Unable to create follow."}
            )

        if created:
            send_social_notification(
                following,
                "New follower",
                (
                    f"Hello {following.first_name or following.username},\n\n"
                    f"{request.user.username} started following you."
                ),
            )
            send_social_notification(
                request.user,
                "Follow successful",
                (
                    f"You are now following "
                    f"{following.first_name or following.username}."
                ),
            )

        return Response(
            {"message": "Follow successful."},
            status=(
                status.HTTP_201_CREATED
                if created
                else status.HTTP_200_OK
            ),
        )

    @extend_schema(
        request=SavePostSerializer,
        responses={201: SavePostSerializer},
        methods=["POST"],
    )
    @action(detail=True, methods=["get", "post"])
    def saved_posts(self, request, pk=None):

        profile = self.get_object()

        if profile.user != request.user:
            return Response(
                {"message": "You can only view your own saved posts."},
                status=status.HTTP_403_FORBIDDEN,
            )

        if request.method == "POST":
            serializer = SavePostSerializer(
                data=request.data,
                context=self.get_serializer_context(),
            )

            if not serializer.is_valid():
                return Response(
                    serializer.errors,
                    status=status.HTTP_400_BAD_REQUEST,
                )

            post = serializer.validated_data["post"]

            try:
                with transaction.atomic():
                    saved_post, created = SavePost.objects.get_or_create(
                        user=request.user,
                        post=post,
                    )
            except IntegrityError:
                raise ValidationError(
                    {"detail": "Unable to save this post."}
                )

            if not created:
                raise ValidationError(
                    {"detail": "You have already saved this post."}
                )

            if post.author != request.user:
                send_social_notification(
                    post.author,
                    "Your post was saved",
                    (
                        f"Hello {post.author.first_name or post.author.username},\n\n"
                        f"{request.user.username} saved your post "
                        f"'{post.title}'."
                    ),
                )

            response_serializer = SavePostSerializer(
                saved_post,
                context=self.get_serializer_context(),
            )
            return Response(
                response_serializer.data,
                status=status.HTTP_201_CREATED,
            )

        queryset = SavePost.objects.filter(
            user=request.user
        ).select_related("post")

        serializer = SavePostSerializer(queryset, many=True)

        return Response(serializer.data)

    @action(detail=True, methods=["get"])
    def reactions(self, request, pk=None):

        profile = self.get_object()

        if profile.user != request.user:
            return Response(
                {"message": "You can only view your own reactions."},
                status=status.HTTP_403_FORBIDDEN,
            )

        queryset = Reaction.objects.filter(
            user=request.user
        ).select_related("post")

        serializer = ReactionSerializer(queryset, many=True)

        return Response(serializer.data)

    @action(detail=True, methods=["get"])
    def likes(self, request, pk=None):

        profile = self.get_object()

        queryset = Reaction.objects.filter(
            user=profile.user,
            reaction_type=Reaction.ReactionType.LIKE,
        ).select_related("post")

        serializer = ReactionSerializer(queryset, many=True)

        return Response(serializer.data)

    @action(detail=True, methods=["get"])
    def dislikes(self, request, pk=None):

        profile = self.get_object()

        queryset = Reaction.objects.filter(
            user=profile.user,
            reaction_type=Reaction.ReactionType.DISLIKE,
        ).select_related("post")

        serializer = ReactionSerializer(queryset, many=True)

        return Response(serializer.data)

    @extend_schema(
        request=ReportSerializer,
        responses={201: ReportSerializer},
        methods=["POST"],
    )
    @action(detail=True, methods=["get", "post"])
    def reports(self, request, pk=None):

        profile = self.get_object()

        if profile.user != request.user:
            return Response(
                {"message": "You can only view your own reports."},
                status=status.HTTP_403_FORBIDDEN,
            )

        if request.method == "POST":
            serializer = ReportSerializer(
                data=request.data,
                context=self.get_serializer_context(),
            )

            if not serializer.is_valid():
                return Response(
                    serializer.errors,
                    status=status.HTTP_400_BAD_REQUEST,
                )

            report = serializer.save(user=request.user)
            target = (
                report.profile.user.username
                if report.profile
                else report.post.title
                if report.post
                else report.comment.content[:100]
            )
            staff_users = User.objects.filter(
                is_staff=True,
                is_active=True,
            ).exclude(email="")

            for staff_user in staff_users:
                send_social_notification(
                    staff_user,
                    "New social media report submitted",
                    (
                        f"Hello {staff_user.username},\n\n"
                        f"A new report has been submitted.\n\n"
                        f"Reported item: {target}\n"
                        f"Reason: {report.reason}\n"
                        f"Description: {report.description or 'No description provided.'}\n"
                        f"Reported by: {request.user.username}"
                    ),
                )

            return Response(
                serializer.data,
                status=status.HTTP_201_CREATED,
            )

        queryset = Report.objects.filter(user=request.user)

        serializer = ReportSerializer(queryset, many=True)

        return Response(serializer.data)

    @action(detail=True, methods=["get"])
    def my_posts(self, request, pk=None):

        profile = self.get_object()

        queryset = Post.objects.filter(
            author=profile.user
        ).order_by("-created_at")

        serializer = PostSerializer(
            queryset,
            many=True,
            context={"request": request},
        )

        return Response(serializer.data)


# ============================================================
# COMMUNITY VIEWSET
# ============================================================

class CommunityViewSet(viewsets.ModelViewSet):

    queryset = Community.objects.select_related("creator").all()
    serializer_class = CommunitySerializer

    permission_classes = [
        IsAuthenticated,
        IsOwnerOrReadOnly,
    ]

    def perform_create(self, serializer):
        community = serializer.save(creator=self.request.user)

        send_social_notification(
            community.creator,
            "Community created",
            (
                f"Hello {community.creator.first_name or community.creator.username},\n\n"
                f"Your community '{community.name}' was created successfully."
            ),
        )


# ============================================================
# POST VIEWSET
# ============================================================

class PostViewSet(viewsets.ModelViewSet):

    queryset = Post.objects.select_related(
        "author",
        "community",
    ).all()

    serializer_class = PostSerializer

    permission_classes = [
        IsAuthenticated,
        IsOwnerOrReadOnly,
    ]

    def get_permissions(self):
        if self.action == "reactions":
            return [IsAuthenticated()]
        return super().get_permissions()

    parser_classes = [
        MultiPartParser,
        FormParser,
        JSONParser,
    ]

    def perform_create(self, serializer):
        post = serializer.save(author=self.request.user)

        send_social_notification(
            post.author,
            "Post created",
            (
                f"Hello {post.author.first_name or post.author.username},\n\n"
                f"Your post '{post.title}' was created successfully."
            ),
        )

    def retrieve(self, request, *args, **kwargs):
        post = self.get_object()
        response = Response(self.get_serializer(post).data)

        if post.author != request.user:
            self._record_post_view(post, request.user)

        return response

    def _record_post_view(self, post, user):
        try:
            with transaction.atomic():
                post_view, created = PostView.objects.get_or_create(
                    user=user,
                    post=post,
                )
        except IntegrityError:
            raise ValidationError(
                {"detail": "Unable to record post view."}
            )

        if created and post.author != user:
            send_social_notification(
                post.author,
                "Your post was viewed",
                (
                    f"Hello {post.author.first_name or post.author.username},\n\n"
                    f"{user.username} viewed your post '{post.title}'."
                ),
            )

        return post_view

    @action(detail=True, methods=["get"])
    def views(self, request, pk=None):
        post = self.get_object()

        if post.author != request.user:
            return Response(
                {"detail": "You can only view visitors to your own posts."},
                status=status.HTTP_403_FORBIDDEN,
            )

        queryset = PostView.objects.filter(
            post=post,
        ).select_related("user", "post")
        serializer = PostViewSerializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=["get"])
    def views_made(self, request):
        queryset = PostView.objects.filter(
            user=request.user,
        ).select_related("user", "post")
        serializer = PostViewSerializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=["get"])
    def comments(self, request, pk=None):

        post = self.get_object()

        queryset = Comment.objects.filter(
            post=post
        ).select_related("author")

        serializer = CommentSerializer(
            queryset,
            many=True,
            context={"request": request},
        )

        return Response(serializer.data)

    @extend_schema(
        request=ReactionCreateSerializer,
        responses={201: ReactionSerializer},
        methods=["POST"],
    )
    @action(detail=True, methods=["get", "post"])
    def reactions(self, request, pk=None):

        post = self.get_object()

        if request.method == "POST":
            create_serializer = ReactionCreateSerializer(data=request.data)

            if not create_serializer.is_valid():
                return Response(
                    create_serializer.errors,
                    status=status.HTTP_400_BAD_REQUEST,
                )

            try:
                with transaction.atomic():
                    reaction, created = Reaction.objects.get_or_create(
                        user=request.user,
                        post=post,
                        defaults={
                            "reaction_type": (
                                create_serializer.validated_data["reaction_type"]
                            )
                        },
                    )
            except IntegrityError:
                raise ValidationError(
                    {"detail": "Unable to save reaction."}
                )

            if not created:
                raise ValidationError(
                    {
                        "detail": (
                            "You have already reacted to this post. "
                            "Update your existing reaction instead."
                        )
                    }
                )

            if post.author != request.user:
                send_social_notification(
                    post.author,
                    f"Your post received a {reaction.reaction_type.lower()}",
                    (
                        f"Hello {post.author.first_name or post.author.username},\n\n"
                        f"{request.user.username} reacted to your post "
                        f"'{post.title}' with {reaction.reaction_type}."
                    ),
                )

            response_serializer = ReactionSerializer(
                reaction,
                context=self.get_serializer_context(),
            )
            return Response(
                response_serializer.data,
                status=status.HTTP_201_CREATED,
            )

        queryset = Reaction.objects.filter(
            post=post
        ).select_related("user")

        serializer = ReactionSerializer(queryset, many=True)

        return Response(serializer.data)

    @action(detail=True, methods=["get"])
    def shares_count(self, request, pk=None):

        post = self.get_object()

        return Response({
            "shares_count": post.shares.count()
        })


# ============================================================
# COMMENT VIEWSET
# ============================================================

class CommentViewSet(viewsets.ModelViewSet):

    queryset = Comment.objects.select_related(
        "author",
        "post",
    ).all()

    serializer_class = CommentSerializer

    permission_classes = [
        IsAuthenticated,
        IsOwnerOrReadOnly,
    ]

    def perform_create(self, serializer):

        comment = serializer.save(author=self.request.user)

        post_owner = comment.post.author

        if post_owner != self.request.user:
            send_social_notification(
                post_owner,
                "New comment on your post",
                (
                    f"Hello {post_owner.first_name or post_owner.username},\n\n"
                    f"{self.request.user.username} commented on your post: "
                    f"{comment.post.title}\n\n"
                    f"Comment: {comment.content}"
                ),
            )


# ============================================================
# COMMUNITY MEMBER VIEWSET
# ============================================================

class CommunityMemberViewSet(viewsets.ModelViewSet):

    queryset = CommunityMember.objects.select_related(
        "user",
        "community",
    ).all()

    serializer_class = CommunityMemberSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):

        return CommunityMember.objects.filter(
            user=self.request.user
        ).select_related("community")

    def perform_create(self, serializer):

        community = serializer.validated_data["community"]

        try:
            with transaction.atomic():
                membership, created = CommunityMember.objects.get_or_create(
                    user=self.request.user,
                    community=community,
                )

        except IntegrityError:
            raise ValidationError(
                {"detail": "Unable to join this community."}
            )

        serializer.instance = membership

        creator = community.creator

        if created:
            send_social_notification(
                self.request.user,
                "Community joined",
                f"You joined the community '{community.name}'.",
            )

        if created and creator != self.request.user:
            send_social_notification(
                creator,
                "New community member",
                (
                    f"Hello {creator.first_name or creator.username},\n\n"
                    f"{self.request.user.username} joined your community "
                    f"{community.name}."
                ),
            )


# ============================================================
# SHARE VIEWSET
# ============================================================

class ShareViewSet(viewsets.ModelViewSet):

    queryset = Share.objects.select_related(
        "user",
        "post",
    ).all()

    serializer_class = ShareSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):

        return Share.objects.filter(
            user=self.request.user
        ).select_related("post")

    def perform_create(self, serializer):

        share = serializer.save(user=self.request.user)

        post_owner = share.post.author

        if post_owner != self.request.user:
            send_social_notification(
                post_owner,
                "Your post was shared",
                (
                    f"Hello {post_owner.first_name or post_owner.username},\n\n"
                    f"{self.request.user.username} shared your post "
                    f"'{share.post.title}'."
                ),
            )


