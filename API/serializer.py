
from django.contrib.auth.models import User
from rest_framework import serializers

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


# ============================================================
# AUTHENTICATION SERIALIZERS
# ============================================================

class RegisterSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=100)
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=8)

    def validate_email(self, value):
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("Email already registered.")
        return value.lower()


class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6, min_length=6)


class ResendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()


class VerifyResetOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6, min_length=6)


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    new_password = serializers.CharField(write_only=True, min_length=8)


# ============================================================
# CUSTOM RELATED FIELDS
# ============================================================

class NamedPrimaryKeyRelatedField(serializers.PrimaryKeyRelatedField):

    def __init__(self, *args, display_field, **kwargs):
        self.display_field = display_field
        super().__init__(*args, **kwargs)

    def use_pk_only_optimization(self):
        return False

    def to_representation(self, value):
        return getattr(value, self.display_field)


class NamedRelatedField(serializers.SlugRelatedField):

    def __init__(self, *args, display_field, **kwargs):
        super().__init__(
            *args,
            slug_field=display_field,
            **kwargs
        )


class ProfileUsernameField(serializers.SlugRelatedField):

    def __init__(self, **kwargs):
        super().__init__(
            slug_field="username",
            **kwargs
        )

    
    def to_internal_value(self, data):
        if not isinstance(data, str) or not data.strip():
            self.fail("invalid")

        try:
            return self.get_queryset().get(
                user__username=data.strip()
            )
        except Profile.DoesNotExist:
            self.fail(
                "does_not_exist",
                slug_name="username",
                value=data
            )



# ============================================================
# USER SERIALIZER
# ============================================================

class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "email",
            "first_name",
            "last_name",
        ]
        read_only_fields = fields


# ============================================================
# PROFILE SERIALIZERS
# ============================================================

class ProfileSerializer(serializers.ModelSerializer):

    user = NamedRelatedField(
        display_field="username",
        read_only=True
    )

    total_followers = serializers.SerializerMethodField()
    total_following = serializers.SerializerMethodField()
    total_profile_views = serializers.SerializerMethodField()
    saved_posts = serializers.SerializerMethodField()
    total_posts = serializers.SerializerMethodField()
    my_posts = serializers.SerializerMethodField()

    class Meta:
        model = Profile
        fields = "__all__"
        read_only_fields = [
            "id",
            "created_at",
        ]

    def get_total_followers(self, obj):
        return obj.user.followers.count()

    def get_total_following(self, obj):
        return obj.user.following.count()

    def get_total_profile_views(self, obj):
        return obj.profile_views.count()

    def get_saved_posts(self, obj):
        saved = obj.user.saved_posts.select_related("post").all()
        return SavePostSerializer(saved, many=True).data

    def get_total_posts(self, obj):
        return obj.user.posts.count()

    def get_my_posts(self, obj):
        posts = obj.user.posts.all().order_by("-created_at")
        return PostSerializer(
            posts,
            many=True,
            context=self.context
        ).data


class ProfileViewSerializer(serializers.ModelSerializer):

    viewer = serializers.SlugRelatedField(
        read_only=True,
        slug_field="username"
    )

    profile = ProfileUsernameField(
        queryset=Profile.objects.select_related("user").all()
    )

    class Meta:
        model = ProfileView
        fields = "__all__"
        read_only_fields = [
            "id",
            "viewer",
            "created_at",
        ]


# ============================================================
# COMMUNITY SERIALIZER
# ============================================================

class CommunitySerializer(serializers.ModelSerializer):

    creator = NamedRelatedField(
        display_field="username",
        read_only=True
    )

    class Meta:
        model = Community
        fields = "__all__"
        read_only_fields = [
            "id",
            "creator",
            "created_at",
        ]


# ============================================================
# POST SERIALIZER
# ============================================================

class PostSerializer(serializers.ModelSerializer):

    author = NamedRelatedField(
        display_field="username",
        read_only=True
    )

    community = NamedRelatedField(
        queryset=Community.objects.all(),
        display_field="name",
        allow_null=True,
        required=False
    )

    likes = serializers.SerializerMethodField()
    dislikes = serializers.SerializerMethodField()
    comments = serializers.SerializerMethodField()
    total_shares = serializers.SerializerMethodField()

    class Meta:
        model = Post
        fields = "__all__"
        read_only_fields = [
            "id",
            "author",
            "created_at",
            "updated_at",
        ]

    def get_likes(self, obj):
        return obj.reactions.filter(
            reaction_type=Reaction.ReactionType.LIKE
        ).count()

    def get_dislikes(self, obj):
        return obj.reactions.filter(
            reaction_type=Reaction.ReactionType.DISLIKE
        ).count()

    def get_comments(self, obj):
        return CommentSerializer(
            obj.comments.all(),
            many=True,
            context=self.context
        ).data

    def get_total_shares(self, obj):
        return obj.shares.count()


# ============================================================
# COMMENT SERIALIZER
# ============================================================

class CommentSerializer(serializers.ModelSerializer):

    author = NamedRelatedField(
        display_field="username",
        read_only=True
    )

    post = NamedPrimaryKeyRelatedField(
        queryset=Post.objects.all(),
        display_field="title"
    )

    parent = NamedPrimaryKeyRelatedField(
        queryset=Comment.objects.all(),
        display_field="content",
        allow_null=True,
        required=False
    )

    class Meta:
        model = Comment
        fields = "__all__"
        read_only_fields = [
            "id",
            "author",
            "created_at",
        ]

    
    def validate_parent(self, value):
        if value is not None:
            post = self.initial_data.get("post")

            if post is not None:
                post_id = str(post)
            elif self.instance is not None:
                post_id = str(self.instance.post_id)
            else:
                post_id = None

            if post_id is not None and str(value.post_id) != post_id:
                raise serializers.ValidationError(
                    "Parent comment must belong to the same post."
                )

        return value



# ============================================================
# FOLLOW SERIALIZER
# ============================================================

class FollowSerializer(serializers.ModelSerializer):

    follower = NamedRelatedField(
        display_field="username",
        read_only=True
    )

    following = NamedRelatedField(
        queryset=User.objects.filter(is_active=True),
        display_field="username"
    )

    class Meta:
        model = Follow
        fields = "__all__"
        read_only_fields = [
            "id",
            "follower",
            "created_at",
        ]


# ============================================================
# COMMUNITY MEMBER SERIALIZER
# ============================================================

class CommunityMemberSerializer(serializers.ModelSerializer):

    user = NamedRelatedField(
        display_field="username",
        read_only=True
    )

    community = NamedRelatedField(
        queryset=Community.objects.all(),
        display_field="name"
    )

    class Meta:
        model = CommunityMember
        fields = "__all__"
        read_only_fields = [
            "id",
            "user",
            "joined_at",
        ]


# ============================================================
# REACTION SERIALIZER
# ============================================================

class ReactionSerializer(serializers.ModelSerializer):

    user = NamedRelatedField(
        display_field="username",
        read_only=True
    )

    post = NamedPrimaryKeyRelatedField(
        queryset=Post.objects.all(),
        display_field="title"
    )

    class Meta:
        model = Reaction
        fields = "__all__"
        read_only_fields = [
            "id",
            "user",
            "created_at",
        ]


# ============================================================
# SHARE SERIALIZER
# ============================================================

class ShareSerializer(serializers.ModelSerializer):

    user = NamedRelatedField(
        display_field="username",
        read_only=True
    )

    post = NamedPrimaryKeyRelatedField(
        queryset=Post.objects.all(),
        display_field="title"
    )

    class Meta:
        model = Share
        fields = "__all__"
        read_only_fields = [
            "id",
            "user",
            "created_at",
        ]


# ============================================================
# SAVE POST SERIALIZER
# ============================================================

class SavePostSerializer(serializers.ModelSerializer):

    user = NamedRelatedField(
        display_field="username",
        read_only=True
    )

    post = NamedPrimaryKeyRelatedField(
        queryset=Post.objects.all(),
        display_field="title"
    )

    class Meta:
        model = SavePost
        fields = "__all__"
        read_only_fields = [
            "id",
            "user",
            "created_at",
        ]


# ============================================================
# REPORT SERIALIZER
# ============================================================

class ReportSerializer(serializers.ModelSerializer):

    user = serializers.SlugRelatedField(
        read_only=True,
        slug_field="username"
    )

    profile = ProfileUsernameField(
        queryset=Profile.objects.select_related("user").all(),
        allow_null=True,
        required=False
    )

    post = NamedPrimaryKeyRelatedField(
        queryset=Post.objects.all(),
        display_field="title",
        allow_null=True,
        required=False
    )

    comment = NamedPrimaryKeyRelatedField(
        queryset=Comment.objects.all(),
        display_field="content",
        allow_null=True,
        required=False
    )

    class Meta:
        model = Report
        fields = "__all__"
        read_only_fields = [
            "id",
            "user",
            "status",
            "created_at",
        ]

    
    def validate(self, attrs):
        if self.instance is not None:
            profile = attrs.get("profile", self.instance.profile)
            post = attrs.get("post", self.instance.post)
            comment = attrs.get("comment", self.instance.comment)
        else:
            profile = attrs.get("profile")
            post = attrs.get("post")
            comment = attrs.get("comment")

        targets = [profile, post, comment]

        if sum(target is not None for target in targets) != 1:
            raise serializers.ValidationError(
                "A report must target exactly one profile, post, or comment."
            )

        return attrs



# ============================================================
# POST VIEW SERIALIZER
# ============================================================

class PostViewSerializer(serializers.ModelSerializer):

    user = NamedRelatedField(
        display_field="username",
        read_only=True
    )

    post = NamedPrimaryKeyRelatedField(
        queryset=Post.objects.all(),
        display_field="title"
    )

    class Meta:
        model = PostView
        fields = "__all__"
        read_only_fields = [
            "id",
            "user",
            "created_at",
        ]
