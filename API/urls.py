
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    AuthViewSet,
    UserViewSet,
    ProfileViewSet,
    CommunityViewSet,
    PostViewSet,
    CommentViewSet,
    FollowViewSet,
    CommunityMemberViewSet,
    ReactionViewSet,
    ShareViewSet,
    SavePostViewSet,
    ReportViewSet,
    PostViewViewSet,
    ProfileViewViewSet,
)

router = DefaultRouter()

# Authentication
router.register("auth", AuthViewSet, basename="auth")

# Social Media
router.register("users", UserViewSet, basename="users")
router.register("profiles", ProfileViewSet, basename="profiles")
router.register("communities", CommunityViewSet, basename="communities")
router.register("posts", PostViewSet, basename="posts")
router.register("comments", CommentViewSet, basename="comments")
router.register("follows", FollowViewSet, basename="follows")
router.register("community-members", CommunityMemberViewSet, basename="community-members")
router.register("reactions", ReactionViewSet, basename="reactions")
router.register("shares", ShareViewSet, basename="shares")
router.register("saved-posts", SavePostViewSet, basename="saved-posts")
router.register("reports", ReportViewSet, basename="reports")
router.register("post-views", PostViewViewSet, basename="post-views")
router.register("profile-views", ProfileViewViewSet, basename="profile-views")

urlpatterns = [
    path("", include(router.urls)),
]
