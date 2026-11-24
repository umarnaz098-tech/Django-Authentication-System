
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    AuthViewSet,
    UserViewSet,
    ProfileViewSet,
    CommunityViewSet,
    PostViewSet,
    CommentViewSet,
    CommunityMemberViewSet,
    ShareViewSet,
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
router.register("community-members", CommunityMemberViewSet, basename="community-members")
router.register("shares", ShareViewSet, basename="shares")

urlpatterns = [
    path("", include(router.urls)),
]
