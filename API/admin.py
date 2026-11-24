from django.contrib import admin

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


admin.site.register(Profile)
admin.site.register(ProfileView)
admin.site.register(Community)
admin.site.register(Post)
admin.site.register(Comment)
admin.site.register(Follow)
admin.site.register(CommunityMember)
admin.site.register(Reaction)
admin.site.register(Share)
admin.site.register(SavePost)
admin.site.register(Report)
admin.site.register(PostView)