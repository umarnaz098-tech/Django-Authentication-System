
from unittest.mock import patch

from django.test import TestCase
from django.contrib.auth.models import User
from django.urls import Resolver404, resolve
from rest_framework.test import APIClient

from .models import (
    Community,
    Follow,
    Post,
    Profile,
    ProfileView,
    Reaction,
    Report,
    PostView,
)


class AuthenticationTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_user_model_available(self):
        self.assertTrue(User.objects.count() >= 0)

    def test_unauthenticated_social_api_access(self):
        response = self.client.get("/api/profiles/")
        self.assertIn(response.status_code, [401, 403, 404])

    def test_follow_api_is_nested_under_profiles(self):
        with self.assertRaises(Resolver404):
            resolve("/api/follows/")

        self.assertEqual(
            resolve("/api/profiles/1/followers/").url_name,
            "profiles-followers",
        )
        self.assertEqual(
            resolve("/api/profiles/1/following/").url_name,
            "profiles-following",
        )
        self.assertEqual(
            resolve("/api/profiles/1/follow/").url_name,
            "profiles-follow",
        )

    def test_reaction_api_is_nested_under_posts(self):
        with self.assertRaises(Resolver404):
            resolve("/api/reactions/")

        self.assertEqual(
            resolve("/api/posts/1/reactions/").url_name,
            "posts-reactions",
        )
        self.assertEqual(
            resolve("/api/profiles/1/reactions/").url_name,
            "profiles-reactions",
        )

    def test_report_api_is_nested_under_profiles(self):
        with self.assertRaises(Resolver404):
            resolve("/api/reports/")

        self.assertEqual(
            resolve("/api/profiles/1/reports/").url_name,
            "profiles-reports",
        )

    def test_saved_posts_api_is_nested_under_profiles(self):
        with self.assertRaises(Resolver404):
            resolve("/api/saved-posts/")

        self.assertEqual(
            resolve("/api/profiles/1/saved_posts/").url_name,
            "profiles-saved-posts",
        )

    def test_profile_views_api_is_nested_under_profiles(self):
        with self.assertRaises(Resolver404):
            resolve("/api/profile-views/")

        self.assertEqual(
            resolve("/api/profiles/1/views/").url_name,
            "profiles-views",
        )
        self.assertEqual(
            resolve("/api/profiles/1/views_made/").url_name,
            "profiles-views-made",
        )

    def test_post_views_api_is_nested_under_posts(self):
        with self.assertRaises(Resolver404):
            resolve("/api/post-views/")

        self.assertEqual(
            resolve("/api/posts/1/views/").url_name,
            "posts-views",
        )
        self.assertEqual(
            resolve("/api/posts/views_made/").url_name,
            "posts-views-made",
        )


class SocialModelTests(TestCase):
    def test_user_creation(self):
        user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="TestPassword123!"
        )

        self.assertEqual(user.username, "testuser")
        self.assertTrue(user.check_password("TestPassword123!"))


class LoginVerificationTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="unverified@example.com",
            email="unverified@example.com",
            password="TestPassword123!",
            is_active=False,
        )
        self.client = APIClient()

    @patch("API.views.can_resend_otp", return_value=True)
    @patch("API.views.send_otp_email")
    def test_login_sends_otp_for_unverified_account(
        self,
        send_otp_email,
        can_resend_otp,
    ):
        response = self.client.post(
            "/api/auth/login/",
            {
                "email": self.user.email,
                "password": "TestPassword123!",
            },
            format="json",
        )

        self.assertEqual(response.status_code, 403)
        self.assertIn("verification OTP was sent", response.data["message"])
        send_otp_email.assert_called_once_with(self.user.email)
        can_resend_otp.assert_called_once_with(self.user.email)

    @patch("API.views.can_resend_otp", return_value=False)
    @patch("API.views.send_otp_email")
    def test_login_does_not_resend_otp_within_rate_limit(
        self,
        send_otp_email,
        can_resend_otp,
    ):
        response = self.client.post(
            "/api/auth/login/",
            {
                "email": self.user.email,
                "password": "TestPassword123!",
            },
            format="json",
        )

        self.assertEqual(response.status_code, 403)
        self.assertIn("sent recently", response.data["message"])
        send_otp_email.assert_not_called()


class SocialNotificationTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            username="post-owner",
            email="owner@example.com",
            password="TestPassword123!",
        )
        self.other_user = User.objects.create_user(
            username="other-user",
            email="other@example.com",
            password="TestPassword123!",
        )
        self.client = APIClient()

    def test_creating_community_emails_creator(self):
        self.client.force_authenticate(user=self.owner)

        with patch("API.views.send_social_notification") as notify:
            response = self.client.post(
                "/api/communities/",
                {"name": "Test community", "description": "Test"},
                format="json",
            )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(notify.call_args.args[0], self.owner)

    def test_saving_the_same_post_twice_returns_an_error(self):
        profile = Profile.objects.create(user=self.other_user)
        post = Post.objects.create(
            author=self.owner,
            title="Test post",
            content="Test",
        )
        self.client.force_authenticate(user=self.other_user)
        url = f"/api/profiles/{profile.pk}/saved_posts/"
        self.client.post(url, {"post": post.pk}, format="json")

        with patch("API.views.send_social_notification") as notify:
            response = self.client.post(
                url,
                {"post": post.pk},
                format="json",
            )

        self.assertEqual(response.status_code, 400)
        notify.assert_not_called()

    def test_creating_post_emails_author(self):
        self.client.force_authenticate(user=self.owner)

        with patch("API.views.send_social_notification") as notify:
            response = self.client.post(
                "/api/posts/",
                {"title": "Test post", "content": "Test"},
                format="json",
            )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(notify.call_args.args[0], self.owner)

    def test_viewing_post_records_once_and_emails_owner(self):
        post = Post.objects.create(
            author=self.other_user,
            title="Test post",
            content="Test",
        )
        self.client.force_authenticate(user=self.owner)

        with patch("API.views.send_social_notification") as notify:
            response = self.client.get(f"/api/posts/{post.pk}/")
            self.client.get(f"/api/posts/{post.pk}/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            PostView.objects.filter(user=self.owner, post=post).count(),
            1,
        )
        self.assertEqual(notify.call_count, 1)
        self.assertEqual(notify.call_args.args[0], self.other_user)

    def test_post_owner_can_list_visitors_but_other_users_cannot(self):
        post = Post.objects.create(
            author=self.other_user,
            title="Test post",
            content="Test",
        )
        PostView.objects.create(user=self.owner, post=post)

        self.client.force_authenticate(user=self.other_user)
        response = self.client.get(f"/api/posts/{post.pk}/views/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data[0]["user"], self.owner.username)

        self.client.force_authenticate(user=self.owner)
        response = self.client.get(f"/api/posts/{post.pk}/views/")
        self.assertEqual(response.status_code, 403)

    def test_user_can_list_posts_they_viewed(self):
        post = Post.objects.create(
            author=self.other_user,
            title="Test post",
            content="Test",
        )
        PostView.objects.create(user=self.owner, post=post)
        self.client.force_authenticate(user=self.owner)

        response = self.client.get("/api/posts/views_made/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data[0]["post"], post.title)

    def test_reacting_to_post_emails_post_owner(self):
        post = Post.objects.create(
            author=self.other_user,
            title="Test post",
            content="Test",
        )
        self.client.force_authenticate(user=self.owner)

        with patch("API.views.send_social_notification") as notify:
            response = self.client.post(
                f"/api/posts/{post.pk}/reactions/",
                {"reaction_type": "Like"},
                format="json",
            )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["user"], self.owner.username)
        self.assertEqual(notify.call_args.args[0], self.other_user)

    def test_profile_reaction_lists_are_still_available(self):
        profile = Profile.objects.create(user=self.owner)
        post = Post.objects.create(
            author=self.other_user,
            title="Test post",
            content="Test",
        )
        Reaction.objects.create(
            user=self.owner,
            post=post,
            reaction_type=Reaction.ReactionType.LIKE,
        )
        self.client.force_authenticate(user=self.owner)

        response = self.client.get(
            f"/api/profiles/{profile.pk}/reactions/"
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 1)

    def test_profile_view_history_is_available_under_profile(self):
        owner_profile = Profile.objects.create(user=self.owner)
        viewed_profile = Profile.objects.create(user=self.other_user)
        ProfileView.objects.create(
            viewer=self.owner,
            profile=viewed_profile,
        )

        self.client.force_authenticate(user=self.other_user)
        visitors_response = self.client.get(
            f"/api/profiles/{viewed_profile.pk}/views/"
        )
        self.client.force_authenticate(user=self.owner)
        history_response = self.client.get(
            f"/api/profiles/{owner_profile.pk}/views_made/"
        )

        self.assertEqual(visitors_response.status_code, 200)
        self.assertEqual(
            visitors_response.data[0]["viewer"],
            self.owner.username,
        )
        self.assertEqual(history_response.status_code, 200)
        self.assertEqual(
            history_response.data[0]["profile"],
            self.other_user.username,
        )

    def test_viewing_a_profile_records_the_view_and_notifies_owner(self):
        profile = Profile.objects.create(user=self.other_user)
        self.client.force_authenticate(user=self.owner)

        with patch("API.views.send_social_notification") as notify:
            response = self.client.get(
                f"/api/profiles/{profile.pk}/"
            )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            ProfileView.objects.filter(
                viewer=self.owner,
                profile=profile,
            ).exists()
        )
        self.assertEqual(notify.call_args.args[0], self.other_user)

    def test_reporting_through_profile_notifies_staff(self):
        profile = Profile.objects.create(user=self.owner)
        post = Post.objects.create(
            author=self.other_user,
            title="Reported post",
            content="Test",
        )
        staff_user = User.objects.create_user(
            username="staff",
            email="staff@example.com",
            password="TestPassword123!",
            is_staff=True,
        )
        self.client.force_authenticate(user=self.owner)

        with patch("API.views.send_social_notification") as notify:
            response = self.client.post(
                f"/api/profiles/{profile.pk}/reports/",
                {
                    "post": post.pk,
                    "reason": Report.Reason.SPAM,
                    "description": "Test report",
                },
                format="json",
            )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["post"], post.title)
        self.assertEqual(notify.call_args.args[0], staff_user)

    def test_following_through_profile_emails_both_users(self):
        profile = Profile.objects.create(user=self.other_user)
        self.client.force_authenticate(user=self.owner)

        with patch("API.views.send_social_notification") as notify:
            response = self.client.post(
                f"/api/profiles/{profile.pk}/follow/",
                format="json",
            )

        recipients = {
            call.args[0]
            for call in notify.call_args_list
        }
        self.assertEqual(response.status_code, 201)
        self.assertEqual(recipients, {self.owner, self.other_user})

    def test_duplicate_profile_follow_does_not_send_another_email(self):
        profile = Profile.objects.create(user=self.other_user)
        Follow.objects.create(
            follower=self.owner,
            following=self.other_user,
        )
        self.client.force_authenticate(user=self.owner)

        with patch("API.views.send_social_notification") as notify:
            response = self.client.post(
                f"/api/profiles/{profile.pk}/follow/",
                format="json",
            )

        self.assertEqual(response.status_code, 200)
        notify.assert_not_called()

    def test_profile_followers_and_following_lists(self):
        owner_profile = Profile.objects.create(user=self.owner)
        other_profile = Profile.objects.create(user=self.other_user)
        Follow.objects.create(
            follower=self.owner,
            following=self.other_user,
        )
        self.client.force_authenticate(user=self.owner)

        followers_response = self.client.get(
            f"/api/profiles/{other_profile.pk}/followers/"
        )
        following_response = self.client.get(
            f"/api/profiles/{owner_profile.pk}/following/"
        )

        self.assertEqual(followers_response.status_code, 200)
        self.assertEqual(following_response.status_code, 200)
        self.assertEqual(
            followers_response.data[0]["follower"],
            self.owner.username,
        )
        self.assertEqual(
            following_response.data[0]["following"],
            self.other_user.username,
        )

    def test_joining_community_emails_member_and_creator(self):
        community = Community.objects.create(
            name="Test community",
            description="Test",
            creator=self.owner,
        )
        self.client.force_authenticate(user=self.other_user)

        with patch("API.views.send_social_notification") as notify:
            response = self.client.post(
                "/api/community-members/",
                {"community": community.name},
                format="json",
            )

        recipients = {
            call.args[0]
            for call in notify.call_args_list
        }
        self.assertEqual(response.status_code, 201)
        self.assertEqual(recipients, {self.owner, self.other_user})

    def test_saving_post_emails_post_owner(self):
        profile = Profile.objects.create(user=self.other_user)
        post = Post.objects.create(
            author=self.owner,
            title="Test post",
            content="Test",
        )
        self.client.force_authenticate(user=self.other_user)

        with patch("API.views.send_social_notification") as notify:
            response = self.client.post(
                f"/api/profiles/{profile.pk}/saved_posts/",
                {"post": post.pk},
                format="json",
            )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(notify.call_args.args[0], self.owner)
        saved_response = self.client.get(
            f"/api/profiles/{profile.pk}/saved_posts/"
        )
        self.assertEqual(saved_response.status_code, 200)
        self.assertEqual(len(saved_response.data), 1)

    def test_creating_comment_does_not_expose_parent_field(self):
        post = Post.objects.create(
            author=self.owner,
            title="Test post",
            content="Test",
        )
        self.client.force_authenticate(user=self.owner)

        response = self.client.post(
            "/api/comments/",
            {"post": post.pk, "content": "Test comment"},
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        self.assertNotIn("parent", response.data)
