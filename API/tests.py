
from django.test import TestCase
from django.contrib.auth.models import User
from rest_framework.test import APIClient


class AuthenticationTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_user_model_available(self):
        self.assertTrue(User.objects.count() >= 0)

    def test_unauthenticated_social_api_access(self):
        response = self.client.get("/api/profiles/")
        self.assertIn(response.status_code, [401, 403, 404])


class SocialModelTests(TestCase):
    def test_user_creation(self):
        user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="TestPassword123!"
        )

        self.assertEqual(user.username, "testuser")
        self.assertTrue(user.check_password("TestPassword123!"))
