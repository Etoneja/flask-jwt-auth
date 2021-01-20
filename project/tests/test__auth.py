# project/tests/test_auth.py
import json
import unittest

from project.server import db
from project.server.models import User
from project.tests.base import BaseTestCase


class TestAuthBlueprint(BaseTestCase):

    def test_registration(self):
        """Test for user registration."""
        with self.client:
            response = self.client.post(
                "/auth/register",
                data=json.dumps(dict(
                    email="test@test.com",
                    password="test"
                )),
                content_type="application/json"
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data["status"] == "success")
            self.assertTrue(data["message"] == "Successfully registered.")
            self.assertTrue(data["auth_token"])
            self.assertTrue(response.content_type == "application/json")
            self.assertEqual(response.status_code, 201)


if __name__ == "__main__":
    unittest.main()
