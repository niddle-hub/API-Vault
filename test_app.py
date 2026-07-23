import sqlite3
import tempfile
import unittest
from pathlib import Path

from app import create_app


class ApiHolderTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.database_path = root / "test.db"
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret",
                "DATABASE": str(self.database_path),
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def csrf_token(self):
        with self.client.session_transaction() as session:
            return session["csrf_token"]

    def setup_vault(self, password="correct horse battery staple"):
        self.client.get("/login")
        token = self.csrf_token()
        return self.client.post(
            "/login",
            data={
                "csrf_token": token,
                "password": password,
                "password_confirm": password,
            },
        )

    def api_headers(self):
        return {"X-CSRF-Token": self.csrf_token()}

    def test_first_login_creates_vault_and_rejects_wrong_password(self):
        response = self.setup_vault()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/keys")

        response = self.client.post(
            "/logout",
            data={"csrf_token": self.csrf_token()},
        )
        self.assertEqual(response.status_code, 302)

        self.client.get("/login")
        response = self.client.post(
            "/login",
            data={
                "csrf_token": self.csrf_token(),
                "password": "incorrect password",
            },
        )
        self.assertEqual(response.status_code, 401)
        self.assertIn("Неверный мастер-пароль".encode(), response.data)

    def test_crud_flow_encrypts_secret_at_rest(self):
        self.setup_vault()
        plaintext = "sk-test-1234567890-secret"

        response = self.client.post(
            "/api/keys",
            headers=self.api_headers(),
            json={"name": "Test service", "value": plaintext},
        )
        self.assertEqual(response.status_code, 201)
        key_id = response.get_json()["id"]

        connection = sqlite3.connect(self.database_path)
        encrypted = connection.execute(
            "SELECT encrypted_value FROM keys WHERE id = ?",
            (key_id,),
        ).fetchone()[0]
        connection.close()
        self.assertNotIn(plaintext.encode(), encrypted)

        response = self.client.get("/api/keys")
        self.assertEqual(
            response.get_json(),
            [
                {
                    "id": key_id,
                    "name": "Test service",
                    "masked_value": "sk-t****cret",
                    "created_at": response.get_json()[0]["created_at"],
                }
            ],
        )

        response = self.client.get(f"/api/keys/{key_id}/value")
        self.assertEqual(response.get_json()["value"], plaintext)

        response = self.client.put(
            f"/api/keys/{key_id}",
            headers=self.api_headers(),
            json={"name": "Renamed service"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            self.client.get(f"/api/keys/{key_id}/value").get_json()["value"],
            plaintext,
        )

        response = self.client.delete(
            f"/api/keys/{key_id}",
            headers=self.api_headers(),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.get("/api/keys").get_json(), [])

    def test_api_requires_authentication_and_csrf(self):
        response = self.client.get("/api/keys")
        self.assertEqual(response.status_code, 401)

        self.setup_vault()
        response = self.client.post(
            "/api/keys",
            json={"name": "Service", "value": "secret"},
        )
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
