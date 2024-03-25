import unittest
from JWKSserverPA1 import app


class FlaskTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    # test for 200 from GET request to '/.well-known/jwks.json'
    def test_GET_status_code(self):
        # sends HTTP GET request
        result = self.app.get("/.well-known/jwks.json")

        # assert
        self.assertEqual(result.status_code, 200)

    # test for 200 from POST request to '/auth'
    def test_POST_status_code(self):
        # send HTTP POST request
        result = self.app.post("/auth")

        # assert
        self.assertEqual(result.status_code, 200)


if __name__ == "__main__":
    unittest.main()
