import datetime
import functools
import hashlib
import json
import unittest
from unittest.mock import Mock

import api


def cases(cases):
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args):
            for c in cases:
                new_args = args + (c if isinstance(c, tuple) else (c,))
                f(*new_args)

        return wrapper

    return decorator


class TestSuite(unittest.TestCase):
    def setUp(self):
        self.context = {}
        self.headers = {}
        self.store = Mock()
        self.request_body_template = {
            "account": None,
            "login": None,
            "method": None,
            "token": None,
            "arguments": None,
        }

    def generate_valid_user_token(self, account, login):
        digest = hashlib.sha512(
            (account + login + api.SALT).encode("utf-8")
        ).hexdigest()

        return digest

    def generate_valid_admin_token(self):
        digest = hashlib.sha512(
            (datetime.datetime.now().strftime("%Y%m%d%H") + api.ADMIN_SALT).encode(
                "utf-8"
            )
        ).hexdigest()

        return digest

    def create_method_request(
        self, account, login, token, method="test", arguments=None
    ):
        request_body = self.create_request_body(
            account, login, token, method, arguments
        )
        return api.MethodRequest(request_body)

    def create_request_body(self, account, login, token, method="test", arguments=None):
        request_body = self.request_body_template.copy()
        request_body["account"] = account
        request_body["login"] = login
        request_body["method"] = method
        request_body["token"] = token
        request_body["arguments"] = {} if arguments is None else arguments

        return request_body

    def get_response(self, request):
        return api.method_handler(
            {"body": request, "headers": self.headers}, self.context, self.store
        )

    @cases([("account", "login")])
    def test_valid_user_auth(self, account, login):
        token = self.generate_valid_user_token(account, login)
        request = self.create_method_request(account, login, token)

        self.assertEqual(api.check_auth(request), True)
        self.assertEqual(request.is_admin, False)

    @cases(
        [
            ("account", "login", None),
            ("account", "login", ""),
            ("account", "login", "token"),
            ("account", "login", "94a08da1fecbb6e8b46990538c7b50b2"),
            ("account", "login", "ee977806d7286510da8b9a7492ba58e2484c0ecc"),
        ]
    )
    def test_invalid_user_auth(self, account, login, token):
        request = self.create_method_request(account, login, token)

        self.assertEqual(api.check_auth(request), False)

    @cases([("account", "admin")])
    def test_valid_admin_auth(self, account, login):
        token = self.generate_valid_admin_token()
        request = self.create_method_request(account, login, token)

        self.assertEqual(api.check_auth(request), True)
        self.assertEqual(request.is_admin, True)

    @cases(
        [
            ("account", "admin", None),
            ("account", "admin", ""),
            ("account", "admin", "token"),
            ("account", "admin", "94a08da1fecbb6e8b46990538c7b50b2"),
            ("account", "admin", "ee977806d7286510da8b9a7492ba58e2484c0ecc"),
        ]
    )
    def test_invalid_admin_auth(self, account, login, token):
        request = self.create_method_request(account, login, token)

        self.assertEqual(api.check_auth(request), False)

    @cases(
        [
            ("account", None),
            (None, "login"),
        ]
    )
    def test_auth_with_empty_credentials(self, account, login):
        request = self.create_method_request(account, login, "sometoken")

        with self.assertRaises(TypeError):
            api.check_auth(request)

    def test_empty_request(self):
        _, code = self.get_response({})
        self.assertEqual(api.INVALID_REQUEST, code)

    @cases(
        [
            ("account", "login", ""),
            ("account", "login", "method"),
        ]
    )
    def test_method_bad_request(self, account, login, method):
        token = self.generate_valid_user_token(account, login)
        request = self.create_request_body(account, login, token, method)

        _, code = self.get_response(request)
        self.assertEqual(code, api.BAD_REQUEST)

    @cases(
        [
            ("account", "login", None, "arguments"),
            ("account", "login", None, []),
            ("account", "login", "method", "arguments"),
            ("account", "login", "method", []),
        ]
    )
    def test_method_invalid_request(self, account, login, method, arguments):
        token = self.generate_valid_user_token(account, login)
        request = self.create_request_body(account, login, token, method, arguments)

        _, code = self.get_response(request)
        self.assertEqual(code, api.INVALID_REQUEST)

    @cases(
        [
            (
                {"client_ids": [1, 2], "date": "20.07.2017"},
                {
                    "1": ["books", "hi-tech"],
                    "2": ["pets", "tv"],
                },
            ),
            (
                {"client_ids": [1, 2], "date": None},
                {
                    "1": ["books", "hi-tech"],
                    "2": ["pets", "tv"],
                },
            ),
            (
                {"client_ids": [1, 2]},
                {
                    "1": ["books", "hi-tech"],
                    "2": ["pets", "tv"],
                },
            ),
        ]
    )
    def test_client_interests_valid_request(self, arguments, expected):
        account = "account"
        login = "login"
        method = "clients_interests"

        token = self.generate_valid_user_token(account, login)
        request = self.create_request_body(account, login, token, method, arguments)

        self.store.get.return_value = json.dumps(expected)

        response, code = self.get_response(request)
        self.assertEqual(code, api.OK)
        self.assertTrue(isinstance(response, dict))
        self.assertEqual(response.keys(), expected.keys())

    @cases(
        [
            (
                {"client_ids": [1, 2], "date": "20.07.2017"},
                {
                    "1": ["books", "hi-tech"],
                    "2": ["pets", "tv"],
                },
            ),
            (
                {"client_ids": [1, 2], "date": None},
                {
                    "1": ["books", "hi-tech"],
                    "2": ["pets", "tv"],
                },
            ),
            (
                {"client_ids": [1, 2]},
                {
                    "1": ["books", "hi-tech"],
                    "2": ["pets", "tv"],
                },
            ),
        ]
    )
    def test_client_interests_context(self, arguments, expected):
        account = "account"
        login = "login"
        method = "clients_interests"

        token = self.generate_valid_user_token(account, login)
        request = self.create_request_body(account, login, token, method, arguments)

        self.store.get.return_value = json.dumps(expected)

        self.get_response(request)
        self.assertEqual(self.context.get("nclients"), 2)

    @cases(
        [
            {"date": "20.07.2017"},
            {"client_ids": None, "date": "20.07.2017"},
            {"client_ids": [], "date": "20.07.2017"},
            {"client_ids": ["1", "2"], "date": "20.07.2017"},
            {"client_ids": "1, 2", "date": "20.07.2017"},
        ]
    )
    def test_client_interests_invalid_request(self, arguments):
        account = "account"
        login = "login"
        method = "clients_interests"

        token = self.generate_valid_user_token(account, login)
        request = self.create_request_body(account, login, token, method, arguments)

        _, code = self.get_response(request)
        self.assertEqual(code, api.INVALID_REQUEST)

    @cases(
        [
            (
                {
                    "phone": "79161234567",
                    "email": "ivan@example.com",
                },
                3.0,
            ),
            (
                {
                    "first_name": "Иван",
                    "last_name": "Петров",
                },
                0.5,
            ),
            ({"birthday": "15.03.1995", "gender": 1}, 1.5),
        ]
    )
    def test_online_score_valid_request(self, arguments, expected):
        account = "account"
        login = "login"
        method = "online_score"

        token = self.generate_valid_user_token(account, login)
        request = self.create_request_body(account, login, token, method, arguments)

        self.store.cache_get.return_value = None
        self.store.cache_set.return_value = None

        response, code = self.get_response(request)
        self.assertEqual(code, api.OK)
        self.assertTrue(isinstance(response, dict))
        self.assertEqual(response.get("score"), expected)

    @cases(
        [
            {
                "phone": "79161234567",
                "email": "ivan@example.com",
            },
            {
                "first_name": "Иван",
                "last_name": "Петров",
            },
            {"birthday": "15.03.1995", "gender": 1},
        ]
    )
    def test_online_score_context(self, arguments):
        account = "account"
        login = "login"
        method = "online_score"

        token = self.generate_valid_user_token(account, login)
        request = self.create_request_body(account, login, token, method, arguments)

        self.store.cache_get.return_value = None
        self.store.cache_set.return_value = None

        self.get_response(request)
        for argument in arguments.keys():
            self.assertIn(argument, self.context.get("has"))

    @cases(
        [
            {
                "phone": "79161234567",
                "email": "ivan@example.com",
            },
            {
                "first_name": "Иван",
                "last_name": "Петров",
            },
            {"birthday": "15.03.1995", "gender": 1},
        ]
    )
    def test_online_score_admin_valid_request(self, arguments):
        account = "account"
        login = "admin"
        method = "online_score"

        token = self.generate_valid_admin_token()
        request = self.create_request_body(account, login, token, method, arguments)

        self.store.cache_get.return_value = None
        self.store.cache_set.return_value = None

        response, code = self.get_response(request)
        self.assertEqual(code, api.OK)
        self.assertTrue(isinstance(response, dict))
        self.assertEqual(response.get("score"), 42)

    @cases(
        [
            {
                "phone": "71234567891",
            },
            {
                "phone": "01234567891",
                "email": "ivan@example.com",
            },
            {
                "phone": "123",
                "email": "ivan@example.com",
            },
            {
                "phone": "7123456789123456789",
                "email": "ivan@example.com",
            },
            {
                "phone": "71234567891",
                "email": "ivanexample.com",
            },
            {
                "first_name": [],
                "last_name": "Петров",
            },
            {
                "first_name": {},
                "last_name": "Петров",
            },
            {
                "first_name": "Иван",
                "last_name": [],
            },
            {
                "first_name": "Иван",
                "last_name": {},
            },
            {"birthday": "01.01.1900", "gender": 1},
            {"birthday": "01.01.2100", "gender": 1},
            {"birthday": "31/10/2024", "gender": 1},
            {"birthday": "31.10.2024", "gender": -1},
            {"birthday": "31.10.2024", "gender": 3},
        ]
    )
    def test_online_score_invalid_request(self, arguments):
        account = "account"
        login = "login"
        method = "online_score"

        token = self.generate_valid_user_token(account, login)
        request = self.create_request_body(account, login, token, method, arguments)

        _, code = self.get_response(request)
        self.assertEqual(code, api.INVALID_REQUEST)
