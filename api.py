import datetime
import hashlib
import json
import logging
import uuid
from argparse import ArgumentParser
from http.server import BaseHTTPRequestHandler, HTTPServer

import scoring
from store import RedisStore

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}
STORAGE_HOST = "localhost"
STORAGE_PORT = 4000


class Field:
    def __init__(self, required=False, nullable=False):
        self.required = required
        self.nullable = nullable

    def validate(self, value):
        if not self.nullable and value is None:
            raise ValueError("Поле `{name}` не может быть None ")


class CharField(Field):
    def validate(self, value):
        super().validate(value)
        if value is not None:
            if not isinstance(value, str):
                raise TypeError(" Поле `{name}` должно быть строкой ")


class ArgumentsField(Field):
    def validate(self, value):
        super().validate(value)
        if value is not None:
            if not isinstance(value, dict):
                raise TypeError("Поле `{name}` должно быть словарем ")


class EmailField(CharField):
    def validate(self, value):
        super().validate(value)
        if value is not None:
            if "@" not in value:
                raise ValueError("Поле `{name}` должно содержать @ ")


class PhoneField(Field):
    def validate(self, value):
        super().validate(value)
        if value is not None:
            if not isinstance(value, (str, int)):
                raise TypeError("Поле `{name}` должно быть числом или строкой ")
            if len(str(value)) != 11:
                raise ValueError("Поле `{name}` должно быть строкой в 11 символов ")
            if not str(value).startswith("7"):
                raise ValueError(
                    "Поле `{name}` должно быть строкой, которая начинается с символа 7 "
                )


class DateField(Field):
    def validate(self, value):
        super().validate(value)
        if value is not None:
            try:
                datetime.datetime.strptime(str(value), "%d.%m.%Y")
            except ValueError:
                raise ValueError(
                    "Поле `{name}` содержит недопустимый формат даты ('DD.MM.YYYY')"
                )


class BirthDayField(Field):
    def validate(self, value):
        super().validate(value)
        if value is not None:
            date = None

            try:
                date = datetime.datetime.strptime(str(value), "%d.%m.%Y")
            except ValueError:
                raise ValueError(
                    "Поле `{name}` содержит недопустимый формат даты ('DD.MM.YYYY')"
                )

            years_delta = datetime.datetime.now().year - date.year

            if years_delta > 70 or years_delta < -70:
                raise ValueError(
                    "Поле `{name}` содержит недопустимую дату (старше 70 лет)"
                )


class GenderField(Field):
    def validate(self, value):
        super().validate(value)
        if value is not None:
            if not isinstance(value, int):
                raise TypeError("Поле `{name}` должно быть целым числом")
            if value < 0 or value > 2:
                raise ValueError("Поле `{name}` должно быть 0, 1 или 2")


class ClientIDsField(Field):
    def validate(self, value):
        super().validate(value)
        if value is not None:
            if not isinstance(value, list):
                raise TypeError("Поле `{name}` должно быть списком ")
            if not value:
                raise TypeError("Поле `{name}` не может быть пустым ")
            if not all(isinstance(item, int) for item in value):
                raise ValueError("Поле `{name}` должно содержать только целые числа")


class MetaRequest(type):
    def __new__(cls, name, bases, attrs):
        fields = {}
        for key, value in attrs.items():
            if isinstance(value, Field):
                fields[key] = value
        attrs["fields"] = fields
        return super().__new__(cls, name, bases, attrs)


class BaseRequest(metaclass=MetaRequest):
    def __init__(self, request_fields):
        self.errors = []
        self.valid_fields = []
        self.not_empty_fields = []

        for field_name, field in self.fields.items():

            if field_name not in request_fields and field.required:
                self.errors.append(f"Поле `{field_name}` обязательно ")
                continue

            value = request_fields.get(field_name)

            try:
                field.validate(value)
            except TypeError as ex:
                self.errors.append(str(ex).format(name=field_name))
                continue
            except ValueError as ex:
                self.errors.append(str(ex).format(name=field_name))
                continue

            setattr(self, field_name, value)
            self.valid_fields.append(field_name)

            if value is not None:
                self.not_empty_fields.append(field_name)

        if self.errors:
            return None

        if hasattr(self, "pairs_validation"):
            pairs = getattr(self, "pairs_validation")
            for left, right in pairs:
                if left in self.valid_fields and right in self.valid_fields:
                    left_value = getattr(self, left)
                    right_value = getattr(self, right)
                    if left_value is not None and right_value is not None:
                        return None

            self.errors.append(f"Нет валидной пары для {pairs}")


class ClientsInterestsRequest(BaseRequest):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(BaseRequest):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    pairs_validation = [
        ("phone", "email"),
        ("first_name", "last_name"),
        ("gender", "birthday"),
    ]


class MethodRequest(BaseRequest):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(
            (datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode("utf-8")
        ).hexdigest()
    else:
        digest = hashlib.sha512(
            (request.account + request.login + SALT).encode("utf-8")
        ).hexdigest()
    return digest == request.token


def method_handler(request, ctx, store):
    response, code = None, None

    request_body = request["body"]

    method_request = MethodRequest(request_body)

    if method_request.errors:
        response, code = "\n".join(method_request.errors), 422
        return response, code

    if not check_auth(method_request):
        response, code = "Forbidden", 403
        return response, code

    if method_request.method == "clients_interests":
        arguments = method_request.arguments
        clients_interests_request = ClientsInterestsRequest(arguments)

        if clients_interests_request.errors:
            response, code = "\n".join(clients_interests_request.errors), 422
            return response, code

        interests = {}
        for cid in clients_interests_request.client_ids:
            interests[str(cid)] = scoring.get_interests(store=store, cid=cid)

        ctx["nclients"] = len(clients_interests_request.client_ids)

        response, code = interests, 200
        return response, code

    if method_request.method == "online_score":
        arguments = method_request.arguments
        online_score_request = OnlineScoreRequest(arguments)

        if online_score_request.errors:
            response, code = "\n".join(online_score_request.errors), 422
            return response, code

        if method_request.is_admin:
            response, code = {"score": 42}, 200
            return response, code

        score = scoring.get_score(
            store=store,
            phone=online_score_request.phone,
            email=online_score_request.email,
            birthday=online_score_request.birthday,
            gender=online_score_request.gender,
            first_name=online_score_request.first_name,
            last_name=online_score_request.last_name,
        )

        ctx["has"] = online_score_request.not_empty_fields

        response, code = {"score": score}, 200
        return response, code

    response, code = {}, 400

    return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {"method": method_handler}
    store = RedisStore(host=STORAGE_HOST, port=STORAGE_PORT)

    def get_request_id(self, headers):
        return headers.get("HTTP_X_REQUEST_ID", uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers["Content-Length"]))
            request = json.loads(data_string)
        except Exception:
            code = BAD_REQUEST
        if request:
            path = self.path.strip("/")
            logging.info(
                "{}: {} {}".format(self.path, data_string, context["request_id"])
            )
            if path in self.router:
                try:
                    response, code = self.router[path](
                        {"body": request, "headers": self.headers}, context, self.store
                    )
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode("utf-8"))
        return


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-p", "--port", action="store", type=int, default=8080)
    parser.add_argument("-l", "--log", action="store", default=None)
    args = parser.parse_args()
    logging.basicConfig(
        filename=args.log,
        level=logging.INFO,
        format="[%(asctime)s] %(levelname).1s %(message)s",
        datefmt="%Y.%m.%d %H:%M:%S",
    )
    server = HTTPServer(("localhost", args.port), MainHTTPHandler)
    logging.info("Starting server at %s" % args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
