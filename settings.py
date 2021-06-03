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

SERVER_HOST = "localhost"
SERVER_PORT = 8004

REDIS_CONNECTION = {
    "host": "localhost",
    "port": 6379,
    "db": 0,
    "socket_timeout": 60,
#    "decode_responses": True,
}

STORE_EXPIRES = 300

RETRY_MAX_ATTEMPTS = 3
RETRY_DELAY = 1.
RETRY_QUIET = True

DATE_FIELD_FORMAT = '%d.%m.%Y'


