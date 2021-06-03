# https://realpython.com/python-redis/

import time
import logging
import functools
import json
import redis  # https://github.com/andymccurdy/redis-py
from logdecorator import log_on_start, log_on_end, log_on_error  # https://github.com/sighalt/logdecorator
from settings import REDIS_CONNECTION, RETRY_MAX_ATTEMPTS, RETRY_DELAY, RETRY_QUIET, STORE_EXPIRES

def retry(max_attempts=RETRY_MAX_ATTEMPTS, delay=RETRY_DELAY, quiet=RETRY_QUIET):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            for _ in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as err:
                    last_exception = err
                    time.sleep(delay)
            if not quiet:
                raise last_exception
        return wrapper
    return decorator

class Store:
    def __init__(self, **connection_settings):
        connection_settings = connection_settings or REDIS_CONNECTION
        self._storage_pool = redis.ConnectionPool(**connection_settings)

    @log_on_start(logging.DEBUG, "Store: -> [{key}] ... ")
    @log_on_error(logging.ERROR, "Store: -> [{key}] is failed with err: {e}", on_exceptions=BaseException, reraise=True)
    @log_on_end(logging.DEBUG, "Store: -> [{key}] => {result}")
    @retry()
    def get(self, key: str):
        with redis.Redis(connection_pool=self._storage_pool) as conn:
            value = conn.get(key)
            return json.loads(value.decode()) if value else None

    @log_on_start(logging.DEBUG, "Store: <- [{key}] <= [{value}] ...")
    @log_on_error(logging.ERROR, "Store: <- [{key}] is failed with err: {e}", on_exceptions=BaseException, reraise=True)
    @log_on_end(logging.DEBUG, "Store: <- [{key}] <= [{value}] - ok")
    @retry()
    def set(self, key: str, value, expires: int = STORE_EXPIRES):
        with redis.Redis(connection_pool=self._storage_pool) as conn:
            conn.set(key, json.dumps(value).encode(), expires)
