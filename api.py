#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import json
import logging
import datetime
import inspect
import functools
import hashlib
import uuid

from typing import NamedTuple, OrderedDict
from collections import namedtuple
from contextlib import suppress
from logdecorator import log_on_start, log_on_end, log_on_error

from optparse import OptionParser
from http.server import HTTPServer, BaseHTTPRequestHandler

from scoring import get_score, get_interests
from store import Store
from settings import (
    SALT, ADMIN_LOGIN, ADMIN_SALT, 
    OK, BAD_REQUEST, FORBIDDEN, NOT_FOUND, INVALID_REQUEST, INTERNAL_ERROR, ERRORS, 
    UNKNOWN, MALE, FEMALE, 
    SERVER_HOST, SERVER_PORT, 
    DATE_FIELD_FORMAT,
)
 


class ValidationError(ValueError):
    pass

class ValidatedField(NamedTuple):
    ' Define value type structure for ValidatedFieldDescriptor. '
    value: object = None
    errors: list = []

class on_error:
    ' Class-Decorator for exception handling. '
    def __init__(self, raise_error_msg: str, raise_error_type = ValidationError, reraise_errors = (ValidationError,), suppress_errors: tuple = (),  suppress_returns = None):
        ''' __init__
        if wrapped function [func] throws an exception (exc), then these params will be used as follows and in the order listed:
            [reraise_errors]    - tuple of exception types that will be re raised as is;
            [suppress_errors]   - --//-- will be suppressed and [suppress_returns] returned
            [raise_error_type]  - in other cases, an exception of this specified type will be thrown ...
            [raise_error_type]  -   with this message (template: any names of [func] parameter can be used with some extras: {error}, {error_type})
        '''
        self.raise_error_msg = raise_error_msg 
        self.raise_error_type = raise_error_type
        self.reraise_errors = reraise_errors
        self.suppress_errors = suppress_errors
        self.suppress_returns = suppress_returns 

    def __call__(self, func):
        ' __call__ '
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except BaseException as err:
                if type(err) in self.reraise_errors:
                    raise
                if type(err) in self.suppress_errors:
                    return self.suppress_returns
                callargs = inspect.getcallargs(func, *args, **kwargs)
                raise self.raise_error_type(self.raise_error_msg.format(error = str(err), error_type=type(err).__name__, **callargs)) from err
        return wrapper
        
class ValidatedFieldDescriptor():
    ' Descriptor base class for field validation. '

    _valid_type = str  # hint: _valid_types (int, float, ...)
    _valid_nulls = (None, '', [], {})  # can be specified in descendant classes
    
    def __init__(self, required=False, nullable=False, default = None, **kwargs):
        self.required = required
        self.nullable = nullable
        self.default = default  # if default else self._type()
#        self.__dict__.update(kwargs)
        self._name = None
        
    @log_on_end(logging.DEBUG, "ValidatedFieldDescriptor:__set_name__({owner}, {name}) -> {self._name}")
    def __set_name__(self, owner, name):
        ' **set name** descriptor method '
        self._name = f'_{name}_{uuid.uuid4().hex}' 

    @log_on_end(logging.DEBUG, "ValidatedFieldDescriptor:__get__({instance}, {cls.__name__}) -> {self._name}: {result}")
    def __get__(self, instance, cls):
        ' **get** descriptor method'
        if instance is None:  # to get access to descriptor via class
            return self
        # return default value if instance is not set / intialized
        # without validation excepting required checks
        return getattr(instance, self._name, 
                        ValidatedField(self.default, ['Required.'] if self.required else [])
                    )

    @log_on_end(logging.DEBUG, "ValidatedFieldDescriptor:__set__({self}, {instance}, {value})")  # note: it would be nice here to add support for recurrent resolving {self.{self._name}} or eval (not safe formatting...)  
    def __set__(self, instance, value):
        ' **set** descriptor method '
        errors = []
        try:
            value = self.preprocess(value)  # type casting
            if not self.is_empty(value) and not isinstance(value, self._valid_type):  # types list ...
                errors.append(f'Must be a {self._valid_type.__name__}.')
            if not self.nullable and self.is_empty(value):
                errors.append(f'Not nullable.')
            if not self.is_empty(value):
                self.validate(value)
        except BaseException as err:  # ValidationError
            errors.append(str(err))
        setattr(instance, self._name, ValidatedField(value, errors))
    
    @on_error('[{value}] is not valid type.')
    @log_on_error(logging.ERROR, "ValidatedFieldDescriptor:preprocess({self}, {value}) raise inner exception {e}", on_exceptions=BaseException, reraise=True)
    @log_on_end(logging.DEBUG, "ValidatedFieldDescriptor:preprocess({self}, {value}) return {result}")    
    def preprocess(self, value):
        ' Simple type casting of input [value] to self._valid_type '
        if value is not None and isinstance(value, self._valid_type):
            return value
        # use strict
        raise ValidationError(f'{value} is not instance of {self._valid_type.__name__}') 
#        return self._valid_type(value) if value is not None else None

    def is_empty(self, value) -> bool:
        ' Check value is nullable. '
        return value in self._valid_nulls
    
    @on_error('[{value}] is not valid value.')  # should not change inner exception of ValidationError type - checks
    @log_on_start(logging.DEBUG, "ValidatedFieldDescriptor:validate({self}, {value}) ...")    
    @log_on_error(logging.ERROR, "ValidatedFieldDescriptor:validate({self}, {value}) raise inner exception {e}", on_exceptions=BaseException, reraise=True)
    def validate(self, value) -> None:
        ''' Validate preprocessed (valid type and not emtpy) value. \
            Method is supposed to be overridden in descendants ( with self.preprocess )  
        '''
        if type(value) is str:
            with suppress(AttributeError):
                rem = getattr(self, '_rem')  # why not to use hasattr here -> https://docs.python.org/3/library/functions.html#hasattr'
                if not rem[0].search(value):
                    raise ValidationError(rem[1])                   

class CharField(ValidatedFieldDescriptor):
    ' any string '
    pass

class ArgumentsField(ValidatedFieldDescriptor):
    ' any dict '
    _valid_type = dict

class EmailField(CharField):
    ' string with valid email address '
    _rem = (re.compile(r'^(\w|\.|\_|\-)+[@](\w|\_|\-|\.)+[.]\w{2,3}$'), 'Not valid email address') 

class PhoneField(ValidatedFieldDescriptor):
    ' string or number of length 11, starts with 7, optional, can be empty '
    _rem = (re.compile(r'7\d{10}$'), 'Not valid phone number.')

    def preprocess(self, value):
        return str(value)    

class DateField(ValidatedFieldDescriptor):
    ' date in DD.MM.YYYY format '
    _valid_type = datetime.date

    def __init__(self, date_format = DATE_FIELD_FORMAT, *args, **kwargs):
        super(DateField, self).__init__(*args, **kwargs)
        self._date_format = date_format

    @on_error('Input [{value}] is not valid date format {self._date_format}')
    @log_on_end(logging.DEBUG, "VDateField:preprocess({self}, {value}) return {result}")    
    def preprocess(self, value):
        return datetime.datetime.strptime(value, self._date_format).date()        

class BirthDayField(DateField):
    ' date (valid DateField) from which no more than 70 years have passed, optionally, can be empty '
    MAX_AGE = 70

    @on_error('Not valid with [{error_type}: {error}]')  # just in case of some method's changes  
    def validate(self, value):
        if value > datetime.date.today():
            raise ValidationError(f'Unborn error.')
        if datetime.date.today().year - value.year > self.MAX_AGE:
            raise ValidationError(f'Sorry, our marketers count only up to {self.MAX_AGE}.')

class GenderField(ValidatedFieldDescriptor):
    _valid_type = int

    @on_error('Error [{value}] gender code [{error_type}: {error}]')  # just in case of some method's changes  
    def validate(self, value):
        if value not in (UNKNOWN, MALE, FEMALE):
            raise ValidationError(f"Value must be valid gender code: {(UNKNOWN, MALE, FEMALE)}")

class ListField(ValidatedFieldDescriptor):
    ' list '
    _valid_type = list # list[int]

class ClientIDsField(ListField):
    ' list[int] '
    def preprocess(self, value):
#        return list(map(int,value))  # ["1", "2"] - is wrong in tests suite ...
        if not all(isinstance(i, int) for i in value):
            raise ValidationError(f"{value} must be list of int.")
        return value

class ValidStatus:
    def __init__(self, errors: dict):
        self.ok: bool = len(errors) == 0
        self.errors: dict = errors

class BaseRequest:
    def __new__(cls, *args, **kwargs):
        cls._fields = tuple(k for k, v in cls.__dict__.items() if isinstance(v, ValidatedFieldDescriptor))
        return super().__new__(cls)

    def __init__(self, *args, **kwargs):
        if len(args) > len(self._fields):
            raise TypeError('Expected {} arguments'.format(len(self._fields)))
        for name, value in zip(self._fields, args):
            setattr(self, name, value)
        for name in self._fields[len(args):]:
            if name in kwargs: 
                setattr(self, name, kwargs.pop(name))
        if kwargs:
            raise TypeError('Invalid argument(s): {}'.format(','.join(kwargs)))

    @log_on_end(logging.DEBUG, "BaseRequest:validate({self}) return {result}")   
    def validate(self) -> ValidStatus:
        errors = {}
        for field_name in self._fields:
            validated_field: ValidatedField = getattr(self, field_name)
            if validated_field.errors:
                errors[f'field: {field_name}'] = '; '.join(validated_field.errors)
        return ValidStatus(errors)

    @property
    @log_on_end(logging.DEBUG, "BaseRequest:all({self}) return {result}")       
    def all(self) -> OrderedDict:
        return OrderedDict(((field_name, getattr(self, field_name).value) for field_name in self._fields))

    @property
    @log_on_end(logging.DEBUG, "BaseRequest:has({self}) return {result}")       
    def has(self) -> tuple:
        return tuple(field for field in self._fields if getattr(self, field).value is not None)   

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

    valid_pairs = (
        ('phone', 'email'),
        ('first_name', 'last_name'),
        ('gender', 'birthday'),
    )

    @log_on_end(logging.DEBUG, "OnlineScoreRequest:validate({self}) return {result}")   
    def validate(self):
        valid_status = super().validate()
        if not any(
            getattr(self, pair[0]).value is not None and getattr(self, pair[1]).value is not None
            for pair in self.valid_pairs ):
                valid_status.errors['validation pairs'] = f'Online score request should have at least one non-empty pair as listed: {self.valid_pairs}'
        return ValidStatus(valid_status.errors)
     
class MethodRequest(BaseRequest):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login.value == ADMIN_LOGIN

Response = namedtuple('Response', ['response', 'code'])

def check_auth(handler: callable):
    ' Authentication decorator '
    @functools.wraps(handler)
    def wrapper(request: MethodRequest, *args, **kwargs):
        if request.is_admin:
            digest = hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode()).hexdigest()
        else:
            digest = hashlib.sha512((request.account.value + request.login.value + SALT).encode()).hexdigest()
        if digest == request.token.value:
            return handler(request, *args, **kwargs)
        return Response(ERRORS[FORBIDDEN], FORBIDDEN)
    return wrapper

@log_on_end(logging.DEBUG, "online_score_handler({method_request}, {ctx}) return {result}")   
@check_auth
def online_score_handler(method_request: MethodRequest, ctx: dict, store) -> Response:
    handler_request = OnlineScoreRequest(**method_request.arguments.value)
    if not (status:=handler_request.validate()).ok:
        return Response(json.dumps(status.errors, sort_keys=True, indent=4), INVALID_REQUEST)
    ctx["has"] = handler_request.has
    score = 42 if method_request.is_admin \
            else get_score(store, **handler_request.all)        
    return Response({"score": score}, OK)

@log_on_end(logging.DEBUG, "clients_interests_handler({method_request}, {ctx}) return {result}")   
@check_auth
def clients_interests_handler(method_request: MethodRequest, ctx: dict, store) -> Response:
    handler_request = ClientsInterestsRequest(**method_request.arguments.value)
    if not (status:=handler_request.validate()).ok:
        return Response(json.dumps(status.errors, sort_keys=True, indent=4), INVALID_REQUEST)
    ctx["nclients"] = len(handler_request.client_ids.value)
    result = {cid: get_interests(store, cid) for cid in handler_request.client_ids.value}
    return Response(result, OK)

@log_on_start(logging.DEBUG, "method_handler({request}, {ctx}, ...) begin")   
def method_handler(request, ctx, store) -> Response:
    handlers = {
        'online_score': online_score_handler,
        'clients_interests': clients_interests_handler,
    }
    method_request = MethodRequest(**request['body'])
    if not (status := method_request.validate()).ok:
        return Response(json.dumps(status.errors, sort_keys=True, indent=4), INVALID_REQUEST)
    if method_request.method.value not in handlers:
        return Response(ERRORS[NOT_FOUND], NOT_FOUND)
    return handlers[method_request.method.value](method_request, ctx, store)


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = Store()

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    @log_on_start(logging.DEBUG, "MainHTTPHandler:do_POST begin\n path: {self.path}\n headers: {self.headers}")   
    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length'])).decode()
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = (*self.router[path]({"body": request, "headers": self.headers}, context, self.store),)
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
        self.wfile.write(json.dumps(r).encode())
        return

if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-s", "--host", type=str, dest="host", default=SERVER_HOST)
    op.add_option("-p", "--port", type=int, dest="port", default=SERVER_PORT)
    op.add_option("-l", "--log", type=str, dest="log", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.DEBUG,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer((opts.host, opts.port), MainHTTPHandler)
    logging.info("Starting server on %s at %s" % (opts.host, opts.port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()