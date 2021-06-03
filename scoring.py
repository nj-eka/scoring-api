import random
import functools
import inspect

def cache(store_arg_name: str = None, key_names: tuple[str] = None):
    def decorator(func):
        nonlocal store_arg_name
        argspec = inspect.getfullargspec(func)
        store_arg_name = store_arg_name or argspec.args[0]  # if [store_arg_name] is not specified explicitly then it should be the first of args
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            callargs = inspect.getcallargs(func, *args, **kwargs)
            store = callargs.pop(store_arg_name)  # exc: KeyValue
            key_parts = dict((carg_name, carg_value) for carg_name, carg_value in callargs.items() \
                         if carg_name in key_names) if key_names else callargs
            key = hash(tuple(sorted(key_parts.items(), key=lambda item: item[0])))
            key = f'{__file__}:{func.__qualname__}|{str(key)}'
            if not (value := store.get(key)):
                value = func(*args, **kwargs)
                if isinstance(store, dict):
                    store[key] = value
                else:
                    store.set(key, value)
            return value
        return wrapper
    return decorator

@cache() # == @cache(store_arg_name='store') == @cache('store', ('phone', 'email', 'birthday', 'gender', 'first_name', 'last_name'))
def get_score(store, phone, email, birthday=None, gender=None, first_name=None, last_name=None):
    score = 0
    if phone:
        score += 1.5
    if email:
        score += 1.5
    if birthday and gender:
        score += 1.5
    if first_name and last_name:
        score += 0.5
    return score

@cache() 
def get_interests(store, cid):
    interests = ["cars", "pets", "travel", "hi-tech", "sport", "music", "books", "tv", "cinema", "geek", "otus"]
    return random.sample(interests, 2)
