
from datetime import datetime

from flask import current_app
from flask.ext.security.exceptions import BadCredentialsError, \
     UserNotFoundError, AuthenticationError
from flask.ext.security.utils import generate_token
from werkzeug.local import LocalProxy

security = LocalProxy(lambda: current_app.security)


def find_user_by_authentication_token(token):
    if not token:
        raise BadCredentialsError('Authentication token required')
    return security.datastore.find_user(authentication_token=token)


def generate_authentication_token(user):
    while True:
        token = generate_token()
        try:
            find_user_by_authentication_token(token)
        except UserNotFoundError:
            break

    now = datetime.utcnow()

    try:
        user['authentication_token'] = token
        user['authentication_token_generated_at'] = now
    except TypeError:
        user.authentication_token = token
        user.authentication_token_generated_at = now

    return user


def authenticate_by_token(token):
    try:
        return find_user_by_authentication_token(token)
    except UserNotFoundError:
        raise BadCredentialsError('Invalid authentication token')
    except Exception, e:
        raise AuthenticationError(str(e))


def reset_authentication_token(user):
    user = generate_authentication_token(user)
    security.datastore._save_model(user)
