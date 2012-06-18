# -*- coding: utf-8 -*-
"""
    flask.ext.security.tokens
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security tokens module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from datetime import datetime

from flask import current_app as app
from werkzeug.local import LocalProxy

from .exceptions import BadCredentialsError, UserNotFoundError
from .utils import generate_token


# Convenient references
_datastore = LocalProxy(lambda: app.security.datastore)


def find_user_by_authentication_token(token):
    if not token:
        raise BadCredentialsError('Authentication token required')
    return _datastore.find_user(authentication_token=token)


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
        user['authentication_token_created_at'] = now
    except TypeError:
        user.authentication_token = token
        user.authentication_token_created_at = now

    return user


def reset_authentication_token(user):
    user = generate_authentication_token(user)
    _datastore._save_model(user)
    return user.authentication_token


def ensure_authentication_token(user):
    if not user.authentication_token:
        reset_authentication_token(user)
    return user.authentication_token
