# -*- coding: utf-8 -*-
"""
    flask.ext.security.tokens
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security tokens module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from flask import current_app as app
from werkzeug.local import LocalProxy

from .utils import md5


# Convenient references
_security = LocalProxy(lambda: app.extensions['security'])

_datastore = LocalProxy(lambda: _security.datastore)


def generate_authentication_token(user):
    """Generates a unique authentication token for the specified user.

    :param user: The user to work with
    """
    data = [str(user.id), md5(user.email)]
    return _security.token_auth_serializer.dumps(data)


def reset_authentication_token(user):
    """Resets a user's authentication token and returns the new token value.

    :param user: The user to work with
    """
    token = generate_authentication_token(user)
    user.authentication_token = token
    _datastore._save_model(user)
    return token


def ensure_authentication_token(user):
    """Ensures that a user has an authentication token. If the user has an
    authentication token already, nothing is performed.

    :param user: The user to work with
    """
    if not user.authentication_token:
        return reset_authentication_token(user)
