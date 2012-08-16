# -*- coding: utf-8 -*-
"""
    flask.ext.security.passwordless
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security passwordless module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from flask import request, current_app as app
from itsdangerous import SignatureExpired, BadSignature
from werkzeug.local import LocalProxy

from .exceptions import PasswordlessLoginError
from .signals import login_instructions_sent
from .utils import send_mail, md5, get_max_age, login_user, get_message, \
     url_for_security


# Convenient references
_security = LocalProxy(lambda: app.extensions['security'])

_datastore = LocalProxy(lambda: _security.datastore)


def send_login_instructions(user, next):
    """Sends the login instructions email for the specified user.

    :param user: The user to send the instructions to
    :param token: The login token
    """
    token = generate_login_token(user, next)

    url = url_for_security('token_login', token=token)

    login_link = request.url_root[:-1] + url

    ctx = dict(user=user, login_link=login_link)

    send_mail('Login Instructions', user.email,
              'login_instructions', ctx)

    login_instructions_sent.send(dict(user=user, login_token=token),
                                 app=app._get_current_object())


def generate_login_token(user, next):
    data = [user.id, md5(user.password), next]
    return _security.login_serializer.dumps(data)


def login_by_token(token):
    serializer = _security.login_serializer
    max_age = get_max_age('LOGIN')

    try:
        data = serializer.loads(token, max_age=max_age)
        user = _datastore.find_user(id=data[0])

        login_user(user, True)

        return user, data[2]

    except SignatureExpired:
        sig_okay, data = serializer.loads_unsafe(token)
        user = _datastore.find_user(id=data[0])
        msg = get_message('LOGIN_EXPIRED',
                          within=_security.login_within,
                          email=user.email)[0]
        raise PasswordlessLoginError(msg, user=user, next=data[2])

    except BadSignature:
        raise PasswordlessLoginError(get_message('INVALID_LOGIN_TOKEN')[0])
