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
     url_for_security, get_url


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

    send_mail('Login Instructions', user.email,
              'login_instructions', user=user, login_link=login_link)

    login_instructions_sent.send(dict(user=user, login_token=token),
                                 app=app._get_current_object())


def generate_login_token(user, next):
    next = next or get_url(_security.post_login_view)
    data = [user.id, md5(user.password), next]
    return _security.login_serializer.dumps(data)


def login_by_token(token):
    serializer = _security.login_serializer
    max_age = get_max_age('LOGIN')

    try:
        user_id, pw, next = serializer.loads(token, max_age=max_age)
        user = _datastore.find_user(id=user_id)
        login_user(user, True)
        return user, next

    except SignatureExpired:
        sig_okay, data = serializer.loads_unsafe(token)
        user_id, pw, next = data
        user = _datastore.find_user(id=data[0])
        within = _security.login_within
        msg = get_message('LOGIN_EXPIRED', within=within, email=user.email)
        raise PasswordlessLoginError(msg[0], user=user, next=next)

    except BadSignature:
        msg = get_message('INVALID_LOGIN_TOKEN')
        raise PasswordlessLoginError(msg[0])
