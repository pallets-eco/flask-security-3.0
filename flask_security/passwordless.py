# -*- coding: utf-8 -*-
"""
    flask_security.passwordless
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security passwordless module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from flask import current_app as app
from werkzeug.local import LocalProxy

from .signals import login_instructions_sent
from .utils import send_mail, url_for_security, get_token_status, \
    config_value


# Convenient references
_security = LocalProxy(lambda: app.extensions['security'])

_datastore = LocalProxy(lambda: _security.datastore)


def send_login_instructions(user):
    """Sends the login instructions email for the specified user.

    :param user: The user to send the instructions to
    :param token: The login token
    """
    token = generate_login_token(user)
    login_link = url_for_security('token_login', token=token, _external=True)

    send_mail(config_value('EMAIL_SUBJECT_PASSWORDLESS'), user.email,
              'login_instructions', user=user, login_link=login_link)

    login_instructions_sent.send(app._get_current_object(), user=user, login_token=token)


def generate_login_token(user):
    """Generates a unique login token for the specified user.

    :param user: The user the token belongs to
    """
    return _security.login_serializer.dumps([str(user.id)])


def login_token_status(token):
    """Returns the expired status, invalid status, and user of a login token.
    For example::

        expired, invalid, user = login_token_status('...')

    :param token: The login token
    """
    return get_token_status(token, 'login', 'LOGIN')
