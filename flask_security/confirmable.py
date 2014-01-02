# -*- coding: utf-8 -*-
"""
    flask.ext.security.confirmable
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security confirmable module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from datetime import datetime

from flask import current_app as app
from werkzeug.local import LocalProxy

from .utils import send_mail, md5, url_for_security, get_token_status,\
    config_value
from .signals import user_confirmed, confirm_instructions_sent


# Convenient references
_security = LocalProxy(lambda: app.extensions['security'])

_datastore = LocalProxy(lambda: _security.datastore)


def generate_confirmation_link(user):
    token = generate_confirmation_token(user)
    return url_for_security('confirm_email', token=token, _external=True), token


def send_confirmation_instructions(user):
    """Sends the confirmation instructions email for the specified user.

    :param user: The user to send the instructions to
    :param token: The confirmation token
    """

    confirmation_link, token = generate_confirmation_link(user)

    send_mail(config_value('EMAIL_SUBJECT_CONFIRM'), user.email,
              'confirmation_instructions', user=user,
              confirmation_link=confirmation_link)

    confirm_instructions_sent.send(app._get_current_object(), user=user)
    return token


def generate_confirmation_token(user):
    """Generates a unique confirmation token for the specified user.

    :param user: The user to work with
    """
    data = [str(user.id), md5(user.email)]
    return _security.confirm_serializer.dumps(data)


def requires_confirmation(user):
    """Returns `True` if the user requires confirmation."""
    return _security.confirmable and not _security.login_without_confirmation and user.confirmed_at == None


def confirm_email_token_status(token):
    """Returns the expired status, invalid status, and user of a confirmation
    token. For example::

        expired, invalid, user = confirm_email_token_status('...')

    :param token: The confirmation token
    """
    return get_token_status(token, 'confirm', 'CONFIRM_EMAIL')


def confirm_user(user):
    """Confirms the specified user

    :param user: The user to confirm
    """
    user.confirmed_at = datetime.utcnow()
    _datastore.put(user)
    user_confirmed.send(app._get_current_object(), user=user)
