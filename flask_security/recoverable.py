# -*- coding: utf-8 -*-
"""
    flask_security.recoverable
    ~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security recoverable module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from flask import current_app as app
from werkzeug.local import LocalProxy

from .signals import password_reset, reset_password_instructions_sent
from .utils import config_value, get_token_status, hash_data, hash_password, \
    url_for_security, verify_hash

# Convenient references
_security = LocalProxy(lambda: app.extensions['security'])

_datastore = LocalProxy(lambda: _security.datastore)


def send_reset_password_instructions(user):
    """Sends the reset password instructions email for the specified user.

    :param user: The user to send the instructions to
    """
    token = generate_reset_password_token(user)
    reset_link = url_for_security(
        'reset_password', token=token, _external=True
    )

    if config_value('SEND_PASSWORD_RESET_EMAIL'):
        _security.send_mail(config_value('EMAIL_SUBJECT_PASSWORD_RESET'),
                            user.email, 'reset_instructions',
                            user=user, reset_link=reset_link)

    reset_password_instructions_sent.send(
        app._get_current_object(), user=user, token=token
    )


def send_password_reset_notice(user):
    """Sends the password reset notice email for the specified user.

    :param user: The user to send the notice to
    """
    if config_value('SEND_PASSWORD_RESET_NOTICE_EMAIL'):
        _security.send_mail(config_value('EMAIL_SUBJECT_PASSWORD_NOTICE'),
                            user.email, 'reset_notice', user=user)


def generate_reset_password_token(user):
    """Generates a unique reset password token for the specified user.

    :param user: The user to work with
    """
    password_hash = hash_data(user.password) if user.password else None
    data = [str(user.id), password_hash]
    return _security.reset_serializer.dumps(data)


def reset_password_token_status(token):
    """Returns the expired status, invalid status, and user of a password reset
    token. For example::

        expired, invalid, user, data = reset_password_token_status('...')

    :param token: The password reset token
    """
    expired, invalid, user, data = get_token_status(
        token, 'reset', 'RESET_PASSWORD', return_data=True
    )
    if not invalid and user:
        if user.password:
            if not verify_hash(data[1], user.password):
                invalid = True

    return expired, invalid, user


def update_password(user, password):
    """Update the specified user's password

    :param user: The user to update_password
    :param password: The unhashed new password
    """
    user.password = hash_password(password)
    _datastore.put(user)
    send_password_reset_notice(user)
    password_reset.send(app._get_current_object(), user=user)
