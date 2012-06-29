# -*- coding: utf-8 -*-
"""
    flask.ext.security.recoverable
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security recoverable module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from datetime import datetime

from flask import current_app as app, request, url_for
from werkzeug.local import LocalProxy

from .exceptions import ResetPasswordError, UserNotFoundError, \
     TokenExpiredError
from .signals import password_reset, password_reset_requested, \
     confirm_instructions_sent
from .utils import generate_token, send_mail


# Convenient references
_security = LocalProxy(lambda: app.security)

_datastore = LocalProxy(lambda: app.security.datastore)


def find_user_by_reset_token(token):
    """Returns a user with a matching reset password token.

    :param token: The reset password token
    """
    if not token:
        raise ResetPasswordError('Reset password token required')
    return _datastore.find_user(reset_password_token=token)


def send_reset_password_instructions(user):
    """Sends the reset password instructions email for the specified user.

    :param user: The user to send the instructions to
    """
    url = url_for('flask_security.reset',
                  email=user.email,
                  reset_token=user.reset_password_token)

    reset_link = request.url_root[:-1] + url

    send_mail('Password reset instructions',
              user.email,
              'reset_instructions',
              dict(user=user, reset_link=reset_link))

    confirm_instructions_sent.send(user, app=app._get_current_object())

    return True


def generate_reset_password_token(user):
    """Generates a unique reset password token for the specified user.

    :param user: The user to work with
    """
    while True:
        token = generate_token()
        try:
            find_user_by_reset_token(token)
        except UserNotFoundError:
            break

    now = datetime.utcnow()

    try:
        user['reset_password_token'] = token
        user['reset_password_sent_at'] = now
    except TypeError:
        user.reset_password_token = token
        user.reset_password_sent_at = now

    return user


def password_reset_token_is_expired(user):
    """Returns `True` if the specified user's reset password token is expired.

    :param user: The user to examine
    """
    token_expires = datetime.utcnow() - _security.reset_password_within
    return user.reset_password_sent_at < token_expires


def reset_by_token(token, email, password):
    """Resets the password of the user given the specified token, email and
    password. If the token is invalid a `ResetPasswordError` error will be
    raised. If the token is expired a `TokenExpiredError` error will be raised.

    :param token: The user's reset password token
    :param email: The user's email address
    :param password: The user's new password
    """
    try:
        user = find_user_by_reset_token(token)
    except UserNotFoundError:
        raise ResetPasswordError('Invalid reset password token')

    if password_reset_token_is_expired(user):
        raise TokenExpiredError('Reset password token is expired', user)

    user.reset_password_token = None
    user.reset_password_sent_at = None
    user.password = _security.pwd_context.encrypt(password)

    _datastore._save_model(user)

    send_mail('Your password has been reset', user.email, 'reset_notice')

    password_reset.send(user, app=app._get_current_object())

    return user


def reset_password_reset_token(user):
    """Resets the specified user's reset password token and sends the user
    an email with instructions explaining next steps.

    :param user: The user to work with
    """
    _datastore._save_model(generate_reset_password_token(user))
    send_reset_password_instructions(user)
    password_reset_requested.send(user, app=app._get_current_object())
