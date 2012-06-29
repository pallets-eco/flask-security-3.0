# -*- coding: utf-8 -*-
"""
    flask.ext.security.confirmable
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security confirmable module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from datetime import datetime

from flask import current_app as app, request, url_for
from werkzeug.local import LocalProxy

from .exceptions import UserNotFoundError, ConfirmationError, TokenExpiredError
from .utils import generate_token, send_mail
from .signals import user_confirmed, confirm_instructions_sent


# Convenient references
_security = LocalProxy(lambda: app.security)

_datastore = LocalProxy(lambda: app.security.datastore)


def find_user_by_confirmation_token(token):
    """Returns a user with a matching confirmation token.

    :param token: The reset password token
    """
    if not token:
        raise ConfirmationError('Confirmation token required')
    return _datastore.find_user(confirmation_token=token)


def send_confirmation_instructions(user):
    """Sends the confirmation instructions email for the specified user.

    :param user: The user to send the instructions to
    """
    url = url_for('flask_security.confirm',
                  confirmation_token=user.confirmation_token)

    confirmation_link = request.url_root[:-1] + url

    send_mail('Please confirm your email', user.email,
              'confirmation_instructions',
              dict(user=user, confirmation_link=confirmation_link))

    confirm_instructions_sent.send(user, app=app._get_current_object())

    return True


def generate_confirmation_token(user):
    """Generates a unique confirmation token for the specified user.

    :param user: The user to work with
    """
    while True:
        token = generate_token()
        try:
            find_user_by_confirmation_token(token)
        except UserNotFoundError:
            break

    now = datetime.utcnow()

    try:
        user['confirmation_token'] = token
        user['confirmation_sent_at'] = now
    except TypeError:
        user.confirmation_token = token
        user.confirmation_sent_at = now

    return user


def should_confirm_email(fn):
    """Handy decorator that returns early if confirmation should not occur."""
    def wrapped(*args, **kwargs):
        if _security.confirmable:
            return fn(*args, **kwargs)
        return False
    return wrapped


@should_confirm_email
def requires_confirmation(user):
    """Returns `True` if the user requires confirmation."""
    return user.confirmed_at == None


@should_confirm_email
def confirmation_token_is_expired(user):
    """Returns `True` if the user's confirmation token is expired."""
    token_expires = datetime.utcnow() - _security.confirm_email_within
    return user.confirmation_sent_at < token_expires


def confirm_by_token(token):
    """Confirm the user given the specified token. If the token is invalid or
    the user is already confirmed a `ConfirmationError` error will be raised.
    If the token is expired a `TokenExpiredError` error will be raised.

    :param token: The user's confirmation token
    """
    try:
        user = find_user_by_confirmation_token(token)
    except UserNotFoundError:
        raise ConfirmationError('Invalid confirmation token')

    if user.confirmed_at:
        raise ConfirmationError('Account has already been confirmed')

    if confirmation_token_is_expired(user):
        raise TokenExpiredError(message='Confirmation token is expired',
                                user=user)

    # TODO: Clear confirmation_token after confirmation?
    #user.confirmation_token = None
    #user.confirmation_sent_at = None
    user.confirmed_at = datetime.utcnow()

    _datastore._save_model(user)

    user_confirmed.send(user, app=app._get_current_object())
    return user


def reset_confirmation_token(user):
    """Resets the specified user's confirmation token and sends the user
    an email with instructions explaining next steps.

    :param user: The user to work with
    """
    _datastore._save_model(generate_confirmation_token(user))
    send_confirmation_instructions(user)
