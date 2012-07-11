# -*- coding: utf-8 -*-
"""
    flask.ext.security.recoverable
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security recoverable module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from itsdangerous import BadSignature, SignatureExpired
from flask import current_app as app, request, url_for
from werkzeug.local import LocalProxy

from .exceptions import ResetPasswordError, UserNotFoundError, \
     TokenExpiredError
from .signals import password_reset, password_reset_requested, \
     reset_instructions_sent
from .utils import send_mail, get_max_age, md5


# Convenient references
_security = LocalProxy(lambda: app.security)

_datastore = LocalProxy(lambda: app.security.datastore)


def send_reset_password_instructions(user, reset_token):
    """Sends the reset password instructions email for the specified user.

    :param user: The user to send the instructions to
    """
    url = url_for('flask_security.reset',
                  token=reset_token)

    reset_link = request.url_root[:-1] + url

    send_mail('Password reset instructions',
              user.email,
              'reset_instructions',
              dict(user=user, reset_link=reset_link))

    reset_instructions_sent.send(dict(user=user, token=reset_token),
                                 app=app._get_current_object())

    return True


def send_password_reset_notice(user):
    """Sends the password reset notice email for the specified user.

    :param user: The user to send the notice to
    """
    send_mail('Your password has been reset',
              user.email,
              'reset_notice',
              dict(user=user))


def generate_reset_password_token(user):
    """Generates a unique reset password token for the specified user.

    :param user: The user to work with
    """
    data = [user.id, md5(user.password)]
    return _security.reset_serializer.dumps(data)


def reset_by_token(token, password):
    """Resets the password of the user given the specified token, email and
    password. If the token is invalid a `ResetPasswordError` error will be
    raised. If the token is expired a `TokenExpiredError` error will be raised.

    :param token: The user's reset password token
    :param email: The user's email address
    :param password: The user's new password
    """
    serializer = _security.reset_serializer
    max_age = get_max_age('RESET_PASSWORD')

    try:
        data = serializer.loads(token, max_age=max_age)
        user = _datastore.find_user(id=data[0])

        if md5(user.password) != data[1]:
            raise UserNotFoundError()

    except UserNotFoundError:
        raise ResetPasswordError('Invalid reset password token')

    except SignatureExpired:
        sig_okay, data = serializer.loads_unsafe(token)
        user = _datastore.find_user(id=data[0])
        raise TokenExpiredError('Reset password token is expired', user)

    except BadSignature:
        raise ResetPasswordError('Invalid reset password token')

    user.password = _security.pwd_context.encrypt(password)

    _datastore._save_model(user)

    send_password_reset_notice(user)

    password_reset.send(user, app=app._get_current_object())

    return user


def reset_password_reset_token(user):
    """Resets the specified user's reset password token and sends the user
    an email with instructions explaining next steps.

    :param user: The user to work with
    """
    token = generate_reset_password_token(user)

    send_reset_password_instructions(user, token)

    password_reset_requested.send(dict(user=user, token=token),
                                  app=app._get_current_object())

    return token
