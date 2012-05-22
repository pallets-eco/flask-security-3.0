
from datetime import datetime

from flask import current_app, request, url_for
from flask.ext.security.exceptions import ResetPasswordError, \
     UserNotFoundError, TokenExpiredError
from flask.ext.security.signals import password_reset_requested
from flask.ext.security.utils import generate_token, send_mail
from werkzeug.local import LocalProxy

security = LocalProxy(lambda: current_app.security)

logger = LocalProxy(lambda: current_app.logger)


def find_user_by_reset_token(token):
    if not token:
        raise ResetPasswordError('Reset password token required')
    return security.datastore.find_user(reset_password_token=token)


def send_reset_password_instructions(user):
    url = url_for('flask_security.reset',
                  reset_token=user.reset_password_token)

    reset_link = request.url_root[:-1] + url

    send_mail('Password reset instructions',
              user.email,
              'reset_instructions',
              dict(user=user, reset_link=reset_link))

    return True


def generate_reset_password_token(user):
    while True:
        token = generate_token()
        try:
            find_user_by_reset_token(token)
        except UserNotFoundError:
            break

    now = datetime.utcnow()

    try:
        user['reset_password_token'] = token
        user['reset_password_token'] = now
    except TypeError:
        user.reset_password_token = token
        user.reset_password_sent_at = now

    return user


def password_reset_token_is_expired(user):
    token_expires = datetime.utcnow() - security.reset_password_within
    return user.reset_password_sent_at < token_expires


def reset_by_token(token, email, password):
    try:
        user = find_user_by_reset_token(token)
    except UserNotFoundError:
        raise ResetPasswordError('Invalid reset password token')

    if password_reset_token_is_expired(user):
        raise TokenExpiredError('Reset password token is expired', user)

    user.reset_password_token = None
    user.reset_password_sent_at = None
    user.password = security.pwd_context.encrypt(password)

    security.datastore._save_model(user)

    return user


def reset_password_reset_token(user):
    security.datastore._save_model(generate_reset_password_token(user))
    send_reset_password_instructions(user)
    password_reset_requested.send(user, app=current_app._get_current_object())
