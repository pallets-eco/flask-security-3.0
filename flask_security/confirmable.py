
from datetime import datetime

from flask import current_app, request, url_for
from flask.ext.security.exceptions import UserNotFoundError, \
     ConfirmationError, TokenExpiredError
from flask.ext.security.utils import generate_token, send_mail
from werkzeug.local import LocalProxy

security = LocalProxy(lambda: current_app.security)

logger = LocalProxy(lambda: current_app.logger)


def find_user_by_confirmation_token(token):
    if not token:
        raise ConfirmationError('Confirmation token required')
    return security.datastore.find_user(confirmation_token=token)


def send_confirmation_instructions(user):
    url = url_for('flask_security.confirm',
                  confirmation_token=user.confirmation_token)

    confirmation_link = request.url_root[:-1] + url

    send_mail('Please confirm your email', user.email,
              'confirmation_instructions',
              dict(user=user, confirmation_link=confirmation_link))

    return True


def generate_confirmation_token(user):
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
    def wrapped(*args, **kwargs):
        if security.confirm_email:
            return fn(*args, **kwargs)
        return False
    return wrapped


@should_confirm_email
def requires_confirmation(user):
    return user.confirmed_at == None


@should_confirm_email
def confirmation_token_is_expired(user):
    token_expires = datetime.utcnow() - security.confirm_email_within
    return user.confirmation_sent_at < token_expires


def confirm_by_token(token):
    try:
        user = find_user_by_confirmation_token(token)
    except UserNotFoundError:
        raise ConfirmationError('Invalid confirmation token')

    if confirmation_token_is_expired(user):
        raise TokenExpiredError(message='Confirmation token is expired',
                                user=user)

    user.confirmation_token = None
    user.confirmation_sent_at = None
    user.confirmed_at = datetime.utcnow()

    security.datastore._save_model(user)

    return user


def reset_confirmation_token(user):
    security.datastore._save_model(generate_confirmation_token(user))
    send_confirmation_instructions(user)
