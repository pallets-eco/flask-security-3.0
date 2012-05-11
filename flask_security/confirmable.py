
from datetime import datetime

from flask import current_app, request, url_for
from flask.ext.security.exceptions import UserNotFoundError
from flask.ext.security.utils import generate_token, send_mail
from werkzeug.local import LocalProxy

security = LocalProxy(lambda: current_app.security)
logger = LocalProxy(lambda: current_app.logger)


def send_confirmation_instructions(user):
    url = url_for('flask_security.confirm',
                  confirmation_token=user.confirmation_token)

    confirmation_link = request.url_root[:-1] + url

    send_mail('Please confirm your email', user.email,
              'confirmation_instructions',
              dict(user=user, confirmation_link=confirmation_link))


def generate_confirmation_token(user):
    while True:
        token = generate_token()
        try:
            security.datastore.find_user(confirmation_token=token)
        except UserNotFoundError:
            break

    now = datetime.utcnow()

    if isinstance(user, dict):
        user['confirmation_token'] = token
        user['confirmation_sent_at'] = now
    else:
        user.confirmation_token = token
        user.confirmation_sent_at = now

    return user
