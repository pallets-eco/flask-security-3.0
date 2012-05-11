
from datetime import datetime

from flask import render_template, current_app, request, url_for
from flask.ext.security.utils import generate_token
from werkzeug.local import LocalProxy


logger = LocalProxy(lambda: current_app.logger)


def send_confirmation_instructions(user):
    from flask.ext.mail import Message

    msg = Message("Please confirm your email",
                  sender=current_app.security.email_sender,
                  recipients=[user.email])

    confirmation_link = request.url_root[:-1] + \
                        url_for('flask_security.confirm',
                                confirmation_token=user.confirmation_token)

    ctx = dict(user=user, confirmation_link=confirmation_link)
    msg.body = render_template('email/confirmation_instructions.txt', **ctx)
    msg.html = render_template('email/confirmation_instructions.html', **ctx)

    logger.debug("Sending confirmation instructions")
    logger.debug(msg.html)

    current_app.mail.send(msg)


def generate_confirmation_token(user):
    token = generate_token()
    now = datetime.utcnow()

    if isinstance(user, dict):
        user['confirmation_token'] = token
        user['confirmation_sent_at'] = now
    else:
        user.confirmation_token = token
        user.confirmation_sent_at = now

    return user
