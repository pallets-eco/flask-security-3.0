
from datetime import datetime, timedelta

from flask import current_app
from flask.ext.security.utils import generate_token


def reset_password_period_valid(user):
    sent_at = user.reset_password_sent_at
    reset_within = int(current_app.security.reset_password_within)
    days_ago = datetime.utcnow() - timedelta(days=reset_within)

    return (sent_at is not None) and \
           (sent_at >= days_ago)


def generate_reset_password_token(user):
    user.reset_password_token = generate_token()
    user.reset_password_sent_at = datetime.utcnow()
    current_app.security.datastore._save_model(user)


def clear_reset_password_token(user):
    user.reset_password_token = None
    user.reset_password_sent_at = None


def send_reset_password_instructions():
    pass


def should_generate_reset_token(user):
    return (user.reset_password_token is None) or \
           (not reset_password_period_valid(user))
