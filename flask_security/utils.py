# -*- coding: utf-8 -*-
"""
    flask.ext.security.utils
    ~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security utils module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

import base64
import os

from contextlib import contextmanager
from importlib import import_module

from flask import url_for, flash, current_app, request, session, render_template
from flask.ext.security.signals import user_registered


def generate_token():
    return base64.urlsafe_b64encode(os.urandom(30))


def do_flash(message, category):
    if config_value(current_app, 'FLASH_MESSAGES'):
        flash(message, category)


def get_class_from_string(app, key):
    """Get a reference to a class by its configuration key name."""
    cv = config_value(app, key).split('::')
    cm = import_module(cv[0])
    return getattr(cm, cv[1])


def get_url(endpoint_or_url):
    """Returns a URL if a valid endpoint is found. Otherwise, returns the
    provided value."""
    try:
        return url_for(endpoint_or_url)
    except:
        return endpoint_or_url


def get_post_login_redirect():
    """Returns the URL to redirect to after a user logs in successfully"""
    return (get_url(request.args.get('next')) or
            get_url(request.form.get('next')) or
            find_redirect('SECURITY_POST_LOGIN_VIEW'))


def find_redirect(key):
    """Returns the URL to redirect to after a user logs in successfully"""
    result = (get_url(session.pop(key.lower(), None)) or
              get_url(current_app.config[key.upper()] or None) or '/')

    try:
        del session[key.lower()]
    except:
        pass
    return result


def config_value(app, key, default=None):
    return app.config.get('SECURITY_' + key.upper(), default)


def send_mail(subject, recipient, template, context):
    from flask.ext.mail import Message

    msg = Message(subject,
                  sender=current_app.security.email_sender,
                  recipients=[recipient])

    msg.body = render_template('email/%s.txt' % template, **context)
    msg.html = render_template('email/%s.html' % template, **context)

    current_app.mail.send(msg)


@contextmanager
def capture_registrations(confirmation_sent_at=None):
    users = []

    def _on(user, app):
        if confirmation_sent_at:
            user.confirmation_sent_at = confirmation_sent_at
            current_app.security.datastore._save_model(user)

        users.append(user)

    user_registered.connect(_on)

    try:
        yield users
    finally:
        user_registered.disconnect(_on)
