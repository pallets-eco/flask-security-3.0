# -*- coding: utf-8 -*-
"""
    flask_security.changeable
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security recoverable module

    :copyright: (c) 2012 by Matt Wright.
    :author: Eskil Heyn Olsen
    :license: MIT, see LICENSE for more details.
"""

from flask import current_app as app
from werkzeug.local import LocalProxy

from .signals import password_changed
from .utils import send_mail, encrypt_password, config_value


# Convenient references
_security = LocalProxy(lambda: app.extensions['security'])

_datastore = LocalProxy(lambda: _security.datastore)


def send_password_changed_notice(user):
    """Sends the password changed notice email for the specified user.

    :param user: The user to send the notice to
    """
    if config_value('SEND_PASSWORD_CHANGE_EMAIL'):
        subject = config_value('EMAIL_SUBJECT_PASSWORD_CHANGE_NOTICE')
        send_mail(subject, user.email, 'change_notice', user=user)


def change_user_password(user, password):
    """Change the specified user's password

    :param user: The user to change_password
    :param password: The unencrypted new password
    """
    user.password = encrypt_password(password)
    _datastore.put(user)
    send_password_changed_notice(user)
    password_changed.send(app._get_current_object(),
                          user=user._get_current_object())
