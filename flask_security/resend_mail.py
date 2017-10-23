# coding: utf-8

# -*- coding: utf-8 -*-
"""
    flask_security.resend_email
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security recoverable module

    :copyright: (c) 2017 by Timilong(timilong@simright.com).
    :author: xialong Li(timilong@simright.com)
    :license: MIT, see LICENSE for more details.
"""
from flask import current_app as app

from werkzeug.local import LocalProxy

from .confirmable import generate_confirmation_link
from .signals import resend_email
from .utils import do_flash, get_message, send_mail, config_value

# Convenient references
_security = LocalProxy(lambda: app.extensions['security'])

_datastore = LocalProxy(lambda: _security.datastore)


def resend_register_email(user):
    confirmation_link, token = None, None

    if _security.confirmable:
        confirmation_link, token = generate_confirmation_link(user)
        do_flash(*get_message('CONFIRM_REGISTRATION', email=user.email))

    resend_email.send(app._get_current_object(), user=user, confirm_token=token)

    if config_value('SEND_REGISTER_EMAIL'):
        try:
            send_mail(
                config_value('EMAIL_SUBJECT_REGISTER'),
                user.email,
                'welcome',
                user=user,
                confirmation_link=confirmation_link
            )
            return True
        except Exception as err:
            return err

    return False


