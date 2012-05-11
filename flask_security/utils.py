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

from importlib import import_module

from flask import url_for, flash, current_app, request, session


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
