# -*- coding: utf-8 -*-
"""
    flask_security.decorators
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security decorators module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from collections import namedtuple
from functools import wraps

from flask import (abort, current_app, Response, request,
                   url_for, redirect, _request_ctx_stack)
from flask_login import current_user, login_required  # pragma: no flakes
from flask_principal import RoleNeed, Permission, Identity, identity_changed
from werkzeug.local import LocalProxy
from werkzeug.routing import BuildError

from . import utils


# Convenient references
_security = LocalProxy(lambda: current_app.extensions['security'])


_default_unauthorized_html = """
    <h1>Unauthorized</h1>
    <p>The server could not verify that you are authorized to access the URL
    requested. You either supplied the wrong credentials (e.g. a bad password),
    or your browser doesn't understand how to supply the credentials required.</p>
    """

BasicAuth = namedtuple('BasicAuth', 'username, password')


def _get_unauthorized_response(text=None, headers=None):
    text = text or _default_unauthorized_html
    headers = headers or {}
    return Response(text, 401, headers)


def _get_unauthorized_view():
    view = utils.get_url(utils.config_value('UNAUTHORIZED_VIEW'))
    if view:
        if callable(view):
            view = view()
        else:
            try:
                view = url_for(view)
            except BuildError:
                view = None
        utils.do_flash(*utils.get_message('UNAUTHORIZED'))
        return redirect(view or request.referrer or '/')
    abort(403)


def roles_required(*roles):
    """Decorator which specifies that a user must have all the specified roles.
    Example::

        @app.route('/dashboard')
        @roles_required('admin', 'editor')
        def dashboard():
            return 'Dashboard'

    The current user must have both the `admin` role and `editor` role in order
    to view the page.

    :param args: The required roles.
    """
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            perms = [Permission(RoleNeed(role)) for role in roles]
            for perm in perms:
                if not perm.can():
                    if _security._unauthorized_callback:
                        return _security._unauthorized_callback()
                    else:
                        return _get_unauthorized_view()
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper


def roles_accepted(*roles):
    """Decorator which specifies that a user must have at least one of the
    specified roles. Example::

        @app.route('/create_post')
        @roles_accepted('editor', 'author')
        def create_post():
            return 'Create Post'

    The current user must have either the `editor` role or `author` role in
    order to view the page.

    :param args: The possible roles.
    """
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            perm = Permission(*[RoleNeed(role) for role in roles])
            if perm.can():
                return fn(*args, **kwargs)
            if _security._unauthorized_callback:
                return _security._unauthorized_callback()
            else:
                return _get_unauthorized_view()
        return decorated_view
    return wrapper


def anonymous_user_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if current_user.is_authenticated:
            return redirect(utils.get_url(_security.post_login_view))
        return f(*args, **kwargs)
    return wrapper
