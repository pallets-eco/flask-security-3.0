# -*- coding: utf-8 -*-
"""
    flask.ext.security
    ~~~~~~~~~~~~~~~~~~

    Flask-Security is a Flask extension that aims to add quick and simple
    security via Flask-Login, Flask-Principal, Flask-WTF, and passlib.

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from flask.ext.login import login_user, logout_user

from .core import Security, RoleMixin, UserMixin, AnonymousUser, \
     AuthenticationProvider, current_user
from .decorators import auth_token_required, http_auth_required, \
     login_required, roles_accepted, roles_required
from .forms import ForgotPasswordForm, LoginForm, RegisterForm, \
     ResetPasswordForm
from .signals import confirm_instructions_sent, password_reset, \
     password_reset_requested, reset_instructions_sent, user_confirmed, \
     user_registered
