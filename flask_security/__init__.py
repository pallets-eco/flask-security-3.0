# -*- coding: utf-8 -*-
"""
    flask.ext.security
    ~~~~~~~~~~~~~~~~~~

    Flask-Security is a Flask extension that aims to add quick and simple
    security via Flask-Login, Flask-Principal, Flask-WTF, and passlib.

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

__version__ = '1.7.1'

from .core import Security, RoleMixin, UserMixin, AnonymousUser, current_user
from .datastore import SQLAlchemyUserDatastore, MongoEngineUserDatastore, PeeweeUserDatastore
from .decorators import auth_token_required, http_auth_required, \
     login_required, roles_accepted, roles_required, auth_required
from .forms import ForgotPasswordForm, LoginForm, RegisterForm, \
     ResetPasswordForm, PasswordlessLoginForm, ConfirmRegisterForm
from .signals import confirm_instructions_sent, password_reset, \
     reset_password_instructions_sent, user_confirmed, user_registered
from .utils import login_user, logout_user, url_for_security
