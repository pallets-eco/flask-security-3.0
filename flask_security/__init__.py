# -*- coding: utf-8 -*-
"""
    flask_security
    ~~~~~~~~~~~~~~

    Flask-Security is a Flask extension that aims to add quick and simple
    security via Flask-Login, Flask-Principal, Flask-WTF, and passlib.

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from .core import Security, RoleMixin, UserMixin, AnonymousUser, current_user
from .datastore import SQLAlchemyUserDatastore, MongoEngineUserDatastore, \
    PeeweeUserDatastore, PonyUserDatastore, SQLAlchemySessionUserDatastore
from .decorators import auth_token_required, http_auth_required, \
    login_required, roles_accepted, roles_required, auth_required
from .forms import ForgotPasswordForm, LoginForm, RegisterForm, \
    ResetPasswordForm, PasswordlessLoginForm, ConfirmRegisterForm
from .signals import confirm_instructions_sent, password_reset, \
    reset_password_instructions_sent, user_confirmed, user_registered
from .utils import login_user, logout_user, url_for_security

__version__ = '3.0.0'
__all__ = (
    'AnonymousUser',
    'ConfirmRegisterForm',
    'ForgotPasswordForm',
    'LoginForm',
    'MongoEngineUserDatastore',
    'PasswordlessLoginForm',
    'PeeweeUserDatastore',
    'PonyUserDatastore',
    'RegisterForm',
    'ResetPasswordForm',
    'RoleMixin',
    'SQLAlchemyUserDatastore',
    'SQLAlchemySessionUserDatastore',
    'Security',
    'UserMixin',
    'auth_required',
    'auth_token_required',
    'confirm_instructions_sent',
    'current_user',
    'http_auth_required',
    'login_required',
    'login_user',
    'logout_user',
    'password_reset',
    'reset_password_instructions_sent',
    'roles_accepted',
    'roles_required',
    'url_for_security',
    'user_confirmed',
    'user_registered',
)
