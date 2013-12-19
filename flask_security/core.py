# -*- coding: utf-8 -*-
"""
    flask.ext.security.core
    ~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security core module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from flask import current_app
from flask.ext.login import AnonymousUserMixin, UserMixin as BaseUserMixin, \
    LoginManager, current_user
from flask.ext.principal import Principal, RoleNeed, UserNeed, Identity, \
    identity_loaded
from itsdangerous import URLSafeTimedSerializer
from passlib.context import CryptContext
from werkzeug.datastructures import ImmutableList
from werkzeug.local import LocalProxy

from .utils import config_value as cv, get_config, md5, url_for_security, string_types
from .views import create_blueprint
from .forms import LoginForm, ConfirmRegisterForm, RegisterForm, \
    ForgotPasswordForm, ChangePasswordForm, ResetPasswordForm, \
    SendConfirmationForm, PasswordlessLoginForm

# Convenient references
_security = LocalProxy(lambda: current_app.extensions['security'])


#: Default Flask-Security configuration
_default_config = {
    'BLUEPRINT_NAME': 'security',
    'URL_PREFIX': None,
    'SUBDOMAIN': None,
    'FLASH_MESSAGES': True,
    'PASSWORD_HASH': 'plaintext',
    'PASSWORD_SALT': None,
    'LOGIN_URL': '/login',
    'LOGOUT_URL': '/logout',
    'REGISTER_URL': '/register',
    'RESET_URL': '/reset',
    'CHANGE_URL': '/change',
    'CONFIRM_URL': '/confirm',
    'POST_LOGIN_VIEW': '/',
    'POST_LOGOUT_VIEW': '/',
    'CONFIRM_ERROR_VIEW': None,
    'POST_REGISTER_VIEW': None,
    'POST_CONFIRM_VIEW': None,
    'POST_RESET_VIEW': None,
    'POST_CHANGE_VIEW': None,
    'UNAUTHORIZED_VIEW': None,
    'FORGOT_PASSWORD_TEMPLATE': 'security/forgot_password.html',
    'LOGIN_USER_TEMPLATE': 'security/login_user.html',
    'REGISTER_USER_TEMPLATE': 'security/register_user.html',
    'RESET_PASSWORD_TEMPLATE': 'security/reset_password.html',
    'CHANGE_PASSWORD_TEMPLATE': 'security/change_password.html',
    'SEND_CONFIRMATION_TEMPLATE': 'security/send_confirmation.html',
    'SEND_LOGIN_TEMPLATE': 'security/send_login.html',
    'CONFIRMABLE': False,
    'REGISTERABLE': False,
    'RECOVERABLE': False,
    'TRACKABLE': False,
    'PASSWORDLESS': False,
    'CHANGEABLE': False,
    'SEND_REGISTER_EMAIL': True,
    'SEND_PASSWORD_CHANGE_EMAIL': True,
    'SEND_PASSWORD_RESET_NOTICE_EMAIL': True,
    'LOGIN_WITHIN': '1 days',
    'CONFIRM_EMAIL_WITHIN': '5 days',
    'RESET_PASSWORD_WITHIN': '5 days',
    'LOGIN_WITHOUT_CONFIRMATION': False,
    'EMAIL_SENDER': 'no-reply@localhost',
    'TOKEN_AUTHENTICATION_KEY': 'auth_token',
    'TOKEN_AUTHENTICATION_HEADER': 'Authentication-Token',
    'CONFIRM_SALT': 'confirm-salt',
    'RESET_SALT': 'reset-salt',
    'LOGIN_SALT': 'login-salt',
    'CHANGE_SALT': 'change-salt',
    'REMEMBER_SALT': 'remember-salt',
    'DEFAULT_REMEMBER_ME': False,
    'DEFAULT_HTTP_AUTH_REALM': 'Login Required',
    'EMAIL_SUBJECT_REGISTER': 'Welcome',
    'EMAIL_SUBJECT_CONFIRM': 'Please confirm your email',
    'EMAIL_SUBJECT_PASSWORDLESS': 'Login instructions',
    'EMAIL_SUBJECT_PASSWORD_NOTICE': 'Your password has been reset',
    'EMAIL_SUBJECT_PASSWORD_CHANGE_NOTICE': 'Your password has been changed',
    'EMAIL_SUBJECT_PASSWORD_RESET': 'Password reset instructions',
    'USER_IDENTITY_ATTRIBUTES': ['email']
}

#: Default Flask-Security messages
_default_messages = {
    'UNAUTHORIZED': ('You do not have permission to view this resource.', 'error'),
    'CONFIRM_REGISTRATION': ('Thank you. Confirmation instructions have been sent to %(email)s.', 'success'),
    'EMAIL_CONFIRMED': ('Thank you. Your email has been confirmed.', 'success'),
    'ALREADY_CONFIRMED': ('Your email has already been confirmed.', 'info'),
    'INVALID_CONFIRMATION_TOKEN': ('Invalid confirmation token.', 'error'),
    'EMAIL_ALREADY_ASSOCIATED': ('%(email)s is already associated with an account.', 'error'),
    'PASSWORD_MISMATCH': ('Password does not match', 'error'),
    'RETYPE_PASSWORD_MISMATCH': ('Passwords do not match', 'error'),
    'INVALID_REDIRECT': ('Redirections outside the domain are forbidden', 'error'),
    'PASSWORD_RESET_REQUEST': ('Instructions to reset your password have been sent to %(email)s.', 'info'),
    'PASSWORD_RESET_EXPIRED': ('You did not reset your password within %(within)s. New instructions have been sent to %(email)s.', 'error'),
    'INVALID_RESET_PASSWORD_TOKEN': ('Invalid reset password token.', 'error'),
    'CONFIRMATION_REQUIRED': ('Email requires confirmation.', 'error'),
    'CONFIRMATION_REQUEST': ('Confirmation instructions have been sent to %(email)s.', 'info'),
    'CONFIRMATION_EXPIRED': ('You did not confirm your email within %(within)s. New instructions to confirm your email have been sent to %(email)s.', 'error'),
    'LOGIN_EXPIRED': ('You did not login within %(within)s. New instructions to login have been sent to %(email)s.', 'error'),
    'LOGIN_EMAIL_SENT': ('Instructions to login have been sent to %(email)s.', 'success'),
    'INVALID_LOGIN_TOKEN': ('Invalid login token.', 'error'),
    'DISABLED_ACCOUNT': ('Account is disabled.', 'error'),
    'EMAIL_NOT_PROVIDED': ('Email not provided', 'error'),
    'INVALID_EMAIL_ADDRESS': ('Invalid email address', 'error'),
    'PASSWORD_NOT_PROVIDED': ('Password not provided', 'error'),
    'PASSWORD_NOT_SET': ('No password is set for this user', 'error'),
    'PASSWORD_INVALID_LENGTH': ('Password must be at least 6 characters', 'error'),
    'USER_DOES_NOT_EXIST': ('Specified user does not exist', 'error'),
    'INVALID_PASSWORD': ('Invalid password', 'error'),
    'PASSWORDLESS_LOGIN_SUCCESSFUL': ('You have successfuly logged in.', 'success'),
    'PASSWORD_RESET': ('You successfully reset your password and you have been logged in automatically.', 'success'),
    'PASSWORD_IS_THE_SAME': ('Your new password must be different than your previous password.', 'error'),
    'PASSWORD_CHANGE': ('You successfully changed your password.', 'success'),
    'LOGIN': ('Please log in to access this page.', 'info'),
    'REFRESH': ('Please reauthenticate to access this page.', 'info'),
}

_allowed_password_hash_schemes = [
    'bcrypt',
    'des_crypt',
    'pbkdf2_sha256',
    'pbkdf2_sha512',
    'sha256_crypt',
    'sha512_crypt',
    # And always last one...
    'plaintext'
]

_default_forms = {
    'login_form': LoginForm,
    'confirm_register_form': ConfirmRegisterForm,
    'register_form': RegisterForm,
    'forgot_password_form': ForgotPasswordForm,
    'reset_password_form': ResetPasswordForm,
    'change_password_form': ChangePasswordForm,
    'send_confirmation_form': SendConfirmationForm,
    'passwordless_login_form': PasswordlessLoginForm,
}


def _user_loader(user_id):
    return _security.datastore.find_user(id=user_id)


def _token_loader(token):
    try:
        data = _security.remember_token_serializer.loads(token)
        user = _security.datastore.find_user(id=data[0])
        if user and md5(user.password) == data[1]:
            return user
    except:
        pass
    return AnonymousUser()


def _identity_loader():
    if not isinstance(current_user._get_current_object(), AnonymousUser):
        identity = Identity(current_user.id)
        return identity


def _on_identity_loaded(sender, identity):
    if hasattr(current_user, 'id'):
        identity.provides.add(UserNeed(current_user.id))

    for role in current_user.roles:
        identity.provides.add(RoleNeed(role.name))

    identity.user = current_user


def _get_login_manager(app):
    lm = LoginManager()
    lm.anonymous_user = AnonymousUser
    lm.login_view = '%s.login' % cv('BLUEPRINT_NAME', app=app)
    lm.user_loader(_user_loader)
    lm.token_loader(_token_loader)

    if cv('FLASH_MESSAGES', app=app):
        lm.login_message, lm.login_message_category = cv('MSG_LOGIN', app=app)
        lm.needs_refresh_message, lm.needs_refresh_message_category = cv('MSG_REFRESH', app=app)
    else:
        lm.login_message = None
        lm.needs_refresh_message = None

    lm.init_app(app)
    return lm


def _get_principal(app):
    p = Principal(app, use_sessions=False)
    p.identity_loader(_identity_loader)
    return p


def _get_pwd_context(app):
    pw_hash = cv('PASSWORD_HASH', app=app)
    if pw_hash not in _allowed_password_hash_schemes:
        allowed = ', '.join(_allowed_password_hash_schemes[:-1]) + ' and ' + _allowed_password_hash_schemes[-1]
        raise ValueError("Invalid hash scheme %r. Allowed values are %s" % (pw_hash, allowed))
    return CryptContext(schemes=_allowed_password_hash_schemes, default=pw_hash)


def _get_serializer(app, name):
    secret_key = app.config.get('SECRET_KEY')
    salt = app.config.get('SECURITY_%s_SALT' % name.upper())
    return URLSafeTimedSerializer(secret_key=secret_key, salt=salt)


def _get_state(app, datastore, **kwargs):
    for key, value in get_config(app).items():
        kwargs[key.lower()] = value

    kwargs.update(dict(
        app=app,
        datastore=datastore,
        login_manager=_get_login_manager(app),
        principal=_get_principal(app),
        pwd_context=_get_pwd_context(app),
        remember_token_serializer=_get_serializer(app, 'remember'),
        login_serializer=_get_serializer(app, 'login'),
        reset_serializer=_get_serializer(app, 'reset'),
        confirm_serializer=_get_serializer(app, 'confirm'),
        _context_processors={},
        _send_mail_task=None
    ))

    for key, value in _default_forms.items():
        if key not in kwargs or not kwargs[key]:
            kwargs[key] = value

    return _SecurityState(**kwargs)


def _context_processor():
    return dict(url_for_security=url_for_security, security=_security)


class RoleMixin(object):
    """Mixin for `Role` model definitions"""

    def __eq__(self, other):
        return (self.name == other or
                self.name == getattr(other, 'name', None))

    def __ne__(self, other):
        return not self.__eq__(other)


class UserMixin(BaseUserMixin):
    """Mixin for `User` model definitions"""

    def is_active(self):
        """Returns `True` if the user is active."""
        return self.active

    def get_auth_token(self):
        """Returns the user's authentication token."""
        data = [str(self.id), md5(self.password)]
        return _security.remember_token_serializer.dumps(data)

    def has_role(self, role):
        """Returns `True` if the user identifies with the specified role.

        :param role: A role name or `Role` instance"""
        if isinstance(role, string_types):
            return role in (role.name for role in self.roles)
        else:
            return role in self.roles


class AnonymousUser(AnonymousUserMixin):
    """AnonymousUser definition"""

    def __init__(self):
        self.roles = ImmutableList()

    def has_role(self, *args):
        """Returns `False`"""
        return False


class _SecurityState(object):

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key.lower(), value)

    def _add_ctx_processor(self, endpoint, fn):
        group = self._context_processors.setdefault(endpoint, [])
        fn not in group and group.append(fn)

    def _run_ctx_processor(self, endpoint):
        rv, fns = {}, []
        for g in [None, endpoint]:
            for fn in self._context_processors.setdefault(g, []):
                rv.update(fn())
        return rv

    def context_processor(self, fn):
        self._add_ctx_processor(None, fn)

    def forgot_password_context_processor(self, fn):
        self._add_ctx_processor('forgot_password', fn)

    def login_context_processor(self, fn):
        self._add_ctx_processor('login', fn)

    def register_context_processor(self, fn):
        self._add_ctx_processor('register', fn)

    def reset_password_context_processor(self, fn):
        self._add_ctx_processor('reset_password', fn)

    def change_password_context_processor(self, fn):
        self._add_ctx_processor('change_password', fn)

    def send_confirmation_context_processor(self, fn):
        self._add_ctx_processor('send_confirmation', fn)

    def send_login_context_processor(self, fn):
        self._add_ctx_processor('send_login', fn)

    def mail_context_processor(self, fn):
        self._add_ctx_processor('mail', fn)

    def send_mail_task(self, fn):
        self._send_mail_task = fn


class Security(object):
    """The :class:`Security` class initializes the Flask-Security extension.

    :param app: The application.
    :param datastore: An instance of a user datastore.
    """
    def __init__(self, app=None, datastore=None, **kwargs):
        self.app = app
        self.datastore = datastore

        if app is not None and datastore is not None:
            self._state = self.init_app(app, datastore, **kwargs)

    def init_app(self, app, datastore=None, register_blueprint=True,
                 login_form=None, confirm_register_form=None,
                 register_form=None, forgot_password_form=None,
                 reset_password_form=None, change_password_form=None,
                 send_confirmation_form=None, passwordless_login_form=None):
        """Initializes the Flask-Security extension for the specified
        application and datastore implentation.

        :param app: The application.
        :param datastore: An instance of a user datastore.
        :param register_blueprint: to register the Security blueprint or not.
        """
        datastore = datastore or self.datastore

        for key, value in _default_config.items():
            app.config.setdefault('SECURITY_' + key, value)

        for key, value in _default_messages.items():
            app.config.setdefault('SECURITY_MSG_' + key, value)

        identity_loaded.connect_via(app)(_on_identity_loaded)

        state = _get_state(app, datastore,
                           login_form=login_form,
                           confirm_register_form=confirm_register_form,
                           register_form=register_form,
                           forgot_password_form=forgot_password_form,
                           reset_password_form=reset_password_form,
                           change_password_form=change_password_form,
                           send_confirmation_form=send_confirmation_form,
                           passwordless_login_form=passwordless_login_form)

        if register_blueprint:
            app.register_blueprint(create_blueprint(state, __name__))
            app.context_processor(_context_processor)

        app.extensions['security'] = state

        return state

    def __getattr__(self, name):
        return getattr(self._state, name, None)
