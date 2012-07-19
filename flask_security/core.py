# -*- coding: utf-8 -*-
"""
    flask.ext.security.core
    ~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security core module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from itsdangerous import URLSafeTimedSerializer
from flask import current_app
from flask.ext.login import AnonymousUser as AnonymousUserBase, \
     UserMixin as BaseUserMixin, LoginManager, current_user
from flask.ext.principal import Principal, RoleNeed, UserNeed, Identity, \
     identity_loaded
from passlib.context import CryptContext
from werkzeug.datastructures import ImmutableList
from werkzeug.local import LocalProxy

from . import views, exceptions
from .confirmable import requires_confirmation
from .utils import config_value as cv, get_config, verify_password

# Convenient references
_security = LocalProxy(lambda: current_app.extensions['security'])


#: Default Flask-Security configuration
_default_config = {
    'URL_PREFIX': None,
    'FLASH_MESSAGES': True,
    'PASSWORD_HASH': 'plaintext',
    'PASSWORD_SALT': None,
    'PASSWORD_HMAC': False,
    'AUTH_URL': '/auth',
    'LOGOUT_URL': '/logout',
    'REGISTER_URL': '/register',
    'RESET_URL': '/reset',
    'CONFIRM_URL': '/confirm',
    'LOGIN_VIEW': '/login',
    'CONFIRM_ERROR_VIEW': '/confirm',
    'POST_LOGIN_VIEW': '/',
    'POST_LOGOUT_VIEW': '/',
    'POST_FORGOT_VIEW': '/',
    'RESET_PASSWORD_ERROR_VIEW': '/',
    'POST_REGISTER_VIEW': None,
    'POST_CONFIRM_VIEW': None,
    'UNAUTHORIZED_VIEW': None,
    'DEFAULT_ROLES': [],
    'CONFIRMABLE': False,
    'REGISTERABLE': False,
    'RECOVERABLE': False,
    'TRACKABLE': False,
    'CONFIRM_EMAIL_WITHIN': '5 days',
    'RESET_PASSWORD_WITHIN': '5 days',
    'LOGIN_WITHOUT_CONFIRMATION': False,
    'EMAIL_SENDER': 'no-reply@localhost',
    'TOKEN_AUTHENTICATION_KEY': 'auth_token',
    'TOKEN_AUTHENTICATION_HEADER': 'X-Auth-Token',
    'CONFIRM_SALT': 'confirm-salt',
    'RESET_SALT': 'reset-salt',
    'AUTH_SALT': 'auth-salt',
    'DEFAULT_HTTP_AUTH_REALM': 'Login Required'
}

#: Default Flask-Security flash messages
_default_flash_messages = {
    'UNAUTHORIZED': ('You do not have permission to view this resource.', 'error'),
    'ACCOUNT_CONFIRMED': ('Your account has been confirmed. You may now log in.', 'success'),
    'ALREADY_CONFIRMED': ('Your account has already been confirmed', 'info'),
    'INVALID_CONFIRMATION_TOKEN': ('Invalid confirmation token', 'error'),
    'PASSWORD_RESET_REQUEST': ('Instructions to reset your password have been sent to %(email)s.', 'info'),
    'PASSWORD_RESET_EXPIRED': ('You did not reset your password within %(within)s. New instructions have been sent to %(email)s.', 'error'),
    'INVALID_RESET_PASSWORD_TOKEN': ('Invalid reset password token', 'error'),
    'CONFIRMATION_REQUEST': ('A new confirmation code has been sent to %(email)s.', 'info'),
    'CONFIRMATION_EXPIRED': ('You did not confirm your account within %(within)s. New instructions to confirm your account have been sent to %(email)s.', 'error')
}


def _user_loader(user_id):
    try:
        return _security.datastore.with_id(user_id)
    except Exception, e:
        current_app.logger.error('Error getting user: %s' % e)
        return None


def _token_loader(token):
    try:
        return _security.datastore.find_user(remember_token=token)
    except Exception, e:
        current_app.logger.error('Error getting user: %s' % e)
        return None


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
    lm.login_view = cv('LOGIN_VIEW', app=app)
    lm.user_loader(_user_loader)
    lm.token_loader(_token_loader)
    lm.init_app(app)
    return lm


def _get_principal(app):
    p = Principal(app, use_sessions=False)
    p.identity_loader(_identity_loader)
    return p


def _get_pwd_context(app):
    pw_hash = cv('PASSWORD_HASH', app=app)
    return CryptContext(schemes=[pw_hash], default=pw_hash)


def _get_serializer(app, salt):
    secret_key = app.config.get('SECRET_KEY', 'secret-key')
    return URLSafeTimedSerializer(secret_key=secret_key, salt=salt)


def _get_reset_serializer(app):
    return _get_serializer(app, app.config['SECURITY_RESET_SALT'])


def _get_confirm_serializer(app):
    return _get_serializer(app, app.config['SECURITY_CONFIRM_SALT'])


def _get_token_auth_serializer(app):
    return _get_serializer(app, app.config['SECURITY_AUTH_SALT'])


class RoleMixin(object):
    """Mixin for `Role` model definitions"""
    def __eq__(self, other):
        return self.name == other or self.name == getattr(other, 'name', None)

    def __ne__(self, other):
        return self.name != other and self.name != getattr(other, 'name', None)

    def __str__(self):
        return '<Role name=%s>' % self.name


class UserMixin(BaseUserMixin):
    """Mixin for `User` model definitions"""

    def is_active(self):
        """Returns `True` if the user is active."""
        return self.active

    def get_auth_token(self):
        """Returns the user's authentication token."""
        self.remember_token

    def has_role(self, role):
        """Returns `True` if the user identifies with the specified role.

        :param role: A role name or `Role` instance"""
        return role in self.roles

    def __str__(self):
        ctx = (str(self.id), self.email)
        return '<User id=%s, email=%s>' % ctx


class AnonymousUser(AnonymousUserBase):
    """AnonymousUser definition"""

    def __init__(self):
        super(AnonymousUser, self).__init__()
        self.roles = ImmutableList()

    def has_role(self, *args):
        """Returns `False`"""
        return False


class _SecurityState(object):

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key.lower(), value)


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

    def init_app(self, app, datastore=None, register_blueprint=True):
        """Initializes the Flask-Security extension for the specified
        application and datastore implentation.

        :param app: The application.
        :param datastore: An instance of a user datastore.
        """

        for key, value in _default_config.items():
            app.config.setdefault('SECURITY_' + key, value)

        for key, value in _default_flash_messages.items():
            app.config.setdefault('SECURITY_MSG_' + key, value)

        identity_loaded.connect_via(app)(_on_identity_loaded)

        if register_blueprint:
            bp = views.create_blueprint(app, 'flask_security', __name__,
                                        template_folder='templates',
                                        url_prefix=cv('URL_PREFIX', app=app))
            app.register_blueprint(bp)

        state = self._get_state(app, datastore or self.datastore)

        if not hasattr(app, 'extensions'):
            app.extensions = {}

        app.extensions['security'] = state

    def _get_state(self, app, datastore):
        assert app is not None
        assert datastore is not None

        kwargs = {}

        for key, value in get_config(app).items():
            kwargs[key.lower()] = value

        for key, value in [
                ('app', app),
                ('datastore', datastore),
                ('auth_provider', AuthenticationProvider()),
                ('login_manager', _get_login_manager(app)),
                ('principal', _get_principal(app)),
                ('pwd_context', _get_pwd_context(app)),
                ('token_auth_serializer', _get_token_auth_serializer(app))]:
            kwargs[key] = value

        kwargs['reset_serializer'] = (
            _get_reset_serializer(app) if kwargs['recoverable'] else None)

        kwargs['confirm_serializer'] = (
            _get_confirm_serializer(app) if kwargs['confirmable'] else None)

        return _SecurityState(**kwargs)

    def __getattr__(self, name):
        return getattr(self._state, name, None)


class AuthenticationProvider(object):
    """The default authentication provider implementation."""
    def _get_user(self, username_or_email):
        datastore = _security.datastore

        try:
            return datastore.find_user(email=username_or_email)
        except exceptions.UserNotFoundError:
            try:
                return datastore.find_user(username=username_or_email)
            except:
                raise exceptions.UserNotFoundError()

    def authenticate(self, form):
        """Processes an authentication request and returns a user instance if
        authentication is successful.

        :param form: A populated WTForm instance that contains `email` and
                     `password` form fields
        """
        if not form.validate():
            if form.email.errors:
                raise exceptions.BadCredentialsError(form.email.errors[0])
            if form.password.errors:
                raise exceptions.BadCredentialsError(form.password.errors[0])

        return self.do_authenticate(form.email.data, form.password.data)

    def do_authenticate(self, username_or_email, password):
        """Returns the authenticated user if authentication is successfull. If
        authentication fails an appropriate `AuthenticationError` is raised

        :param username_or_email: The username or email address of the user
        :param password: The password supplied by the authentication request
        """

        try:
            user = self._get_user(username_or_email)
        except AttributeError, e:
            self.auth_error("Could not find user datastore: %s" % e)
        except exceptions.UserNotFoundError, e:
            raise exceptions.BadCredentialsError("Specified user does not exist")
        except Exception, e:
            self.auth_error('Unexpected authentication error: %s' % e)

        if requires_confirmation(user):
            raise exceptions.BadCredentialsError('Account requires confirmation')

        # compare passwords
        if verify_password(password, user.password,
                           salt=_security.password_salt,
                           use_hmac=_security.password_hmac):
            return user

        # bad match
        raise exceptions.BadCredentialsError("Password does not match")

    def auth_error(self, msg):
        """Sends an error log message and raises an authentication error.

        :param msg: An authentication error message"""
        current_app.logger.error(msg)
        raise exceptions.AuthenticationError(msg)
