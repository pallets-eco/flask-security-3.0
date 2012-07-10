# -*- coding: utf-8 -*-
"""
    flask.ext.security.core
    ~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security core module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from datetime import timedelta

from flask import current_app, Blueprint
from flask.ext.login import AnonymousUser as AnonymousUserBase, \
     UserMixin as BaseUserMixin, LoginManager, current_user
from flask.ext.principal import Principal, RoleNeed, UserNeed, Identity, \
     identity_loaded
from passlib.context import CryptContext
from werkzeug.datastructures import ImmutableList

from . import views, exceptions, utils
from .confirmable import confirmation_token_is_expired, requires_confirmation, \
     reset_confirmation_token
from .decorators import login_required


#: Default Flask-Security configuration
_default_config = {
    'URL_PREFIX': None,
    'FLASH_MESSAGES': True,
    'PASSWORD_HASH': 'plaintext',
    'AUTH_PROVIDER': 'flask.ext.security::AuthenticationProvider',
    'AUTH_URL': '/auth',
    'LOGOUT_URL': '/logout',
    'REGISTER_URL': '/register',
    'FORGOT_URL': '/forgot',
    'RESET_URL': '/reset',
    'CONFIRM_URL': '/confirm',
    'LOGIN_VIEW': '/login',
    'POST_LOGIN_VIEW': '/',
    'POST_LOGOUT_VIEW': '/',
    'POST_FORGOT_VIEW': '/',
    'RESET_PASSWORD_ERROR_VIEW': '/',
    'POST_REGISTER_VIEW': None,
    'POST_CONFIRM_VIEW': None,
    'DEFAULT_ROLES': [],
    'CONFIRMABLE': False,
    'REGISTERABLE': False,
    'RECOVERABLE': False,
    'TRACKABLE': False,
    'CONFIRM_EMAIL_WITHIN': '5 days',
    'RESET_PASSWORD_WITHIN': '2 days',
    'LOGIN_WITHOUT_CONFIRMATION': False,
    'EMAIL_SENDER': 'no-reply@localhost',
    'TOKEN_AUTHENTICATION_KEY': 'auth_token',
    'TOKEN_AUTHENTICATION_HEADER': 'X-Auth-Token'
}


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


def _user_loader(user_id):
    try:
        return current_app.security.datastore.with_id(user_id)
    except Exception, e:
        current_app.logger.error('Error getting user: %s' % e)
        return None


def _token_loader(token):
    try:
        return current_app.security.datastore.find_user(remember_token=token)
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


class Security(object):
    """The :class:`Security` class initializes the Flask-Security extension.

    :param app: The application.
    :param datastore: An instance of a user datastore.
    """
    def __init__(self, app=None, datastore=None, **kwargs):
        self.init_app(app, datastore, **kwargs)

    def init_app(self, app, datastore):
        """Initializes the Flask-Security extension for the specified
        application and datastore implentation.

        :param app: The application.
        :param datastore: An instance of a user datastore.
        :param confirmable: Set to `True` to enable email confirmation
        :param registerable: Set to `False` to disable registration endpoints
        :param recoverable: Set to `False` to disable password recovery
                            endpoints
        """
        if app is None or datastore is None:
            return

        for key, value in _default_config.items():
            app.config.setdefault('SECURITY_' + key, value)

        login_manager = LoginManager()
        login_manager.anonymous_user = AnonymousUser
        login_manager.login_view = utils.config_value(app, 'LOGIN_VIEW')
        login_manager.user_loader(_user_loader)
        login_manager.token_loader(_token_loader)
        login_manager.init_app(app)

        Provider = utils.get_class_from_string(app, 'AUTH_PROVIDER')
        pw_hash = utils.config_value(app, 'PASSWORD_HASH')

        self.login_manager = login_manager

        self.pwd_context = CryptContext(schemes=[pw_hash], default=pw_hash)

        self.auth_provider = Provider()

        self.principal = Principal(app, use_sessions=False)
        self.principal.identity_loader(_identity_loader)

        self.datastore = datastore

        self.auth_url = utils.config_value(app, 'AUTH_URL')
        self.logout_url = utils.config_value(app, 'LOGOUT_URL')
        self.reset_url = utils.config_value(app, 'RESET_URL')
        self.register_url = utils.config_value(app, 'REGISTER_URL')
        self.confirm_url = utils.config_value(app, 'CONFIRM_URL')
        self.forgot_url = utils.config_value(app, 'FORGOT_URL')

        self.post_login_view = utils.config_value(app, 'POST_LOGIN_VIEW')
        self.post_logout_view = utils.config_value(app, 'POST_LOGOUT_VIEW')
        self.post_register_view = utils.config_value(app, 'POST_REGISTER_VIEW')
        self.post_confirm_view = utils.config_value(app, 'POST_CONFIRM_VIEW')
        self.post_forgot_view = utils.config_value(app, 'POST_FORGOT_VIEW')
        self.reset_password_error_view = utils.config_value(app, 'RESET_PASSWORD_ERROR_VIEW')

        self.default_roles = utils.config_value(app, "DEFAULT_ROLES")
        self.login_without_confirmation = utils.config_value(app, 'LOGIN_WITHOUT_CONFIRMATION')
        self.confirmable = utils.config_value(app, 'CONFIRMABLE')
        self.registerable = utils.config_value(app, 'REGISTERABLE')
        self.recoverable = utils.config_value(app, 'RECOVERABLE')
        self.trackable = utils.config_value(app, 'TRACKABLE')
        self.email_sender = utils.config_value(app, 'EMAIL_SENDER')
        self.token_authentication_key = utils.config_value(app, 'TOKEN_AUTHENTICATION_KEY')
        self.token_authentication_header = utils.config_value(app, 'TOKEN_AUTHENTICATION_HEADER')

        self.confirm_email_within_text = utils.config_value(app, 'CONFIRM_EMAIL_WITHIN')
        values = self.confirm_email_within_text.split()
        self.confirm_email_within = timedelta(**{values[1]: int(values[0])})

        self.reset_password_within_text = utils.config_value(app, 'RESET_PASSWORD_WITHIN')
        values = self.reset_password_within_text.split()
        self.reset_password_within = timedelta(**{values[1]: int(values[0])})

        identity_loaded.connect_via(app)(_on_identity_loaded)

        bp = Blueprint('flask_security', __name__, template_folder='templates')

        bp.route(self.auth_url,
                 methods=['POST'],
                 endpoint='authenticate')(views.authenticate)

        bp.route(self.logout_url,
                 endpoint='logout')(login_required(views.logout))

        self._setup_registerable(bp) if self.registerable else None
        self._setup_recoverable(bp) if self.recoverable else None
        self._setup_confirmable(bp) if self.confirmable else None

        app.register_blueprint(bp,
            url_prefix=utils.config_value(app, 'URL_PREFIX'))

        app.security = self

    def _setup_registerable(self, bp):
        bp.route(self.register_url,
                 methods=['POST'],
                 endpoint='register')(views.register)

    def _setup_recoverable(self, bp):
        bp.route(self.forgot_url,
                 methods=['POST'],
                 endpoint='forgot')(views.forgot)
        bp.route(self.reset_url,
                 methods=['POST'],
                 endpoint='reset')(views.reset)

    def _setup_confirmable(self, bp):
        bp.route(self.confirm_url,
                 endpoint='confirm')(views.confirm)


class AuthenticationProvider(object):
    """The default authentication provider implementation."""
    def _get_user(self, username_or_email):
        datastore = current_app.security.datastore

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

        if confirmation_token_is_expired(user):
            reset_confirmation_token(user)

        if requires_confirmation(user):
            raise exceptions.BadCredentialsError('Account requires confirmation')

        # compare passwords
        if current_app.security.pwd_context.verify(password, user.password):
            return user

        # bad match
        raise exceptions.BadCredentialsError("Password does not match")

    def auth_error(self, msg):
        """Sends an error log message and raises an authentication error.

        :param msg: An authentication error message"""
        current_app.logger.error(msg)
        raise exceptions.AuthenticationError(msg)
