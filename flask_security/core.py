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

from .utils import config_value as cv, get_config, md5, url_for_security
from .views import create_blueprint

# Convenient references
_security = LocalProxy(lambda: current_app.extensions['security'])


#: Default Flask-Security configuration
_default_config = {
    'BLUEPRINT_NAME': 'security',
    'URL_PREFIX': None,
    'FLASH_MESSAGES': True,
    'PASSWORD_HASH': 'plaintext',
    'PASSWORD_HMAC': False,
    'PASSWORD_HMAC_SALT': None,
    'LOGIN_URL': '/login',
    'LOGOUT_URL': '/logout',
    'REGISTER_URL': '/register',
    'RESET_URL': '/reset',
    'CONFIRM_URL': '/confirm',
    'POST_LOGIN_VIEW': '/',
    'POST_LOGOUT_VIEW': '/',
    'CONFIRM_ERROR_VIEW': None,
    'POST_REGISTER_VIEW': None,
    'POST_CONFIRM_VIEW': None,
    'POST_RESET_VIEW': None,
    'UNAUTHORIZED_VIEW': None,
    'CONFIRMABLE': False,
    'REGISTERABLE': False,
    'RECOVERABLE': False,
    'TRACKABLE': False,
    'PASSWORDLESS': False,
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
    'REMEMBER_SALT': 'remember-salt',
    'DEFAULT_HTTP_AUTH_REALM': 'Login Required'
}

#: Default Flask-Security messages
_default_messages = {
    'UNAUTHORIZED': ('You do not have permission to view this resource.', 'error'),
    'CONFIRM_REGISTRATION': ('Thank you. Confirmation instructions have been sent to %(email)s.', 'success'),
    'EMAIL_CONFIRMED': ('Thank you. Your email has been confirmed.', 'success'),
    'ALREADY_CONFIRMED': ('Your email has already been confirmed.', 'info'),
    'INVALID_CONFIRMATION_TOKEN': ('Invalid confirmation token.', 'error'),
    'ALREADY_CONFIRMED': ('This email has already been confirmed', 'info'),
    'PASSWORD_MISMATCH': ('Password does not match', 'error'),
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
    'PASSWORDLESS_LOGIN_SUCCESSFUL': ('You have successfuly logged in.', 'success'),
    'PASSWORD_RESET': ('You successfully reset your password and you have been logged in automatically.', 'success')
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
    lm.login_view = '%s.login' % cv('BLUEPRINT_NAME', app=app)
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


def _get_remember_token_serializer(app):
    return _get_serializer(app, app.config['SECURITY_REMEMBER_SALT'])


def _get_reset_serializer(app):
    return _get_serializer(app, app.config['SECURITY_RESET_SALT'])


def _get_confirm_serializer(app):
    return _get_serializer(app, app.config['SECURITY_CONFIRM_SALT'])


def _get_login_serializer(app):
    return _get_serializer(app, app.config['SECURITY_LOGIN_SALT'])


class RoleMixin(object):
    """Mixin for `Role` model definitions"""
    def __eq__(self, other):
        return self.name == other or self.name == getattr(other, 'name', None)

    def __ne__(self, other):
        return self.name != other and self.name != getattr(other, 'name', None)


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
        return role in self.roles


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
        self._send_mail_task = None

    def _add_ctx_processor(self, endpoint, fn):
        c = self.context_processors

        if endpoint not in c:
            c[endpoint] = []

        if fn not in c[endpoint]:
            c[endpoint].append(fn)

    def _run_ctx_processor(self, endpoint):
        rv, fns = {}, []

        for g in ['all', endpoint]:
            if g in self.context_processors:
                fns += self.context_processors[g]

        for fn in fns:
            rv.update(fn())

        return rv

    def context_processor(self, fn):
        self._add_ctx_processor('all', fn)

    def forgot_password_context_processor(self, fn):
        self._add_ctx_processor('forgot_password', fn)

    def login_context_processor(self, fn):
        self._add_ctx_processor('login', fn)

    def register_context_processor(self, fn):
        self._add_ctx_processor('register', fn)

    def reset_password_context_processor(self, fn):
        self._add_ctx_processor('reset_password', fn)

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

    def init_app(self, app, datastore=None, register_blueprint=True, **kwargs):
        """Initializes the Flask-Security extension for the specified
        application and datastore implentation.

        :param app: The application.
        :param datastore: An instance of a user datastore.
        """
        datastore = datastore or self.datastore

        for key, value in _default_config.items():
            app.config.setdefault('SECURITY_' + key, value)

        for key, value in _default_messages.items():
            app.config.setdefault('SECURITY_MSG_' + key, value)

        identity_loaded.connect_via(app)(_on_identity_loaded)

        if register_blueprint:
            name = cv('BLUEPRINT_NAME', app=app)
            url_prefix = cv('URL_PREFIX', app=app)
            bp = create_blueprint(app, name, __name__,
                                  url_prefix=url_prefix,
                                  template_folder='templates')
            app.register_blueprint(bp)

        state = self._get_state(app, datastore, **kwargs)

        app.extensions['security'] = state

        app.context_processor(lambda: dict(url_for_security=url_for_security,
                                           security=state))

        return state

    def _get_state(self, app, datastore, **kwargs):
        assert app is not None
        assert datastore is not None

        for key, value in get_config(app).items():
            kwargs[key.lower()] = value

        for key, value in [
                ('app', app),
                ('datastore', datastore),
                ('login_manager', _get_login_manager(app)),
                ('principal', _get_principal(app)),
                ('pwd_context', _get_pwd_context(app)),
                ('remember_token_serializer', _get_remember_token_serializer(app)),
                ('context_processors', {})]:
            kwargs[key] = value

        kwargs['login_serializer'] = (
            _get_login_serializer(app) if kwargs['passwordless'] else None)
        kwargs['reset_serializer'] = (
            _get_reset_serializer(app) if kwargs['recoverable'] else None)
        kwargs['confirm_serializer'] = (
            _get_confirm_serializer(app) if kwargs['confirmable'] else None)

        return _SecurityState(**kwargs)

    def __getattr__(self, name):
        return getattr(self._state, name, None)
