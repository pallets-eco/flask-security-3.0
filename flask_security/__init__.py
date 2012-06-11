# -*- coding: utf-8 -*-
"""
    flask.ext.security
    ~~~~~~~~~~~~~~~~~~

    Flask-Security is a Flask extension that aims to add quick and simple
    security via Flask-Login, Flask-Principal, Flask-WTF, and passlib.

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from functools import wraps
from importlib import import_module

from flask import current_app, Blueprint, flash, redirect, request, \
    session, url_for
from flask.ext.login import AnonymousUser as AnonymousUserBase, \
    UserMixin as BaseUserMixin, LoginManager, login_required, login_user, \
    logout_user, current_user, login_url
from flask.ext.principal import Identity, Principal, RoleNeed, UserNeed, \
    Permission, AnonymousIdentity, identity_changed, identity_loaded
from flask.ext.wtf import Form, TextField, PasswordField, SubmitField, \
    HiddenField, Required, BooleanField
from passlib.context import CryptContext
from werkzeug.datastructures import ImmutableList


#: Default Flask-Security configuration
_default_config = {
    'SECURITY_URL_PREFIX': None,
    'SECURITY_FLASH_MESSAGES': True,
    'SECURITY_PASSWORD_HASH': 'plaintext',
    'SECURITY_USER_DATASTORE': 'user_datastore',
    'SECURITY_AUTH_PROVIDER': 'flask.ext.security::AuthenticationProvider',
    'SECURITY_LOGIN_FORM': 'flask.ext.security::LoginForm',
    'SECURITY_AUTH_URL': '/auth',
    'SECURITY_LOGOUT_URL': '/logout',
    'SECURITY_LOGIN_VIEW': '/login',
    'SECURITY_POST_LOGIN_VIEW': '/',
    'SECURITY_POST_LOGOUT_VIEW': '/',
}


class BadCredentialsError(Exception):
    """Raised when an authentication attempt fails due to an error with the
    provided credentials.
    """


class AuthenticationError(Exception):
    """Raised when an authentication attempt fails due to invalid configuration
    or an unknown reason.
    """


class UserNotFoundError(Exception):
    """Raised by a user datastore when there is an attempt to find a user by
    their identifier, often username or email, and the user is not found.
    """


class RoleNotFoundError(Exception):
    """Raised by a user datastore when there is an attempt to find a role and
    the role cannot be found.
    """


class UserIdNotFoundError(Exception):
    """Raised by a user datastore when there is an attempt to find a user by
    ID and the user is not found.
    """


class UserDatastoreError(Exception):
    """Raised when a user datastore experiences an unexpected error
    """


class UserCreationError(Exception):
    """Raised when an error occurs when creating a user
    """


class RoleCreationError(Exception):
    """Raised when an error occurs when creating a role
    """


def roles_required(*args):
    """View decorator which specifies that a user must have all the specified
    roles. Example::

        @app.route('/dashboard')
        @roles_required('admin', 'editor')
        def dashboard():
            return 'Dashboard'

    The current user must have both the `admin` role and `editor` role in order
    to view the page.

    :param args: The required roles.
    """
    roles = args
    perm = Permission(*[RoleNeed(role) for role in roles])

    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated():
                login_view = current_app.security.login_manager.login_view
                return redirect(login_url(login_view, request.url))

            if perm.can():
                return fn(*args, **kwargs)

            current_app.logger.debug('Identity does not provide the '
                                     'roles: %s' % [r for r in roles])
            return redirect(request.referrer or '/')
        return decorated_view
    return wrapper


def roles_accepted(*args):
    """View decorator which specifies that a user must have at least one of the
    specified roles. Example::

        @app.route('/create_post')
        @roles_accepted('editor', 'author')
        def create_post():
            return 'Create Post'

    The current user must have either the `editor` role or `author` role in
    order to view the page.

    :param args: The possible roles.
    """
    roles = args
    perms = [Permission(RoleNeed(role)) for role in roles]

    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated():
                login_view = current_app.security.login_manager.login_view
                return redirect(login_url(login_view, request.url))

            for perm in perms:
                if perm.can():
                    return fn(*args, **kwargs)

            current_app.logger.debug('Identity does not provide at least one '
                                     'role: %s' % [r for r in roles])

            _do_flash('You do not have permission to view this resource',
                      'error')
            return redirect(request.referrer or '/')
        return decorated_view
    return wrapper


class RoleMixin(object):
    """Mixin for `Role` model definitions"""
    def __eq__(self, other):
        if isinstance(other, basestring):
            return self.name == other
        return self.name == getattr(other, 'name', None)

    def __ne__(self, other):
        if isinstance(other, basestring):
            return self.name != other
        return self.name != getattr(other, 'name', None)

    def __str__(self):
        return '<Role name=%s, description=%s>' % (self.name, self.description)


class UserMixin(BaseUserMixin):
    """Mixin for `User` model definitions"""

    def is_active(self):
        """Returns `True` if the user is active."""
        return self.active

    def has_role(self, role):
        """Returns `True` if the user identifies with the specified role.

        :param role: A role name or `Role` instance"""
        return role in self.roles

    def __str__(self):
        ctx = (str(self.id), self.username, self.email)
        return '<User id=%s, username=%s, email=%s>' % ctx


class AnonymousUser(AnonymousUserBase):
    def __init__(self):
        super(AnonymousUser, self).__init__()
        self.roles = ImmutableList()

    def has_role(self, *args):
        """Returns `False`"""
        return False


class Security(object):
    """The :class:`Security` class initializes the Flask-Security extension.

    :param app: The application.
    :param datastore: An instance of a user datastore.
    """
    def __init__(self, app=None, datastore=None):
        self.init_app(app, datastore)

    def init_app(self, app, datastore):
        """Initializes the Flask-Security extension for the specified
        application and datastore implentation.

        :param app: The application.
        :param datastore: An instance of a user datastore.
        """
        if app is None or datastore is None:
            return

        for key, value in _default_config.items():
            app.config.setdefault(key, value)

        login_manager = LoginManager()
        login_manager.anonymous_user = AnonymousUser
        login_manager.login_view = _config_value(app, 'LOGIN_VIEW')
        login_manager.setup_app(app)

        Provider = _get_class_from_string(app, 'AUTH_PROVIDER')
        Form = _get_class_from_string(app, 'LOGIN_FORM')
        pw_hash = _config_value(app, 'PASSWORD_HASH')

        self.login_manager = login_manager
        self.pwd_context = CryptContext(schemes=[pw_hash], default=pw_hash)
        self.auth_provider = Provider(Form)
        self.principal = Principal(app)
        self.datastore = datastore
        self.auth_url = _config_value(app, 'AUTH_URL')
        self.logout_url = _config_value(app, 'LOGOUT_URL')
        self.post_login_view = _config_value(app, 'POST_LOGIN_VIEW')
        self.post_logout_view = _config_value(app, 'POST_LOGOUT_VIEW')

        @identity_loaded.connect_via(app)
        def on_identity_loaded(sender, identity):
            if hasattr(current_user, 'id'):
                identity.provides.add(UserNeed(current_user.id))

            for role in current_user.roles:
                identity.provides.add(RoleNeed(role.name))

            identity.user = current_user

        @login_manager.user_loader
        def load_user(user_id):
            try:
                return app.security.datastore.with_id(user_id)
            except Exception, e:
                app.logger.error('Error getting user: %s' % e)
                return None

        bp = Blueprint('auth', __name__)

        @bp.route(self.auth_url, methods=['POST'], endpoint='authenticate')
        def authenticate():
            try:
                form = Form()
                user = current_app.security.auth_provider.authenticate(form)

                if login_user(user, remember=form.remember.data):
                    redirect_url = _get_post_login_redirect()
                    identity_changed.send(app, identity=Identity(user.id))
                    app.logger.debug('User %s logged in. Redirecting to: '
                                     '%s' % (user, redirect_url))
                    return redirect(redirect_url)

                raise BadCredentialsError('Inactive user')

            except BadCredentialsError, e:
                message = '%s' % e
                _do_flash(message, 'error')
                redirect_url = request.referrer or login_manager.login_view
                app.logger.error('Unsuccessful authentication attempt: %s. '
                                 'Redirect to: %s' % (message, redirect_url))
                return redirect(redirect_url)

        @bp.route(self.logout_url, endpoint='logout')
        @login_required
        def logout():
            for value in ('identity.name', 'identity.auth_type'):
                session.pop(value, None)

            identity_changed.send(app, identity=AnonymousIdentity())
            logout_user()

            redirect_url = _find_redirect('SECURITY_POST_LOGOUT_VIEW')
            app.logger.debug('User logged out. Redirect to: %s' % redirect_url)
            return redirect(redirect_url)

        app.register_blueprint(bp, url_prefix=_config_value(app, 'URL_PREFIX'))
        app.security = self


class LoginForm(Form):
    """The default login form"""

    username = TextField("Username or Email",
        validators=[Required(message="Username not provided")])
    password = PasswordField("Password",
        validators=[Required(message="Password not provided")])
    remember = BooleanField("Remember Me")
    next = HiddenField()
    submit = SubmitField("Login")

    def __init__(self, *args, **kwargs):
        super(LoginForm, self).__init__(*args, **kwargs)
        self.next.data = request.args.get('next', None)


class AuthenticationProvider(object):
    """The default authentication provider implementation.

    :param login_form_class: The login form class to use when authenticating a
                             user
    """

    def __init__(self, login_form_class=None):
        self.login_form_class = login_form_class or LoginForm

    def login_form(self, formdata=None):
        """Returns an instance of the login form with the provided form.

        :param formdata: The incoming form data"""
        return self.login_form_class(formdata)

    def authenticate(self, form):
        """Processes an authentication request and returns a user instance if
        authentication is successful.

        :param form: An instance of a populated login form
        """
        if not form.validate():
            if form.username.errors:
                raise BadCredentialsError(form.username.errors[0])
            if form.password.errors:
                raise BadCredentialsError(form.password.errors[0])

        return self.do_authenticate(form.username.data, form.password.data)

    def do_authenticate(self, user_identifier, password):
        """Returns the authenticated user if authentication is successfull. If
        authentication fails an appropriate error is raised

        :param user_identifier: The user's identifier, either an email address
                                or username
        :param password: The user's unencrypted password
        """
        try:
            user = current_app.security.datastore.find_user(user_identifier)
        except AttributeError, e:
            self.auth_error("Could not find user service: %s" % e)
        except UserNotFoundError, e:
            raise BadCredentialsError("Specified user does not exist")
        except AttributeError, e:
            self.auth_error('Invalid user service: %s' % e)
        except Exception, e:
            self.auth_error('Unexpected authentication error: %s' % e)

        # compare passwords
        if current_app.security.pwd_context.verify(password, user.password):
            return user

        # bad match
        raise BadCredentialsError("Password does not match")

    def auth_error(self, msg):
        """Sends an error log message and raises an authentication error.

        :param msg: An authentication error message"""
        current_app.logger.error(msg)
        raise AuthenticationError(msg)


def _do_flash(message, category):
    if _config_value(current_app, 'FLASH_MESSAGES'):
        flash(message, category)


def _get_class_from_string(app, key):
    """Get a reference to a class by its configuration key name."""
    cv = _config_value(app, key).split('::')
    cm = import_module(cv[0])
    return getattr(cm, cv[1])


def get_url(endpoint_or_url):
    """Returns a URL if a valid endpoint is found. Otherwise, returns the
    provided value."""
    try:
        return url_for(endpoint_or_url)
    except:
        return endpoint_or_url


def _get_post_login_redirect():
    """Returns the URL to redirect to after a user logs in successfully"""
    return (get_url(request.args.get('next')) or
            get_url(request.form.get('next')) or
            _find_redirect('SECURITY_POST_LOGIN_VIEW'))


def _find_redirect(key):
    """Returns the URL to redirect to after a user logs in successfully"""
    result = (get_url(session.pop(key.lower(), None)) or
              get_url(current_app.config[key.upper()] or None) or '/')

    try:
        del session[key.lower()]
    except:
        pass
    return result


def _config_value(app, key):
    return app.config['SECURITY_' + key.upper()]
