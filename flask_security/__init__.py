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

from flask import current_app, Blueprint, redirect, request
from flask.ext.login import AnonymousUser as AnonymousUserBase, \
     UserMixin as BaseUserMixin, LoginManager, login_required, \
     current_user, login_url
from flask.ext.principal import Principal, RoleNeed, UserNeed, \
     Permission, identity_loaded
from flask.ext.wtf import Form, TextField, PasswordField, SubmitField, \
     HiddenField, Required, BooleanField
from flask.ext.security import views, exceptions, utils
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
    'SECURITY_RESET_URL': '/reset',
    'SECURITY_LOGIN_VIEW': '/login',
    'SECURITY_POST_LOGIN_VIEW': '/',
    'SECURITY_POST_LOGOUT_VIEW': '/',
    'SECURITY_RESET_PASSWORD_WITHIN': 10
}


def roles_required(*roles):
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


def roles_accepted(*roles):
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

            current_app.logger.debug('Current user does not provide a required '
                'role. Accepted: %s Provided: %s' % ([r for r in roles],
                                                     [r.name for r in current_user.roles]))

            utils.do_flash('You do not have permission to view this resource',
                      'error')
            return redirect(request.referrer or '/')
        return decorated_view
    return wrapper


class RoleMixin(object):
    """Mixin for `Role` model definitions"""
    def __eq__(self, other):
        if isinstance(other, basestring):
            return self.name == other
        return self.name == other.name

    def __ne__(self, other):
        if isinstance(other, basestring):
            return self.name != other
        return self.name != other.name

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


def load_user(user_id):
    try:
        return current_app.security.datastore.with_id(user_id)
    except Exception, e:
        current_app.logger.error('Error getting user: %s' % e)
        return None


def on_identity_loaded(sender, identity):
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
    def __init__(self, app=None, datastore=None):
        self.init_app(app, datastore)

    def init_app(self, app, datastore, recoverable=False):
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
        login_manager.login_view = utils.config_value(app, 'LOGIN_VIEW')
        login_manager.setup_app(app)

        Provider = utils.get_class_from_string(app, 'AUTH_PROVIDER')
        Form = utils.get_class_from_string(app, 'LOGIN_FORM')
        pw_hash = utils.config_value(app, 'PASSWORD_HASH')

        self.login_manager = login_manager
        self.pwd_context = CryptContext(schemes=[pw_hash], default=pw_hash)
        self.auth_provider = Provider(Form)
        self.principal = Principal(app)
        self.datastore = datastore
        self.form_class = Form
        self.auth_url = utils.config_value(app, 'AUTH_URL')
        self.logout_url = utils.config_value(app, 'LOGOUT_URL')
        self.reset_url = utils.config_value(app, 'RESET_URL')
        self.post_login_view = utils.config_value(app, 'POST_LOGIN_VIEW')
        self.post_logout_view = utils.config_value(app, 'POST_LOGOUT_VIEW')
        self.reset_password_within = utils.config_value(app, 'RESET_PASSWORD_WITHIN')

        identity_loaded.connect_via(app)(on_identity_loaded)

        login_manager.user_loader(load_user)

        bp = Blueprint('auth', __name__)

        bp.route(self.auth_url,
                 methods=['POST'],
                 endpoint='authenticate')(views.authenticate)

        bp.route(self.logout_url,
                 endpoint='logout')(login_required(views.logout))

        if recoverable:
            bp.route(self.reset_url,
                     methods=['POST'],
                     endpoint='reset')(views.reset)

        app.register_blueprint(bp,
            url_prefix=utils.config_value(app, 'URL_PREFIX'))
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
                raise exceptions.BadCredentialsError(form.username.errors[0])
            if form.password.errors:
                raise exceptions.BadCredentialsError(form.password.errors[0])

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
            self.auth_error("Could not find user datastore: %s" % e)
        except exceptions.UserNotFoundError, e:
            raise exceptions.BadCredentialsError("Specified user does not exist")
        except Exception, e:
            self.auth_error('Unexpected authentication error: %s' % e)

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
