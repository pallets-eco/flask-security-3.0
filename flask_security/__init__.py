# -*- coding: utf-8 -*-
"""
    flask.ext.security
    ~~~~~~~~~~~~~~~~~~

    Flask-Security is a Flask extension that aims to add quick and simple 
    security via Flask-Login, Flask-Principal, Flask-WTF, and passlib.

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

import sys

from datetime import datetime
from types import StringType

from flask import (current_app, Blueprint, flash, redirect, request, 
    session, _request_ctx_stack, url_for, abort, g)

from flask.ext.login import (AnonymousUser as AnonymousUserBase, 
    UserMixin as BaseUserMixin, LoginManager, login_required, login_user, 
    logout_user, current_user, user_logged_in, user_logged_out)

from flask.ext.principal import (Identity, Principal, RoleNeed, UserNeed,
    Permission, AnonymousIdentity, identity_changed, identity_loaded)

from flask.ext.wtf import (Form, TextField, PasswordField, SubmitField, 
    HiddenField, Required, ValidationError, BooleanField, Email)

from functools import wraps
from passlib.context import CryptContext
from werkzeug.utils import import_string
from werkzeug.local import LocalProxy

class User(object):
    """User model"""

class Role(object):
    """Role model"""

URL_PREFIX_KEY =     'SECURITY_URL_PREFIX'
AUTH_PROVIDER_KEY =  'SECURITY_AUTH_PROVIDER'
PASSWORD_HASH_KEY =  'SECURITY_PASSWORD_HASH'
USER_DATASTORE_KEY = 'SECURITY_USER_DATASTORE'
LOGIN_FORM_KEY =     'SECURITY_LOGIN_FORM'
AUTH_URL_KEY =       'SECURITY_AUTH_URL'
LOGOUT_URL_KEY =     'SECURITY_LOGOUT_URL'
LOGIN_VIEW_KEY =     'SECURITY_LOGIN_VIEW'
POST_LOGIN_KEY =     'SECURITY_POST_LOGIN'
POST_LOGOUT_KEY =    'SECURITY_POST_LOGOUT'
FLASH_MESSAGES_KEY = 'SECURITY_FLASH_MESSAGES'

DEBUG_LOGIN = 'User %s logged in. Redirecting to: %s'
ERROR_LOGIN = 'Unsuccessful authentication attempt: %s. Redirecting to: %s'
DEBUG_LOGOUT = 'User logged out, redirecting to: %s'
FLASH_INACTIVE = 'Inactive user'
FLASH_PERMISSIONS = 'You do not have permission to view this resource.'

#: Default Flask-Security configuration
default_config = {
    URL_PREFIX_KEY:     None,
    FLASH_MESSAGES_KEY: True,
    PASSWORD_HASH_KEY:  'plaintext',
    USER_DATASTORE_KEY: 'user_datastore',
    AUTH_PROVIDER_KEY:  'flask.ext.security.AuthenticationProvider',
    LOGIN_FORM_KEY:     'flask.ext.security.LoginForm',
    AUTH_URL_KEY:       '/auth',
    LOGOUT_URL_KEY:     '/logout',
    LOGIN_VIEW_KEY:     '/login',
    POST_LOGIN_KEY:     '/',
    POST_LOGOUT_KEY:    '/',
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
    
         
#: App logger for convenience
logger = LocalProxy(lambda: current_app.logger)

#: Authentication provider
auth_provider = LocalProxy(lambda: current_app.auth_provider)

#: Login manager
login_manager = LocalProxy(lambda: current_app.login_manager)

#: Password encyption context
pwd_context = LocalProxy(lambda: current_app.pwd_context)

#: User datastore
user_datastore = LocalProxy(lambda: getattr(current_app, 
    current_app.config[USER_DATASTORE_KEY]))

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
                return redirect(current_app.config[LOGIN_VIEW_KEY])
            
            if perm.can():
                return fn(*args, **kwargs)
            
            logger.debug('Identity does not provide all of the '
                         'following roles: %s' % [r for r in roles])
            
            do_flash(FLASH_PERMISSIONS, 'error')
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
                return redirect(current_app.config[LOGIN_VIEW_KEY])
            
            for perm in perms:
                if perm.can():
                    return fn(*args, **kwargs)
                
            logger.debug('Identity does not provide at least one of '
                         'the following roles: %s' % [r for r in roles])
            
            do_flash(FLASH_PERMISSIONS, 'error')
            return redirect(request.referrer or '/')
        return decorated_view
    return wrapper


class RoleMixin(object):
    """Mixin for `Role` model definitions"""
    def __eq__(self, other):
        return self.name == other.name
    
    def __ne__(self, other):
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
        if not isinstance(role, Role):
            role = Role(name=role)
        return role in self.roles
    
    def __str__(self):
        ctx = (str(self.id), self.username, self.email)
        return '<User id=%s, username=%s, email=%s>' % ctx


class AnonymousUser(AnonymousUserBase):
    def __init__(self):
        super(AnonymousUser, self).__init__()
        self.roles = [] # TODO: Make this immutable?
        
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
        if app is None or datastore is None: return
        
        # TODO: change blueprint name
        blueprint = Blueprint('auth', __name__)
        
        configured = {}
        
        for key, value in default_config.items():
            configured[key] = app.config.get(key, value)
        
        app.config.update(configured)
        config = app.config
        
        # setup the login manager extension
        login_manager = LoginManager()
        login_manager.anonymous_user = AnonymousUser
        login_manager.login_view = config[LOGIN_VIEW_KEY]
        login_manager.setup_app(app)
        app.login_manager = login_manager
        
        Provider = get_class_from_config(AUTH_PROVIDER_KEY, config)
        Form = get_class_from_config(LOGIN_FORM_KEY, config)
        pw_hash = config[PASSWORD_HASH_KEY]
        
        app.pwd_context = CryptContext(schemes=[pw_hash], default=pw_hash)
        app.auth_provider = Provider(Form)
        app.principal = Principal(app)
        
        from flask.ext import security as s
        s.User, s.Role = datastore.get_models()
        
        setattr(app, config[USER_DATASTORE_KEY], datastore)
        
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
                return datastore.with_id(user_id)
            except Exception, e:
                logger.error('Error getting user: %s' % e) 
                return None
            
        auth_url = config[AUTH_URL_KEY]
        @blueprint.route(auth_url, methods=['POST'], endpoint='authenticate')
        def authenticate():
            try:
                form = Form()
                user = auth_provider.authenticate(form)
                
                if login_user(user, remember=form.remember.data):
                    redirect_url = get_post_login_redirect()
                    identity_changed.send(app, identity=Identity(user.id))
                    logger.debug(DEBUG_LOGIN % (user, redirect_url))
                    return redirect(redirect_url)

                raise BadCredentialsError(FLASH_INACTIVE)
                
            except BadCredentialsError, e:
                message = '%s' % e
                do_flash(message, 'error')
                redirect_url = request.referrer or login_manager.login_view
                logger.error(ERROR_LOGIN % (message, redirect_url))
                return redirect(redirect_url)
    
        @blueprint.route(config[LOGOUT_URL_KEY], endpoint='logout')
        @login_required
        def logout():
            for value in ('identity.name', 'identity.auth_type'):
                session.pop(value, None)
            
            identity_changed.send(app, identity=AnonymousIdentity())
            logout_user()
            
            redirect_url = find_redirect(POST_LOGOUT_KEY)
            logger.debug(DEBUG_LOGOUT % redirect_url)
            return redirect(redirect_url)
        
        app.register_blueprint(blueprint, url_prefix=config[URL_PREFIX_KEY])
        
        
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
            user = user_datastore.find_user(user_identifier)
        except AttributeError, e:
            self.auth_error("Could not find user service: %s" % e)
        except UserNotFoundError, e:
            raise BadCredentialsError("Specified user does not exist")
        except AttributeError, e:
            self.auth_error('Invalid user service: %s' % e)
        except Exception, e:
            self.auth_error('Unexpected authentication error: %s' % e)
        
        # compare passwords
        if pwd_context.verify(password, user.password):
            return user

        # bad match
        raise BadCredentialsError("Password does not match")
    
    def auth_error(self, msg):
        """Sends an error log message and raises an authentication error.
        
        :param msg: An authentication error message"""
        logger.error(msg)
        raise AuthenticationError(msg)

def do_flash(message, category):
    if current_app.config[FLASH_MESSAGES_KEY]:
        flash(message, category)


def get_class_by_name(clazz):
    """Get a reference to a class by its string representation."""
    parts = clazz.split('.')
    module = ".".join(parts[:-1])
    m = __import__( module )
    for comp in parts[1:]:
        m = getattr(m, comp)            
    return m

def get_class_from_config(key, config):
    """Get a reference to a class by its configuration key name."""
    try:
        return get_class_by_name(config[key])
    except Exception, e:
        raise AttributeError(
            "Could not get class '%s' for Auth setting '%s' >> %s" %  
            (config[key], key, e)) 

def get_url(endpoint_or_url):
    """Returns a URL if a valid endpoint is found. Otherwise, returns the 
    provided value."""
    try: 
        return url_for(endpoint_or_url)
    except: 
        return endpoint_or_url

def get_post_login_redirect():
    """Returns the URL to redirect to after a user logs in successfully"""
    return (get_url(request.args.get('next')) or 
            get_url(request.form.get('next')) or 
            find_redirect(POST_LOGIN_KEY))

def find_redirect(key):
    """Returns the URL to redirect to after a user logs in successfully"""
    result = (get_url(session.pop(key.lower(), None)) or 
              get_url(current_app.config[key.upper()] or None) or '/')
    
    try: 
        del session[key.lower()]
    except: 
        pass
    return result
