# -*- coding: utf-8 -*-
"""
    flask.ext.security
    ~~~~~~~~~~~~~~

    Flask-Security is a Flask extension module that aims to add quick and
    simple security via Flask-Login and Flask-Principal.

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""
from __future__ import absolute_import

import sys

from datetime import datetime

from flask import (current_app, Blueprint, flash, redirect, request, 
    session, _request_ctx_stack, url_for, abort, g)

from flask.ext.login import (AnonymousUser as AnonymousUserBase, UserMixin, 
    LoginManager, login_required, login_user, logout_user, 
    current_user, user_logged_in, user_logged_out)

from flask.ext.principal import (Identity, Principal, RoleNeed, UserNeed,
    Permission, AnonymousIdentity, identity_changed, identity_loaded)

from flask.ext.wtf import (Form, TextField, PasswordField, SubmitField, 
    HiddenField, Required, ValidationError, BooleanField, Email)

from functools import wraps
from passlib.context import CryptContext
from werkzeug.utils import import_string
from werkzeug.local import LocalProxy

User, Role = None, None

AUTH_CONFIG_KEY = 'AUTH'
URL_PREFIX_KEY = 'url_prefix'
USER_MODEL_ENGINE_KEY = 'user_model_engine'
AUTH_PROVIDER_KEY = 'auth_provider'
PASSWORD_HASH_KEY = 'password_hash'
USER_DATASTORE_NAME_KEY = 'user_datastore_name'
LOGIN_FORM_KEY = 'login_form'
AUTH_URL_KEY = 'auth_url'
LOGOUT_URL_KEY = 'logout_url'
LOGIN_VIEW_KEY = 'login_view'
POST_LOGIN_VIEW_KEY = 'post_login_view'
POST_LOGOUT_VIEW_KEY = 'post_logout_view'

default_config = {
    URL_PREFIX_KEY:            None,
    PASSWORD_HASH_KEY:         'plaintext',
    USER_DATASTORE_NAME_KEY:   'user_datastore',
    AUTH_PROVIDER_KEY:         'flask.ext.security.AuthenticationProvider',
    LOGIN_FORM_KEY:            'flask.ext.security.LoginForm',
    AUTH_URL_KEY:              '/auth',
    LOGOUT_URL_KEY:            '/logout',
    LOGIN_VIEW_KEY:            '/login',
    POST_LOGIN_VIEW_KEY:       '/',
    POST_LOGOUT_VIEW_KEY:      '/',
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
    
class UserIdNotFoundError(Exception):
    """Raised by a user datastore when there is an attempt to find a user by 
    ID and the user is not found.
    """
     
class UserDatastoreError(Exception):
    """Raise when a user datastore experiences an unexpected error
    """
    
class UserCreationError(Exception):
    """Raise when an error occurs during user create
    """
    
#: App logger for convenience
logger = LocalProxy(lambda: current_app.logger)

#: Authentication provider
auth_provider = LocalProxy(lambda: current_app.auth_provider)

#: Login manager
login_manager = LocalProxy(lambda: current_app.login_manager)

#: Password encyption context
pwd_context = LocalProxy(lambda: current_app.pwd_context)

# User service
user_datastore = LocalProxy(lambda: getattr(current_app, 
    current_app.config[AUTH_CONFIG_KEY][USER_DATASTORE_NAME_KEY]))

def roles_required(*args):
    roles = args
    perm = Permission(*[RoleNeed(role) for role in roles])
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if current_user.is_authenticated() and perm.can():
                return fn(*args, **kwargs)
            
            logger.debug('Identity does not provide all of the '
                         'following roles: %s' % [r for r in roles])
            
            c = current_app.config[AUTH_CONFIG_KEY]
            return redirect(c[LOGIN_VIEW_KEY])
        return decorated_view
    return wrapper

def roles_accepted(*args):
    roles = args
    perms = [Permission(RoleNeed(role)) for role in roles]
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            for perm in perms:
                if current_user.is_authenticated() and perm.can():
                    return fn(*args, **kwargs)
                
            logger.debug('Identity does not provide at least one of '
                         'the following roles: %s' % [r for r in roles])
            
            c = current_app.config[AUTH_CONFIG_KEY]
            return redirect(c[LOGIN_VIEW_KEY])
        return decorated_view
    return wrapper


class AnonymousUser(AnonymousUserBase):
    def __init__(self):
        super(AnonymousUser, self).__init__()
        self.roles = [] # TODO: Make this immutable
        
    def has_role(self, *args):
        return False

class Security(object):
    def __init__(self, app=None, datastore=None):
        self.init_app(app, datastore)
    
    def init_app(self, app, datastore):
        """Initialize the application
        
        :param app: An instance of an application
        :param datastore: An instance of a datastore for your users
        """
        if app is None or datastore is None: return
        
        blueprint = Blueprint(AUTH_CONFIG_KEY.lower(), __name__)
        
        config = default_config.copy()
        config.update(app.config.get(AUTH_CONFIG_KEY, {}))
        app.config[AUTH_CONFIG_KEY] = config
        
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
        
        setattr(app, config[USER_DATASTORE_NAME_KEY], datastore)
        
        @identity_loaded.connect_via(app)
        def on_identity_loaded(sender, identity):
            if hasattr(current_user, 'id'):
                identity.provides.add(UserNeed(current_user.id))
                
            for role in current_user.roles:
                identity.provides.add(RoleNeed(role.name))
            
            identity.user = current_user
        
        DEBUG_LOGIN = 'User %s logged in. Redirecting to: %s'
        ERROR_LOGIN = 'Unsuccessful authentication attempt: %s. ' \
                      'Redirecting to: %s'
        DEBUG_LOGOUT = 'User logged out, redirecting to: %s'
        FLASH_INACTIVE = 'Inactive user'
        
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
                flash(message, 'error')
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
            
            redirect_url = find_redirect(POST_LOGOUT_VIEW_KEY, config)
            logger.debug(DEBUG_LOGOUT % redirect_url)
            return redirect(redirect_url)
        
        app.register_blueprint(blueprint, url_prefix=config[URL_PREFIX_KEY])
        
"""
Here are some forms, useing the WTForm extension for Flask because, well, its 
nice to have a form library when building web apps
"""
class LoginForm(Form):
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
    
"""
Here we have the default authentication provider. It requires a user service in 
order to retrieve users and handle authentication.
"""
class AuthenticationProvider(object):
    def __init__(self, login_form_class=None):
        self.login_form_class = login_form_class or LoginForm
        
    def login_form(self, formdata=None):
        return self.login_form_class(formdata)
    
    def authenticate(self, form):
        # first some basic validation
        if not form.validate():
            if form.username.errors:
                raise BadCredentialsError(form.username.errors[0])
            if form.password.errors:
                raise BadCredentialsError(form.password.errors[0])
        
        return self.do_authenticate(form.username.data, form.password.data)
        
    def do_authenticate(self, user_identifier, password):
        try:
            user = user_datastore.find(user_identifier)
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
        logger.error(msg)
        raise AuthenticationError(msg)

def get_class_by_name(clazz):
    parts = clazz.split('.')
    module = ".".join(parts[:-1])
    m = __import__( module )
    for comp in parts[1:]:
        m = getattr(m, comp)            
    return m

def get_class_from_config(key, config):
    try:
        return get_class_by_name(config[key])
    except Exception, e:
        raise AttributeError(
            "Could not get class '%s' for Auth setting '%s' >> %s" %  
            (config[key], key, e)) 

def get_url(value):
    # try building the url or assume its a url already
    try: return url_for(value)
    except: return value
    
def get_post_login_redirect():
    return (get_url(request.args.get('next')) or 
            get_url(request.form.get('next')) or 
            find_redirect(POST_LOGIN_VIEW_KEY, 
                          current_app.config[AUTH_CONFIG_KEY]))
    
def find_redirect(key, config):
    # Look in the session first, and if not there go to the config, and
    # if its not there either just go to the root url
    result = (get_url(session.get(key.lower(), None)) or 
              get_url(config[key.lower()] or None) or '/')
    # Try and delete the session value if it was used
    try: del session[key.lower()]
    except: pass
    return result
