# -*- coding: utf-8 -*-
"""
    flask.ext.security.views
    ~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security views module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from flask import current_app as app, redirect, request, \
     render_template, jsonify, Blueprint
from werkzeug.datastructures import MultiDict
from werkzeug.local import LocalProxy

from flask_security.confirmable import confirm_by_token, reset_confirmation_token
from flask_security.core import current_user
from flask_security.decorators import login_required
from flask_security.exceptions import ConfirmationError, BadCredentialsError, \
     ResetPasswordError, PasswordlessLoginError
from flask_security.forms import LoginForm, RegisterForm, ForgotPasswordForm, \
     ResetPasswordForm, ResendConfirmationForm, PasswordlessLoginForm
from flask_security.passwordless import send_login_instructions, login_by_token
from flask_security.recoverable import reset_by_token, \
     reset_password_reset_token
from flask_security.signals import user_registered
from flask_security.utils import get_url, get_post_login_redirect, do_flash, \
     get_message, config_value, login_user, logout_user, url_for_security, \
     anonymous_user_required


# Convenient references
_security = LocalProxy(lambda: app.extensions['security'])

_datastore = LocalProxy(lambda: _security.datastore)

_logger = LocalProxy(lambda: app.logger)


def _json_auth_ok(user):
    return jsonify({
        "meta": {
            "code": 200
        },
        "response": {
            "user": {
                "id": str(user.id),
                "authentication_token": user.get_auth_token()
            }
        }
    })


def _json_auth_error(msg):
    resp = jsonify({
        "meta": {
            "code": 400
        },
        "response": {
            "error": msg
        }
    })
    resp.status_code = 400
    return resp


def authenticate():
    """View function which handles an authentication request."""
    confirm_url = None
    form_data = MultiDict(request.json) if request.json else request.form
    form = LoginForm(form_data)

    try:
        user = _security.auth_provider.authenticate(form)

        if login_user(user, remember=form.remember.data):
            if request.json:
                return _json_auth_ok(user)

            return redirect(get_post_login_redirect())

        raise BadCredentialsError(get_message('DISABLED_ACCOUNT')[0])

    except ConfirmationError, e:
        msg = str(e)
        confirm_url = url_for_security('send_confirmation')

    except BadCredentialsError, e:
        msg = str(e)

    _logger.debug('Unsuccessful authentication attempt: %s' % msg)

    if request.json:
        return _json_auth_error(msg)

    do_flash(msg, 'error')

    return redirect(request.referrer or
                    confirm_url or
                    url_for_security('login'))


@anonymous_user_required
def login():
    """View function for login view"""

    form = PasswordlessLoginForm() if _security.passwordless else LoginForm()
    template = 'send_login' if _security.passwordless else 'login'
    return render_template('security/%s.html' % template, login_form=form)


@login_required
def logout():
    """View function which handles a logout request."""

    logout_user()

    _logger.debug('User logged out')

    return redirect(request.args.get('next', None) or
                    get_url(_security.post_logout_view))


@anonymous_user_required
def register():
    """View function which handles a registration request."""

    form = RegisterForm(csrf_enabled=not app.testing)

    if form.validate_on_submit():
        # Create user
        u = _datastore.create_user(**form.to_dict())

        # Send confirmation instructions if necessary
        t = reset_confirmation_token(u) if _security.confirmable else None

        data = dict(user=u, confirm_token=t)
        user_registered.send(data, app=app._get_current_object())

        _logger.debug('User %s registered' % u)

        # Login the user if allowed
        if not _security.confirmable or _security.login_without_confirmation:
            login_user(u)

        return redirect(get_url(_security.post_register_view) or
                        get_url(_security.post_login_view))

    return render_template('security/register.html',
                           register_user_form=form)


@anonymous_user_required
def send_login():
    """View function that sends login instructions for passwordless login"""
    form = PasswordlessLoginForm()

    user = _datastore.find_user(**form.to_dict())

    if user.is_active():
        send_login_instructions(user, form.next.data)
        do_flash(*get_message('LOGIN_EMAIL_SENT', email=user.email))
    else:
        do_flash(*get_message('DISABLED_ACCOUNT'))

    return render_template('security/send_login.html', login_form=form)


@anonymous_user_required
def token_login(token):
    """View function that handles passwordless login via a token"""

    try:
        user, next = login_by_token(token)

    except PasswordlessLoginError, e:
        if e.user:
            send_login_instructions(e.user, e.next)

        do_flash(str(e), 'error')

        return redirect(request.referrer or url_for_security('login'))

    do_flash(*get_message('PASSWORDLESS_LOGIN_SUCCESSFUL'))

    return redirect(next or get_url(_security.post_login_view))


@anonymous_user_required
def send_confirmation():
    """View function which sends confirmation instructions."""

    form = ResendConfirmationForm(csrf_enabled=not app.testing)

    if form.validate_on_submit():
        user = _datastore.find_user(**form.to_dict())

        reset_confirmation_token(user)

        _logger.debug('%s request confirmation instructions' % user)

        do_flash(*get_message('CONFIRMATION_REQUEST', email=user.email))

    return render_template('security/send_confirmation.html',
                           reset_confirmation_form=form)


def confirm_email(token):
    """View function which handles a email confirmation request."""

    try:
        user = confirm_by_token(token)
        _logger.debug('%s confirmed their email' % user)

    except ConfirmationError, e:
        msg = (str(e), 'error')

        _logger.debug('Confirmation error: ' + msg[0])

        if e.user:
            reset_confirmation_token(e.user)

        do_flash(*msg)

        return redirect(get_url(_security.confirm_error_view) or
                        url_for_security('send_confirmation'))

    do_flash(*get_message('EMAIL_CONFIRMED'))

    login_user(user, True)

    return redirect(get_url(_security.post_confirm_view) or
                    get_url(_security.post_login_view))


@anonymous_user_required
def forgot_password():
    """View function that handles a forgotten password request."""

    form = ForgotPasswordForm(csrf_enabled=not app.testing)

    if form.validate_on_submit():
        user = _datastore.find_user(**form.to_dict())

        reset_password_reset_token(user)

        _logger.debug('%s requested to reset their password' % user)

        do_flash(*get_message('PASSWORD_RESET_REQUEST', email=user.email))

        return redirect(get_url(_security.post_forgot_view))

    else:
        for key, value in form.errors.items():
            do_flash(value[0], 'error')

    return render_template('security/forgot_password.html',
                           forgot_password_form=form)


@anonymous_user_required
def reset_password(token):
    """View function that handles a reset password request."""

    form = ResetPasswordForm(csrf_enabled=not app.testing)

    if form.validate_on_submit():
        try:
            user = reset_by_token(token=token, **form.to_dict())

            _logger.debug('%s reset their password' % user)

            do_flash(*get_message('PASSWORD_RESET'))

            login_user(user)

            return redirect(get_url(_security.post_reset_view) or
                            get_url(_security.post_login_view))

        except ResetPasswordError, e:
            msg = (str(e), 'error')

            _logger.debug('Password reset error: ' + msg[0])

            if e.user:
                reset_password_reset_token(e.user)

                msg = get_message('PASSWORD_RESET_EXPIRED',
                                  within=_security.reset_password_within,
                                  email=e.user.email)

            do_flash(*msg)

    return render_template('security/reset_password.html',
                           reset_password_form=form,
                           password_reset_token=token)


def create_blueprint(app, name, import_name, **kwargs):
    """Creates the security extension blueprint"""

    bp = Blueprint(name, import_name, **kwargs)

    if config_value('PASSWORDLESS', app=app):
        bp.route(config_value('AUTH_URL', app=app),
                 methods=['POST'],
                 endpoint='send_login')(send_login)

        bp.route(config_value('AUTH_URL', app=app) + '/<token>',
                 methods=['GET'],
                 endpoint='token_login')(token_login)
    else:
        bp.route(config_value('AUTH_URL', app=app),
                 methods=['POST'],
                 endpoint='authenticate')(authenticate)

    bp.route(config_value('LOGIN_URL', app=app),
             endpoint='login')(login)

    bp.route(config_value('LOGOUT_URL', app=app),
             endpoint='logout')(logout)

    if config_value('REGISTERABLE', app=app):
        bp.route(config_value('REGISTER_URL', app=app),
                 methods=['GET', 'POST'],
                 endpoint='register')(register)

    if config_value('RECOVERABLE', app=app):
        bp.route(config_value('RESET_URL', app=app),
                 methods=['GET', 'POST'],
                 endpoint='forgot_password')(forgot_password)
        bp.route(config_value('RESET_URL', app=app) + '/<token>',
                 methods=['GET', 'POST'],
                 endpoint='reset_password')(reset_password)

    if config_value('CONFIRMABLE', app=app):
        bp.route(config_value('CONFIRM_URL', app=app),
                 methods=['GET', 'POST'],
                 endpoint='send_confirmation')(send_confirmation)
        bp.route(config_value('CONFIRM_URL', app=app) + '/<token>',
                 methods=['GET', 'POST'],
                 endpoint='confirm_email')(confirm_email)

    return bp
