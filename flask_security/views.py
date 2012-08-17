# -*- coding: utf-8 -*-
"""
    flask.ext.security.views
    ~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security views module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from flask import current_app as app, redirect, request, \
     render_template, jsonify, after_this_request, Blueprint
from werkzeug.datastructures import MultiDict
from werkzeug.local import LocalProxy

from flask_security.confirmable import confirm_by_token, \
     send_confirmation_instructions
from flask_security.decorators import login_required
from flask_security.exceptions import ConfirmationError, BadCredentialsError, \
     ResetPasswordError, PasswordlessLoginError
from flask_security.forms import LoginForm, RegisterForm, ForgotPasswordForm, \
     ResetPasswordForm, SendConfirmationForm, PasswordlessLoginForm
from flask_security.passwordless import send_login_instructions, login_by_token
from flask_security.recoverable import reset_by_token, \
     send_reset_password_instructions
from flask_security.signals import user_registered
from flask_security.utils import get_url, get_post_login_redirect, do_flash, \
     get_message, config_value, login_user, logout_user, \
     anonymous_user_required, url_for_security as url_for


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


def _commit(response=None):
    _datastore._commit()
    return response


def _ctx(endpoint):
    return _security._run_ctx_processor(endpoint)


def authenticate():
    """View function which handles an authentication request."""

    form = LoginForm(request.form)
    user, msg, confirm_url = None, None, None

    if request.json:
        form = LoginForm(MultiDict(request.json))

    try:
        user = _security.auth_provider.authenticate(form)
    except ConfirmationError, e:
        msg = str(e)
        confirm_url = url_for('send_confirmation', email=e.user.email)
    except BadCredentialsError, e:
        msg = str(e)

    if user:
        if login_user(user, remember=form.remember.data):
            after_this_request(_commit)
            if request.json:
                return _json_auth_ok(user)
            return redirect(get_post_login_redirect())
        msg = get_message('DISABLED_ACCOUNT')[0]

    _logger.debug('Unsuccessful authentication attempt: %s' % msg)

    if request.json:
        return _json_auth_error(msg)

    do_flash(msg, 'error')
    return redirect(confirm_url or url_for('login'))


@anonymous_user_required
def login():
    """View function for login view"""

    tmp, form = '', LoginForm

    if _security.passwordless:
        tmp, form = 'send_', PasswordlessLoginForm

    return render_template('security/%slogin.html' % tmp,
                           login_form=form(),
                           **_ctx('login'))


@login_required
def logout():
    """View function which handles a logout request."""

    logout_user()
    _logger.debug('User logged out')
    next_url = request.args.get('next', None)
    post_logout_url = get_url(_security.post_logout_view)
    return redirect(next_url or post_logout_url)


@anonymous_user_required
def register():
    """View function which handles a registration request."""

    form = RegisterForm(csrf_enabled=not app.testing)

    if not form.validate_on_submit():
        return render_template('security/register.html',
                               register_user_form=form,
                               **_ctx('register'))

    token = None
    user = _datastore.create_user(**form.to_dict())
    _commit()

    if _security.confirmable:
        token = send_confirmation_instructions(user)
        do_flash(*get_message('CONFIRM_REGISTRATION', email=user.email))

    user_registered.send(dict(user=user, confirm_token=token),
                         app=app._get_current_object())

    _logger.debug('User %s registered' % user)

    if not _security.confirmable or _security.login_without_confirmation:
        after_this_request(_commit)
        login_user(user)

    post_register_url = get_url(_security.post_register_view)
    post_login_url = get_url(_security.post_login_view)

    return redirect(post_register_url or post_login_url)


@anonymous_user_required
def send_login():
    """View function that sends login instructions for passwordless login"""

    form = PasswordlessLoginForm()
    user = _datastore.find_user(**form.to_dict())

    if user.is_active():
        send_login_instructions(user, form.next.data)
        msg = get_message('LOGIN_EMAIL_SENT', email=user.email)
    else:
        msg = get_message('DISABLED_ACCOUNT')

    do_flash(*msg)
    return render_template('security/send_login.html',
                           login_form=form,
                           **_ctx('send_login'))


@anonymous_user_required
def token_login(token):
    """View function that handles passwordless login via a token"""

    try:
        user, next = login_by_token(token)
    except PasswordlessLoginError, e:
        if e.user:
            send_login_instructions(e.user, e.next)
        do_flash(str(e), 'error')
        return redirect(request.referrer or url_for('login'))

    do_flash(*get_message('PASSWORDLESS_LOGIN_SUCCESSFUL'))
    return redirect(next)


@anonymous_user_required
def send_confirmation():
    """View function which sends confirmation instructions."""

    form = SendConfirmationForm(csrf_enabled=not app.testing)

    if form.validate_on_submit():
        user = _datastore.find_user(**form.to_dict())
        send_confirmation_instructions(user)
        _logger.debug('%s request confirmation instructions' % user)
        do_flash(*get_message('CONFIRMATION_REQUEST', email=user.email))

    return render_template('security/send_confirmation.html',
                           reset_confirmation_form=form,
                           **_ctx('send_confirmation'))


def confirm_email(token):
    """View function which handles a email confirmation request."""
    after_this_request(_commit)

    try:
        user = confirm_by_token(token)
    except ConfirmationError, e:
        _logger.debug('Confirmation error: %s' % e)
        if e.user:
            send_confirmation_instructions(e.user)
        do_flash(str(e), 'error')
        confirm_error_url = get_url(_security.confirm_error_view)
        return redirect(confirm_error_url or url_for('send_confirmation'))

    _logger.debug('%s confirmed their email' % user)
    do_flash(*get_message('EMAIL_CONFIRMED'))
    login_user(user, True)
    post_confirm_url = get_url(_security.post_confirm_view)
    post_login_url = get_url(_security.post_login_view)
    return redirect(post_confirm_url or post_login_url)


@anonymous_user_required
def forgot_password():
    """View function that handles a forgotten password request."""

    form = ForgotPasswordForm(csrf_enabled=not app.testing)

    if form.validate_on_submit():
        user = _datastore.find_user(**form.to_dict())
        send_reset_password_instructions(user)
        _logger.debug('%s requested to reset their password' % user)
        do_flash(*get_message('PASSWORD_RESET_REQUEST', email=user.email))

        if _security.post_forgot_view:
            return redirect(get_url(_security.post_forgot_view))
    else:
        for key, value in form.errors.items():
            do_flash(value[0], 'error')

    return render_template('security/forgot_password.html',
                           forgot_password_form=form,
                           **_ctx('forgot_password'))


@anonymous_user_required
def reset_password(token):
    """View function that handles a reset password request."""

    next, msg = None, None
    form = ResetPasswordForm(csrf_enabled=not app.testing)

    if form.validate_on_submit():
        try:
            user = reset_by_token(token=token, **form.to_dict())
            msg = get_message('PASSWORD_RESET')
            next = (get_url(_security.post_reset_view) or
                    get_url(_security.post_login_view))
        except ResetPasswordError, e:
            msg = (str(e), 'error')
            if e.user:
                send_reset_password_instructions(e.user)
                msg = get_message('PASSWORD_RESET_EXPIRED',
                                  within=_security.reset_password_within,
                                  email=e.user.email)
            _logger.debug('Password reset error: ' + msg[0])

    do_flash(*msg)

    if next:
        login_user(user)
        _logger.debug('%s reset their password' % user)
        return redirect(next)

    return render_template('security/reset_password.html',
                           reset_password_form=form,
                           reset_password_token=token,
                           **_ctx('reset_password'))


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
