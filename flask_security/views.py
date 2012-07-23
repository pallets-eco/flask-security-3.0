# -*- coding: utf-8 -*-
"""
    flask.ext.security.views
    ~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security views module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from flask import current_app as app, redirect, request, session, \
     render_template, jsonify, Blueprint
from flask.ext.principal import AnonymousIdentity, identity_changed
from werkzeug.datastructures import MultiDict
from werkzeug.local import LocalProxy

from flask_security.confirmable import confirm_by_token, reset_confirmation_token
from flask_security.decorators import login_required
from flask_security.exceptions import ConfirmationError, BadCredentialsError, \
     ResetPasswordError
from flask_security.forms import LoginForm, RegisterForm, ForgotPasswordForm, \
     ResetPasswordForm, ResendConfirmationForm
from flask_security.recoverable import reset_by_token, \
     reset_password_reset_token
from flask_security.signals import user_registered
from flask_security.utils import get_url, get_post_login_redirect, do_flash, \
     get_message, config_value, login_user, logout_user


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
                "authentication_token": user.authentication_token
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

    form = LoginForm(MultiDict(request.json) if request.json else request.form)

    try:
        user = _security.auth_provider.authenticate(form)

        if login_user(user, remember=form.remember.data):
            if request.json:
                return _json_auth_ok(user)

            return redirect(get_post_login_redirect())

        raise BadCredentialsError('Account is disabled')

    except BadCredentialsError, e:
        msg = str(e)

    _logger.debug('Unsuccessful authentication attempt: %s' % msg)

    if request.json:
        return _json_auth_error(msg)

    do_flash(msg, 'error')

    return redirect(request.referrer or _security.login_manager.login_view)


def logout():
    """View function which handles a logout request."""

    logout_user()

    _logger.debug('User logged out')

    return redirect(request.args.get('next', None) or
                    _security.post_logout_view)


def register_user():
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

        return redirect(_security.post_register_view or
                        _security.post_login_view)

    return render_template('security/registrations/new.html',
                           register_user_form=form)


def send_confirmation():
    form = ResendConfirmationForm()

    if form.validate_on_submit():
        user = _datastore.find_user(email=form.email.data)

        reset_confirmation_token(user)

        _logger.debug('%s request confirmation instructions' % user)

        msg, cat = get_message('CONFIRMATION_REQUEST', email=user.email)

        do_flash(msg, cat)

    else:
        for key, value in form.errors.items():
            do_flash(value[0], 'error')

    return render_template('security/confirmations/new.html',
                           reset_confirmation_form=form)


def confirm_account(token):
    """View function which handles a account confirmation request."""
    try:
        user = confirm_by_token(token)
        _logger.debug('%s confirmed their account' % user)

    except ConfirmationError, e:
        msg, cat = str(e), 'error'

        _logger.debug('Confirmation error: ' + msg)

        if e.user:
            reset_confirmation_token(e.user)

            msg, cat = get_message('CONFIRMATION_EXPIRED',
                                   within=_security.confirm_email_within,
                                   email=e.user.email)

        do_flash(msg, cat)

        return redirect(get_url(_security.confirm_error_view))

    do_flash(get_message('ACCOUNT_CONFIRMED'))

    return redirect(_security.post_confirm_view or _security.post_login_view)


def forgot_password():
    """View function that handles a forgotten password request."""

    form = ForgotPasswordForm(csrf_enabled=not app.testing)

    if form.validate_on_submit():
        user = _datastore.find_user(**form.to_dict())

        reset_password_reset_token(user)

        _logger.debug('%s requested to reset their password' % user)

        msg, cat = get_message('PASSWORD_RESET_REQUEST', email=user.email)

        do_flash(msg, cat)

        return redirect(_security.post_forgot_view)

    else:
        _logger.debug('A reset password request was made for %s but '
                      'that email does not exist.' % form.email.data)

        for key, value in form.errors.items():
            do_flash(value[0], 'error')

    return render_template('security/passwords/new.html',
                           forgot_password_form=form)


def reset_password(token):
    """View function that handles a reset password request."""

    form = ResetPasswordForm(csrf_enabled=not app.testing)

    if form.validate_on_submit():
        try:
            user = reset_by_token(token=token, **form.to_dict())
            _logger.debug('%s reset their password' % user)

        except ResetPasswordError, e:
            msg, cat = str(e), 'error'

            _logger.debug('Password reset error: ' + msg)

            if e.user:
                reset_password_reset_token(e.user)

                msg, cat = get_message('PASSWORD_RESET_EXPIRED',
                                       within=_security.reset_password_within,
                                       email=e.user.email)

            do_flash(msg, cat)

    return render_template('security/passwords/edit.html',
                           reset_password_form=form,
                           password_reset_token=token)


def create_blueprint(app, name, import_name, **kwargs):
    bp = Blueprint(name, import_name, **kwargs)

    bp.route(config_value('AUTH_URL', app=app),
             methods=['POST'],
             endpoint='authenticate')(authenticate)

    bp.route(config_value('LOGOUT_URL', app=app),
             endpoint='logout')(login_required(logout))

    if config_value('REGISTERABLE', app=app):
        bp.route(config_value('REGISTER_URL', app=app),
                 methods=['GET', 'POST'],
                 endpoint='register')(register_user)

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
                 endpoint='confirm_account')(confirm_account)

    return bp
