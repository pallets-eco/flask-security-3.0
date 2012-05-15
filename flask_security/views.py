# -*- coding: utf-8 -*-
"""
    flask.ext.security.views
    ~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security views module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from flask import current_app, redirect, request, session
from flask.ext.login import login_user, logout_user
from flask.ext.principal import Identity, AnonymousIdentity, identity_changed
from flask.ext.security.confirmable import confirmation_token_is_expired, \
     send_confirmation_instructions, generate_confirmation_token, \
     reset_confirmation_token, requires_confirmation, confirm_by_token
from flask.ext.security.exceptions import ConfirmationExpiredError, \
     ConfirmationError, BadCredentialsError
from flask.ext.security.utils import get_post_login_redirect, do_flash
from flask.ext.security.signals import user_registered
from werkzeug.local import LocalProxy


security = LocalProxy(lambda: current_app.security)

logger = LocalProxy(lambda: current_app.logger)


def _do_login(user, remember=True):
    if login_user(user, remember):
        identity_changed.send(current_app._get_current_object(),
                              identity=Identity(user.id))

        logger.debug('User %s logged in' % user)
        return True
    return False


def authenticate():
    """View function which handles an authentication attempt. If authentication
    is successful the user is redirected to, if set, the value of the `next`
    form parameter. If that value is not set the user is redirected to the
    value of the `SECURITY_POST_LOGIN_VIEW` configuration value. If
    authenticate fails the user an appropriate error message is flashed and
    the user is redirected to the referring page or the login view.
    """
    form = security.LoginForm()

    try:
        user = security.auth_provider.authenticate(form)

        if confirmation_token_is_expired(user):
            reset_confirmation_token(user)

        if requires_confirmation(user):
            raise BadCredentialsError('Account requires confirmation')

        if _do_login(user, remember=form.remember.data):
            return redirect(get_post_login_redirect())

        raise BadCredentialsError('Inactive user')

    except BadCredentialsError, e:
        msg = str(e)

    except Exception, e:
        msg = 'Uknown authentication error'

    do_flash(msg, 'error')

    logger.debug('Unsuccessful authentication attempt: %s. ' % msg)

    return redirect(request.referrer or security.login_manager.login_view)


def logout():
    """View function which logs out the current user. When completed the user
    is redirected to the value of the `next` query string parameter or the
    `SECURITY_POST_LOGIN_VIEW` configuration value.
    """
    for key in ('identity.name', 'identity.auth_type'):
        session.pop(key, None)

    identity_changed.send(current_app._get_current_object(),
                          identity=AnonymousIdentity())

    logout_user()

    logger.debug('User logged out')

    return redirect(request.args.get('next', None) or \
                    security.post_logout_view)


def register():
    """View function which registers a new user and, if configured so, the user
    isautomatically logged in. If required confirmation instructions are sent
    via email.  After registration is completed the user is redirected to, if
    set, the value of the `SECURITY_POST_REGISTER_VIEW` configuration value.
    Otherwise the user is redirected to the `SECURITY_POST_LOGIN_VIEW`
    configuration value.
    """
    form = security.RegisterForm(csrf_enabled=not current_app.testing)

    # Exit early if the form doesn't validate
    if not form.validate_on_submit():
        return redirect(request.referrer or security.register_url)

    # Create user and send signal
    user = security.datastore.create_user(**form.to_dict())
    user_registered.send(user, app=current_app._get_current_object())

    # Send confirmation instructions if necessary
    if security.confirm_email:
        send_confirmation_instructions(user)

    # Login the user if allowed
    if security.login_without_confirmation:
        _do_login(user)

    logger.debug('User %s registered' % user)

    return redirect(security.post_register_view or security.post_login_view)


def confirm():
    """View function which confirms a user's email address using a token taken
    from the value of the `confirmation_token` query string argument.
    """
    try:
        token = request.args.get('confirmation_token', None)
        user = confirm_by_token(token)

    except ConfirmationError, e:
        do_flash(str(e), 'error')
        return redirect('/')  # TODO: Don't just redirect to root

    except ConfirmationExpiredError, e:
        user = e.user
        generate_confirmation_token(user)
        send_confirmation_instructions(user)

        msg = 'You did not confirm your email within %s. ' \
              'A new confirmation code has been sent to %s' % (
               security.confirm_email_within_text, user.email)

        do_flash(msg, 'error')

        return redirect('/')

    _do_login(user)
    do_flash('Thank you! Your email has been confirmed', 'success')

    return redirect(security.post_confirm_view or security.post_login_view)


def reset():
    # user = something
    # if reset_password_period_valid_for_user(user):
    #     user.reset_password_sent_at = datetime.utcnow()
    #     user.reset_password_token = token
    #     current_app.security.datastore._save_model(user)
    pass
