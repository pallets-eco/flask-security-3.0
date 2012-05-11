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
from flask.ext.security import exceptions, utils, confirmable, signals
from werkzeug.local import LocalProxy


security = LocalProxy(lambda: current_app.security)

logger = LocalProxy(lambda: current_app.logger)


def do_login(user, remember=True):
    if login_user(user, remember):
        identity_changed.send(current_app._get_current_object(),
                              identity=Identity(user.id))
        logger.debug('User %s logged in' % user)
        return True
    return False


def authenticate():
    form = current_app.security.LoginForm()
    try:
        user = security.auth_provider.authenticate(form)

        if do_login(user, remember=form.remember.data):
            url = utils.get_post_login_redirect()
            return redirect(url)

        raise exceptions.BadCredentialsError('Inactive user')

    except exceptions.BadCredentialsError, e:
        msg = str(e)
        utils.do_flash(msg, 'error')
        url = request.referrer or security.login_manager.login_view

        logger.debug('Unsuccessful authentication attempt: %s. '
                     'Redirect to: %s' % (msg, url))

        return redirect(url)


def logout():
    for key in ('identity.name', 'identity.auth_type'):
        session.pop(key, None)

    app = current_app._get_current_object()
    identity_changed.send(app, identity=AnonymousIdentity())
    logout_user()

    url = security.post_logout_view
    logger.debug('User logged out. Redirect to: %s' % url)
    return redirect(url)


def register():
    form = security.RegisterForm(csrf_enabled=not current_app.testing)

    if form.validate_on_submit():
        params = form.to_dict()
        params['roles'] = security.default_roles
        params['active'] = True

        if security.confirm_email:
            confirmable.generate_confirmation_token(params)

        user = security.datastore.create_user(**params)

        app = current_app._get_current_object()
        signals.user_registered.send(user, app=app)

        if security.confirm_email:
            confirmable.send_confirmation_instructions(user)

        if security.login_without_confirmation:
            do_login(user)

        url = security.post_register_view
        logger.debug('User %s registered. Redirect to: %s' % (user, url))
        return redirect(url)

    return redirect(request.referrer or security.register_url)


def confirm():
    try:
        token = request.args.get('confirmation_token', None)
        user = confirmable.confirm_by_token(token)

    except exceptions.ConfirmationError, e:
        utils.do_flash(str(e), 'error')
        return redirect('/')  # TODO: Don't just redirect to root

    except exceptions.ConfirmationExpiredError, e:
        user = e.user
        confirmable.generate_confirmation_token(user)
        confirmable.send_confirmation_instructions(user)

        msg = 'You did not confirm your email within %s. ' \
              'A new confirmation code has been sent to %s' % (
               security.confirm_email_within_text, user.email)

        utils.do_flash(msg, 'error')

        return redirect('/')

    do_login(user)
    utils.do_flash('Thank you! Your email has been confirmed', 'success')

    return redirect(security.post_confirm_view or security.post_login_view)


def reset():
    # user = something
    # if reset_password_period_valid_for_user(user):
    #     user.reset_password_sent_at = datetime.utcnow()
    #     user.reset_password_token = token
    #     current_app.security.datastore._save_model(user)
    pass
