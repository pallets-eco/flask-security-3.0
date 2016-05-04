# -*- coding: utf-8 -*-
"""
    flask_security.views
    ~~~~~~~~~~~~~~~~~~~~

    Flask-Security views module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""
import pyqrcode
from flask import current_app, redirect, request, jsonify, \
    after_this_request, Blueprint, session
from flask_login import current_user
from werkzeug.datastructures import MultiDict
from werkzeug.local import LocalProxy

from .confirmable import send_confirmation_instructions, \
    confirm_user, confirm_email_token_status
from .decorators import login_required, anonymous_user_required
from .passwordless import send_login_instructions, \
    login_token_status
from .recoverable import reset_password_token_status, \
    send_reset_password_instructions, update_password
from .changeable import change_user_password
from .registerable import register_user
from .utils import config_value, do_flash, get_url, get_post_login_redirect, \
    get_post_register_redirect, get_message, login_user, logout_user, \
    url_for_security as url_for, slash_url_suffix

from .twofactor import send_security_token, get_totp_uri, \
    get_totp_password, verify_totp, generate_totp

# Convenient references
_security = LocalProxy(lambda: current_app.extensions['security'])

_datastore = LocalProxy(lambda: _security.datastore)


def _render_json(form, include_user=True, include_auth_token=False):
    has_errors = len(form.errors) > 0

    if has_errors:
        code = 400
        response = dict(errors=form.errors)
    else:
        code = 200
        response = dict()
        if include_user:
            response['user'] = dict(id=str(form.user.id))
        if include_auth_token:
            token = form.user.get_auth_token()
            response['user']['authentication_token'] = token

    return jsonify(dict(meta=dict(code=code), response=response))


def _commit(response=None):
    _datastore.commit()
    return response


def _ctx(endpoint):
    return _security._run_ctx_processor(endpoint)


@anonymous_user_required
def login():
    """View function for login view"""

    form_class = _security.login_form

    if request.json:
        form = form_class(MultiDict(request.json))
    else:
        form = form_class()

    if form.validate_on_submit():
        login_user(form.user, remember=form.remember.data)
        after_this_request(_commit)

        if not request.json:
            return redirect(get_post_login_redirect(form.next.data))

    if request.json:
        return _render_json(form, include_auth_token=True)

    return _security.render_template(config_value('LOGIN_USER_TEMPLATE'),
                                     login_user_form=form,
                                     **_ctx('login'))


def logout():
    """View function which handles a logout request."""

    if current_user.is_authenticated:
        logout_user()

    return redirect(request.args.get('next', None) or
                    get_url(_security.post_logout_view))


@anonymous_user_required
def register():
    """View function which handles a registration request."""

    if _security.confirmable or request.json:
        form_class = _security.confirm_register_form
    else:
        form_class = _security.register_form

    if request.json:
        form_data = MultiDict(request.json)
    else:
        form_data = request.form

    form = form_class(form_data)

    if form.validate_on_submit():
        user = register_user(**form.to_dict())
        form.user = user

        if not _security.confirmable or _security.login_without_confirmation:
            after_this_request(_commit)
            login_user(user)

        if not request.json:
            if 'next' in form:
                redirect_url = get_post_register_redirect(form.next.data)
            else:
                redirect_url = get_post_register_redirect()

            return redirect(redirect_url)
        return _render_json(form, include_auth_token=True)

    if request.json:
        return _render_json(form)

    return _security.render_template(config_value('REGISTER_USER_TEMPLATE'),
                                     register_user_form=form,
                                     **_ctx('register'))


def send_login():
    """View function that sends login instructions for passwordless login"""

    form_class = _security.passwordless_login_form

    if request.json:
        form = form_class(MultiDict(request.json))
    else:
        form = form_class()

    if form.validate_on_submit():
        send_login_instructions(form.user)
        if request.json is None:
            do_flash(*get_message('LOGIN_EMAIL_SENT', email=form.user.email))

    if request.json:
        return _render_json(form)

    return _security.render_template(config_value('SEND_LOGIN_TEMPLATE'),
                                     send_login_form=form,
                                     **_ctx('send_login'))


@anonymous_user_required
def token_login(token):
    """View function that handles passwordless login via a token"""

    expired, invalid, user = login_token_status(token)

    if invalid:
        do_flash(*get_message('INVALID_LOGIN_TOKEN'))
    if expired:
        send_login_instructions(user)
        do_flash(*get_message('LOGIN_EXPIRED', email=user.email,
                              within=_security.login_within))
    if invalid or expired:
        return redirect(url_for('login'))

    login_user(user)
    after_this_request(_commit)
    do_flash(*get_message('PASSWORDLESS_LOGIN_SUCCESSFUL'))

    return redirect(get_post_login_redirect())


def send_confirmation():
    """View function which sends confirmation instructions."""

    form_class = _security.send_confirmation_form

    if request.json:
        form = form_class(MultiDict(request.json))
    else:
        form = form_class()

    if form.validate_on_submit():
        send_confirmation_instructions(form.user)
        if request.json is None:
            do_flash(*get_message('CONFIRMATION_REQUEST', email=form.user.email))

    if request.json:
        return _render_json(form)

    return _security.render_template(config_value('SEND_CONFIRMATION_TEMPLATE'),
                                     send_confirmation_form=form,
                                     **_ctx('send_confirmation'))


def confirm_email(token):
    """View function which handles a email confirmation request."""

    expired, invalid, user = confirm_email_token_status(token)

    if not user or invalid:
        invalid = True
        do_flash(*get_message('INVALID_CONFIRMATION_TOKEN'))
    if expired:
        send_confirmation_instructions(user)
        do_flash(*get_message('CONFIRMATION_EXPIRED', email=user.email,
                              within=_security.confirm_email_within))
    if invalid or expired:
        return redirect(get_url(_security.confirm_error_view) or
                        url_for('send_confirmation'))

    if user != current_user:
        logout_user()
        login_user(user)

    if confirm_user(user):
        after_this_request(_commit)
        msg = 'EMAIL_CONFIRMED'
    else:
        msg = 'ALREADY_CONFIRMED'

    do_flash(*get_message(msg))

    return redirect(get_url(_security.post_confirm_view) or
                    get_url(_security.post_login_view))


@anonymous_user_required
def forgot_password():
    """View function that handles a forgotten password request."""

    form_class = _security.forgot_password_form

    if request.json:
        form = form_class(MultiDict(request.json))
    else:
        form = form_class()

    if form.validate_on_submit():
        send_reset_password_instructions(form.user)
        if request.json is None:
            do_flash(*get_message('PASSWORD_RESET_REQUEST', email=form.user.email))

    if request.json:
        return _render_json(form, include_user=False)

    return _security.render_template(config_value('FORGOT_PASSWORD_TEMPLATE'),
                                     forgot_password_form=form,
                                     **_ctx('forgot_password'))


@anonymous_user_required
def reset_password(token):
    """View function that handles a reset password request."""

    expired, invalid, user = reset_password_token_status(token)

    if invalid:
        do_flash(*get_message('INVALID_RESET_PASSWORD_TOKEN'))
    if expired:
        do_flash(*get_message('PASSWORD_RESET_EXPIRED', email=user.email,
                              within=_security.reset_password_within))
    if invalid or expired:
        return redirect(url_for('forgot_password'))

    form = _security.reset_password_form()

    if form.validate_on_submit():
        after_this_request(_commit)
        update_password(user, form.password.data)
        do_flash(*get_message('PASSWORD_RESET'))
        login_user(user)
        return redirect(get_url(_security.post_reset_view) or
                        get_url(_security.post_login_view))

    return _security.render_template(config_value('RESET_PASSWORD_TEMPLATE'),
                                     reset_password_form=form,
                                     reset_password_token=token,
                                     **_ctx('reset_password'))


@login_required
def change_password():
    """View function which handles a change password request."""

    form_class = _security.change_password_form

    if request.json:
        form = form_class(MultiDict(request.json))
    else:
        form = form_class()

    if form.validate_on_submit():
        after_this_request(_commit)
        change_user_password(current_user, form.new_password.data)
        if request.json is None:
            do_flash(*get_message('PASSWORD_CHANGE'))
            return redirect(get_url(_security.post_change_view) or
                            get_url(_security.post_login_view))

    if request.json:
        form.user = current_user
        return _render_json(form)

    return _security.render_template(config_value('CHANGE_PASSWORD_TEMPLATE'),
                                     change_password_form=form,
                                     **_ctx('change_password'))


@login_required
def two_factor_change_method():
    """View function which handles a change second factor method request."""

    form_class = _security.two_factor_change_method_form

    if request.json:
        form = form_class(MultiDict(request.json))
    else:
        form = form_class()

    if form.validate_on_submit():
        # after_this_request(_commit)
        # change_user_password(current_user, form.new_password.data)
        if request.json is None:
            do_flash(*get_message('TWO_FACTOR_METHOD_CHANGE_SUCCEEDED'))
            two_factor_verify_code_form = _security.two_factor_verify_code_form
            two_factor_setup_form = _security.two_factor_setup_form
            if request.json:
                two_factor_verify_code_form = two_factor_verify_code_form(MultiDict(request.json))
                two_factor_setup_form = two_factor_setup_form(MultiDict(request.json))
            else:
                two_factor_verify_code_form = two_factor_verify_code_form()
                two_factor_setup_form = two_factor_setup_form()
                # change user's totp - qrcode will be unique everytime choose method template is called
                current_user.totp = generate_totp()

            return _security.render_template(config_value('TWO_FACTOR_CHOOSE_METHOD_TEMPLATE'),
                                     two_factor_verify_code_form=two_factor_verify_code_form,
                                     two_factor_setup_form=two_factor_setup_form,
                                     next_endpoint='two_factor_change_method_token_validation',
                                     **_ctx('two_factor_change_method_token_validation'))
    if request.json:
        form.user = current_user
        return _render_json(form)

    return _security.render_template(config_value('TWO_FACTOR_CHANGE_METHOD_TEMPLATE'),
                                     two_factor_change_method_form=form,
                                     **_ctx('two_factor_change_method'))


@anonymous_user_required
def two_factor_login():
    """View function for two factor authentication login"""
    form_class = _security.login_form

    if request.json:
        form = form_class(MultiDict(request.json))
    else:
        form = form_class()

    if form.validate_on_submit():
        session['username'] = form.user.username
        user = _datastore.find_user(username=session['username'])
        primary = user.two_factor_primary_method

        two_factor_verify_code_form = _security.two_factor_verify_code_form
        if request.json:
            two_factor_verify_code_form = two_factor_verify_code_form(MultiDict(request.json))
        else:
            two_factor_verify_code_form = two_factor_verify_code_form()

        if primary is None:
            two_factor_setup_form = _security.two_factor_setup_form
            if request.json:
                two_factor_setup_form = two_factor_setup_form(MultiDict(request.json))
            else:
                two_factor_setup_form = two_factor_setup_form()

            return _security.render_template(config_value('TWO_FACTOR_CHOOSE_METHOD_TEMPLATE'),
                                             two_factor_verify_code_form=two_factor_verify_code_form,
                                             two_factor_setup_form=two_factor_setup_form,
                                             next_endpoint='two_factor_token_validation',
                                             **_ctx('two_factor_token_validation'))
        else:
            send_security_token(user=user, method=primary)
            return _security.render_template(config_value('TWO_FACTOR_VERIFY_CODE_TEMPLATE'),
                                             two_factor_verify_code_form=two_factor_verify_code_form)

    if request.json:
        form.user = current_user
        return _render_json(form)

    return _security.render_template(config_value('TWO_FACTOR_LOGIN_USER_TEMPLATE'),
                                         login_user_form=form,
                                         **_ctx('login'))

@login_required
def two_factor_change_method_token_validation():
    """View function for changing the two factor authentication method"""
    user = current_user
    session['username'] = user.username
    session['two_factor_primary'] = user.two_factor_primary_method
    next_endpoint = 'two_factor_change_method_token_validation'
    return token_validation(user, next_endpoint)

@anonymous_user_required
def two_factor_token_validation():
    """View function for validating the code entered during two factor authentication"""
    user = _datastore.find_user(username=session['username'])
    next_endpoint = 'two_factor_token_validation'
    return token_validation(user, next_endpoint)


def token_validation(user, next_endpoint):
    form = request.form
    two_factor_verify_code_form, two_factor_setup_form, two_factor_enter_phone_form = construct_two_factor_setup_forms()
    # Relevant to users who wants to submit a phone number to get codes to

    if form.has_key('phone'):
        form.setup = 'sms'
        user.phone_number = form['phone']
    # Relevant for mail, google authenticator and sms methods and help determines html
    if form.has_key('setup'):
        method = form['setup']
        if next_endpoint == 'two_factor_change_method_token_validation' and \
                                                            method == user.two_factor_primary_method:
            do_flash(*get_message('TWO_FACTOR_METHOD_IS_THE_SAME'))
            return _security.render_template(config_value('TWO_FACTOR_CHOOSE_METHOD_TEMPLATE'),
                                                 two_factor_verify_code_form=two_factor_verify_code_form,
                                                 two_factor_setup_form=two_factor_setup_form,
                                                 two_factor_enter_phone_form=two_factor_enter_phone_form,
                                                 next_endpoint=next_endpoint,
                                                 **_ctx(next_endpoint))
        else:
            session['two_factor_primary'] = method
            send_security_token(user=user, method=method)
            return _security.render_template(config_value('TWO_FACTOR_CHOOSE_METHOD_TEMPLATE'),
                                                 two_factor_verify_code_form=two_factor_verify_code_form,
                                                 two_factor_setup_form=two_factor_setup_form,
                                                 two_factor_enter_phone_form=two_factor_enter_phone_form,
                                                 chosen_method=method,
                                                 next_endpoint =next_endpoint,
                                                 **_ctx(next_endpoint))

    if form.has_key('code'):
        code_entered = form['code']
        if 'two_factor_primary' in session and session['two_factor_primary'] == 'google_authenticator':
            window = 0
        else:
            window = 1

        if verify_totp(user=user, token=code_entered, window=window):
            perform_user_login(user)
            return redirect(get_post_login_redirect())
        else:
            do_flash(*get_message('TWO_FACTOR_INVALID_TOKEN'))
            return _security.render_template(config_value('TWO_FACTOR_CHOOSE_METHOD_TEMPLATE'),
                                                 two_factor_setup_form=two_factor_setup_form,
                                                 two_factor_verify_code_form=two_factor_verify_code_form,
                                                 next_endpoint=next_endpoint,
                                                 **_ctx(next_endpoint))

    if request.json:
        form.user = current_user
        return _render_json(form)

    return _security.render_template(config_value('TWO_FACTOR_VERIFY_CODE_TEMPLATE'),
                                     two_factor_setup_form=two_factor_setup_form,
                                     two_factor_verify_code_form=two_factor_verify_code_form,
                                      **_ctx('verify_code'))

@anonymous_user_required
def two_factor_qrcode():
    """View function for generating a qrcode svg for two factor authentication"""
    if 'username' not in session:
        return redirect(url_for('login'))
    user = _datastore.find_user(username=session['username'])
    if user is None:
        return redirect(url_for('login'))
    url = pyqrcode.create(get_totp_uri(user))
    from StringIO import StringIO
    stream = StringIO()
    url.svg(stream, scale=3)
    return stream.getvalue().encode('utf-8'), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

def construct_two_factor_setup_forms():
    two_factor_verify_code_form = _security.two_factor_verify_code_form
    two_factor_setup_form = _security.two_factor_setup_form
    two_factor_enter_phone_form = _security.two_factor_enter_phone_form

    if request.json:
        two_factor_verify_code_form = two_factor_verify_code_form(MultiDict(request.json))
        two_factor_setup_form = two_factor_setup_form(MultiDict(request.json))
        two_factor_enter_phone_form = two_factor_enter_phone_form(MultiDict(request.json))

    else:
        two_factor_verify_code_form = two_factor_verify_code_form()
        two_factor_setup_form = two_factor_setup_form()
        two_factor_enter_phone_form = two_factor_enter_phone_form()

    return two_factor_verify_code_form, two_factor_setup_form, two_factor_enter_phone_form


def perform_user_login(user):
    """ helper function that del unnecessary information before logging user in, and commits after request"""
    del session['username']
    if user.two_factor_primary_method == None:
        user.two_factor_primary_method = session['two_factor_primary']
    else:
        user.two_factor_secondary_method = user.two_factor_primary_method
        user.two_factor_primary_method = session['two_factor_primary']
    del session['two_factor_primary']

    login_user(user)
    after_this_request(_commit)
    do_flash(*get_message('TWO_FACTOR_LOGIN_SUCCESSFUL'))

def create_blueprint(state, import_name):
    """Creates the security extension blueprint"""
    bp = Blueprint(state.blueprint_name, import_name,
                   url_prefix=state.url_prefix,
                   subdomain=state.subdomain,
                   template_folder='templates')

    bp.route(state.logout_url, endpoint='logout')(logout)

    if state.passwordless:
        bp.route(state.login_url,
                 methods=['GET', 'POST'],
                 endpoint='login')(send_login)
        bp.route(state.login_url + slash_url_suffix(state.login_url, '<token>'),
                 endpoint='token_login')(token_login)

    elif state.two_factor_authentication:
        bp.route(state.login_url,
                 methods=['GET', 'POST'],
                 endpoint='login')(two_factor_login)
        bp.route(state.login_url + slash_url_suffix(state.login_url, 'two_factor_token_validation'),
                 methods=['GET', 'POST'],
                 endpoint='two_factor_token_validation')(two_factor_token_validation)
        bp.route(state.login_url + slash_url_suffix(state.login_url, 'two_factor_qrcode'),
                 endpoint='two_factor_qrcode')(two_factor_qrcode)


    else:
        bp.route(state.login_url,
                 methods=['GET', 'POST'],
                 endpoint='login')(login)

    if state.registerable:
        bp.route(state.register_url,
                 methods=['GET', 'POST'],
                 endpoint='register')(register)

    if state.recoverable:
        bp.route(state.reset_url,
                 methods=['GET', 'POST'],
                 endpoint='forgot_password')(forgot_password)
        bp.route(state.reset_url + slash_url_suffix(state.reset_url, '<token>'),
                 methods=['GET', 'POST'],
                 endpoint='reset_password')(reset_password)

    if state.changeable:
        bp.route(state.change_url,
                 methods=['GET', 'POST'],
                 endpoint='change_password')(change_password)
        bp.route(state.change_url + slash_url_suffix(state.change_url, 'two_factor_change_method'),
                 methods=['GET', 'POST'],
                 endpoint='two_factor_change_method')(two_factor_change_method)
        bp.route(state.change_url + slash_url_suffix(state.change_url, 'two_factor_change_method_token_validation'),
                 methods=['GET', 'POST'],
                 endpoint='two_factor_change_method_token_validation')(two_factor_change_method_token_validation)


    if state.confirmable:
        bp.route(state.confirm_url,
                 methods=['GET', 'POST'],
                 endpoint='send_confirmation')(send_confirmation)
        bp.route(state.confirm_url + slash_url_suffix(state.confirm_url, '<token>'),
                 methods=['GET', 'POST'],
                 endpoint='confirm_email')(confirm_email)

    return bp
