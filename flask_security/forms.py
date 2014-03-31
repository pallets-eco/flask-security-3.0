# -*- coding: utf-8 -*-
"""
    flask.ext.security.forms
    ~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security forms module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

import inspect

from ._compat import PY2

if not PY2:
    import urllib.parse as urlparse
else:
    import urlparse

import flask_wtf as wtf
from flask import request, current_app, get_template_attribute, flash
from flask_wtf import Form as BaseForm
from wtforms import TextField, PasswordField, validators, \
    SubmitField, HiddenField, BooleanField, ValidationError, Field
from flask_login import current_user
from werkzeug.local import LocalProxy

from .confirmable import requires_confirmation
from .utils import verify_and_update_password, get_message, config_value, validate_redirect_url

# Convenient reference
_datastore = LocalProxy(lambda: current_app.extensions['security'].datastore)

_default_field_labels = {
    'email': 'Email Address',
    'password': 'Password',
    'remember_me': 'Remember Me',
    'login': 'Login',
    'retype_password': 'Retype Password',
    'register': 'Register',
    'send_confirmation': 'Resend Confirmation Instructions',
    'recover_password': 'Recover Password',
    'reset_password': 'Reset Password',
    'retype_password': 'Retype Password',
    'new_password': 'New Password',
    'change_password': 'Change Password',
    'send_login_link': 'Send Login Link'
}


class ValidatorMixin(object):
    def __call__(self, form, field):
        if self.message and self.message.isupper():
            self.message = get_message(self.message)[0]
        return super(ValidatorMixin, self).__call__(form, field)


class EqualTo(ValidatorMixin, validators.EqualTo):
    pass


class Required(ValidatorMixin, validators.Required):
    pass


class Email(ValidatorMixin, validators.Email):
    pass


class Length(ValidatorMixin, validators.Length):
    pass


email_required = Required(message='EMAIL_NOT_PROVIDED')
email_validator = Email(message='INVALID_EMAIL_ADDRESS')
password_required = Required(message='PASSWORD_NOT_PROVIDED')
password_length = Length(min=6, max=128, message='PASSWORD_INVALID_LENGTH')


def get_form_field_label(key):
    return _default_field_labels.get(key, '')


def unique_user_email(form, field):
    if _datastore.find_user(email=field.data) is not None:
        msg = get_message('EMAIL_ALREADY_ASSOCIATED', email=field.data)[0]
        raise ValidationError(msg)


def valid_user_email(form, field):
    form.user = _datastore.find_user(email=field.data)
    if form.user is None:
        raise ValidationError(get_message('USER_DOES_NOT_EXIST')[0])


class SecurityForm(BaseForm):
    def __init__(self, *args, **kwargs):
        if current_app.testing:
            self.TIME_LIMIT = None
        super(SecurityForm, self).__init__(*args, **kwargs)

    def update(self, ctx):
        [setattr(self, k, v) for k,v in ctx.items()]

    @classmethod
    def _ctx_tag(cls):
        return ''.join('_'+x.lower() if x.isupper() else x for x in cls.__name__[:-4]).strip('_')

    @property
    def _renderable(self):
        return get_template_attribute(self.mtemplate, self.mname)

    def render_macro(self, ctx):
        self.update(ctx)
        return self._renderable(self)


class EmailFormMixin():
    email = TextField(
        get_form_field_label('email'),
        validators=[email_required, email_validator])


class UserEmailFormMixin():
    user = None
    email = TextField(
        get_form_field_label('email'),
        validators=[email_required, email_validator, valid_user_email])


class UniqueEmailFormMixin():
    email = TextField(
        get_form_field_label('email'),
        validators=[email_required, email_validator, unique_user_email])


class PasswordFormMixin():
    password = PasswordField(
        get_form_field_label('password'), validators=[password_required])


class NewPasswordFormMixin():
    password = PasswordField(
        get_form_field_label('password'),
        validators=[password_required, password_length])


class PasswordConfirmFormMixin():
    password_confirm = PasswordField(
        get_form_field_label('retype_password'),
        validators=[EqualTo('password', message='RETYPE_PASSWORD_MISMATCH')])


class NextFormMixin():
    next = HiddenField()

    def validate_next(self, field):
        if field.data and not validate_redirect_url(field.data):
            field.data = ''
            flash(*get_message('INVALID_REDIRECT'))
            raise ValidationError(get_message('INVALID_REDIRECT')[0])


class RegisterFormMixin(SecurityForm):
    mname='register_macro'
    mtemplate='security/macros/_register.html'

    submit = SubmitField(get_form_field_label('register'))

    def to_dict(form):
        def is_field_and_user_attr(member):
            return isinstance(member, Field) and \
                hasattr(_datastore.user_model, member.name)

        fields = inspect.getmembers(form, is_field_and_user_attr)
        return dict((key, value.data) for key, value in fields)


class SendConfirmationForm(UserEmailFormMixin, SecurityForm):
    """The default send confirmation form"""

    mname='send_confirmation_macro'
    mtemplate='security/macros/_send_confirmation.html'

    submit = SubmitField(get_form_field_label('send_confirmation'))

    def __init__(self, *args, **kwargs):
        super(SendConfirmationForm, self).__init__(*args, **kwargs)
        if request.method == 'GET':
            self.email.data = request.args.get('email', None)

    def validate(self):
        if not super(SendConfirmationForm, self).validate():
            return False

        self.user = _datastore.get_user(self.email.data)

        if not self.user:
            self.email.errors.append(get_message('USER_DOES_NOT_EXIST')[0])
            return False

        if self.user.confirmed_at is not None:
            self.email.errors.append(get_message('ALREADY_CONFIRMED')[0])
            return False
        return True


class ForgotPasswordForm(UserEmailFormMixin, SecurityForm):
    """The default forgot password form"""

    mname='forgot_password_macro'
    mtemplate='security/macros/_forgot_password.html'

    submit = SubmitField(get_form_field_label('recover_password'))

    def __init__(self, *args, **kwargs):
        super(ForgotPasswordForm, self).__init__(*args, **kwargs)


class PasswordlessForm(UserEmailFormMixin, SecurityForm):
    """The passwordless login form"""

    mname='passwordless_macro'
    mtemplate='security/macros/_passwordless.html'

    submit = SubmitField(get_form_field_label('send_login_link'))

    def __init__(self, *args, **kwargs):
        super(PasswordlessForm, self).__init__(*args, **kwargs)

    def validate(self):
        if not super(PasswordlessForm, self).validate():
            return False

        self.user = _datastore.get_user(self.email.data)

        if self.user is None:
            self.email.errors.append(get_message('USER_DOES_NOT_EXIST')[0])
            return False

        if not self.user.is_active():
            self.email.errors.append(get_message('DISABLED_ACCOUNT')[0])
            return False
        return True


class LoginForm(NextFormMixin, SecurityForm):
    """The default login form"""

    mname='login_macro'
    mtemplate='security/macros/_login.html'

    email = TextField(get_form_field_label('email'))
    password = PasswordField(get_form_field_label('password'))
    remember = BooleanField(get_form_field_label('remember_me'))
    submit = SubmitField(get_form_field_label('login'))

    def __init__(self, *args, **kwargs):
        super(LoginForm, self).__init__(*args, **kwargs)
        if not self.next.data:
            self.next.data = request.args.get('next', '')
        self.remember.default = config_value('DEFAULT_REMEMBER_ME')

    def validate(self):
        if not super(LoginForm, self).validate():
            return False

        if self.email.data.strip() == '':
            self.email.errors.append(get_message('EMAIL_NOT_PROVIDED')[0])
            return False

        if self.password.data.strip() == '':
            self.password.errors.append(get_message('PASSWORD_NOT_PROVIDED')[0])
            return False

        self.user = _datastore.get_user(self.email.data)

        if self.user is None:
            self.email.errors.append(get_message('USER_DOES_NOT_EXIST')[0])
            return False
        if not self.user.password:
            self.password.errors.append(get_message('PASSWORD_NOT_SET')[0])
            return False
        if not verify_and_update_password(self.password.data, self.user):
            self.password.errors.append(get_message('INVALID_PASSWORD')[0])
            return False
        if requires_confirmation(self.user):
            self.email.errors.append(get_message('CONFIRMATION_REQUIRED')[0])
            return False
        if not self.user.is_active():
            self.email.errors.append(get_message('DISABLED_ACCOUNT')[0])
            return False
        return True


class ConfirmRegisterForm(UniqueEmailFormMixin, NewPasswordFormMixin, RegisterFormMixin, SecurityForm):
    """The default confirm register password form"""

    mname='confirm_register_macro'
    mtemplate='security/macros/_confirm_register.html'

    def __init__(self, *args, **kwargs):
        super(ConfirmRegisterForm, self).__init__(*args, **kwargs)


class RegisterForm(PasswordConfirmFormMixin, ConfirmRegisterForm):
    """The default register password form"""

    mname='register_macro'
    mtemplate='security/macros/_register.html'

    def __init__(self, *args, **kwargs):
        super(RegisterForm, self).__init__(*args, **kwargs)


class ResetPasswordForm(NewPasswordFormMixin, PasswordConfirmFormMixin, SecurityForm):
    """The default reset password form"""

    mname='reset_password_macro'
    mtemplate='security/macros/_reset_password.html'

    submit = SubmitField(get_form_field_label('reset_password'))

    def __init__(self, *args, **kwargs):
        super(ResetPasswordForm, self).__init__(*args, **kwargs)


class ChangePasswordForm(PasswordFormMixin, SecurityForm):
    """The default change password form"""

    mname='change_password_macro'
    mtemplate='security/macros/_change_password.html'

    new_password = PasswordField(
        get_form_field_label('new_password'),
        validators=[password_required, password_length])

    new_password_confirm = PasswordField(
        get_form_field_label('retype_password'),
        validators=[EqualTo('new_password', message='RETYPE_PASSWORD_MISMATCH')])

    submit = SubmitField(get_form_field_label('change_password'))

    def __init__(self, *args, **kwargs):
        super(ChangePasswordForm, self).__init__(*args, **kwargs)

    def validate(self):
        if not super(ChangePasswordForm, self).validate():
            return False

        if not verify_and_update_password(self.password.data, current_user):
            self.password.errors.append(get_message('INVALID_PASSWORD')[0])
            return False
        if self.password.data.strip() == self.new_password.data.strip():
            self.password.errors.append(get_message('PASSWORD_IS_THE_SAME')[0])
            return False
        return True
