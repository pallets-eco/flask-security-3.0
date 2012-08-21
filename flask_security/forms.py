# -*- coding: utf-8 -*-
"""
    flask.ext.security.forms
    ~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security forms module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from flask import request, current_app as app
from flask.ext.wtf import Form, TextField, PasswordField, SubmitField, \
     HiddenField, Required, BooleanField, EqualTo, Email, ValidationError
from werkzeug.local import LocalProxy

from .exceptions import UserNotFoundError
from .utils import encrypt_password

# Convenient reference
_datastore = LocalProxy(lambda: app.extensions['security'].datastore)

email_required = Required(message='Email not provided')

email_validator = Email(message='Invalid email address')


def unique_user_email(form, field):
    try:
        _datastore.find_user(email=field.data)
        raise ValidationError(field.data + ' is already associated with an account')
    except UserNotFoundError:
        pass


def valid_user_email(form, field):
    try:
        form.user = _datastore.find_user(email=field.data)
    except UserNotFoundError:
        raise ValidationError('Specified user does not exist')


class EmailFormMixin():
    email = TextField("Email Address",
        validators=[email_required,
                    email_validator])


class UserEmailFormMixin():
    user = None
    email = TextField("Email Address",
        validators=[email_required,
                    email_validator,
                    valid_user_email])


class UniqueEmailFormMixin():
    email = TextField("Email Address",
        validators=[email_required,
                    email_validator,
                    unique_user_email])


class PasswordFormMixin():
    password = PasswordField("Password",
        validators=[Required(message="Password not provided")])


class PasswordConfirmFormMixin():
    password_confirm = PasswordField("Retype Password",
        validators=[EqualTo('password', message="Passwords do not match")])


class SendConfirmationForm(Form, UserEmailFormMixin):
    """The default forgot password form"""

    submit = SubmitField("Resend Confirmation Instructions")

    def __init__(self, *args, **kwargs):
        super(SendConfirmationForm, self).__init__(*args, **kwargs)
        if request.method == 'GET':
            self.email.data = request.args.get('email', None)

    def to_dict(self):
        return dict(email=self.email.data)


class ForgotPasswordForm(Form, UserEmailFormMixin):
    """The default forgot password form"""

    submit = SubmitField("Recover Password")

    def to_dict(self):
        return dict(email=self.email.data)


class PasswordlessLoginForm(Form, UserEmailFormMixin):
    """The passwordless login form"""

    next = HiddenField()
    submit = SubmitField("Send Login Link")

    def __init__(self, *args, **kwargs):
        super(PasswordlessLoginForm, self).__init__(*args, **kwargs)
        if request.method == 'GET':
            self.next.data = request.args.get('next', None)

    def to_dict(self):
        return dict(email=self.email.data)


class LoginForm(Form, UserEmailFormMixin, PasswordFormMixin):
    """The default login form"""

    remember = BooleanField("Remember Me")
    next = HiddenField()
    submit = SubmitField("Login")

    def __init__(self, *args, **kwargs):
        super(LoginForm, self).__init__(*args, **kwargs)
        self.next.data = request.args.get('next', None)


class RegisterForm(Form,
                   UniqueEmailFormMixin,
                   PasswordFormMixin,
                   PasswordConfirmFormMixin):
    """The default register form"""

    submit = SubmitField("Register")

    def to_dict(self):
        return dict(email=self.email.data,
                    password=encrypt_password(self.password.data))


class ResetPasswordForm(Form,
                        PasswordFormMixin,
                        PasswordConfirmFormMixin):
    """The default reset password form"""

    submit = SubmitField("Reset Password")

    def to_dict(self):
        return dict(password=self.password.data)
