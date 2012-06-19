# -*- coding: utf-8 -*-
"""
    flask.ext.security.forms
    ~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security forms module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from flask import request
from flask.ext.wtf import Form, TextField, PasswordField, SubmitField, \
     HiddenField, Required, BooleanField, EqualTo, Email


class EmailFormMixin():
    email = TextField("Email Address",
        validators=[Required(message="Email not provided"),
                    Email(message="Invalid email address")])


class PasswordFormMixin():
    password = PasswordField("Password",
        validators=[Required(message="Password not provided")])


class PasswordConfirmFormMixin():
    password_confirm = PasswordField("Retype Password",
        validators=[EqualTo('password', message="Passwords do not match")])


class ForgotPasswordForm(Form, EmailFormMixin):
    """The default forgot password form"""

    submit = SubmitField("Recover Password")

    def to_dict(self):
        return dict(email=self.email.data)


class LoginForm(Form, EmailFormMixin, PasswordFormMixin):
    """The default login form"""

    remember = BooleanField("Remember Me")
    next = HiddenField()
    submit = SubmitField("Login")

    def __init__(self, *args, **kwargs):
        super(LoginForm, self).__init__(*args, **kwargs)

        if request.method == 'GET':
            self.next.data = request.args.get('next', None)


class RegisterForm(Form,
                   EmailFormMixin,
                   PasswordFormMixin,
                   PasswordConfirmFormMixin):
    """The default register form"""

    submit = SubmitField("Register")

    def to_dict(self):
        return dict(email=self.email.data, password=self.password.data)


class ResetPasswordForm(Form,
                        EmailFormMixin,
                        PasswordFormMixin,
                        PasswordConfirmFormMixin):
    """The default reset password form"""

    token = HiddenField(validators=[Required()])

    submit = SubmitField("Reset Password")

    def __init__(self, *args, **kwargs):
        super(ResetPasswordForm, self).__init__(*args, **kwargs)

        if request.method == 'GET':
            self.token.data = request.args.get('token', None)
            self.email.data = request.args.get('email', None)

    def to_dict(self):
        return dict(token=self.token.data,
                    email=self.email.data,
                    password=self.password.data)
