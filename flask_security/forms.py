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


class ForgotPasswordForm(Form):
    email = TextField("Email Address",
        validators=[Required(message="Email not provided")])

    def to_dict(self):
        return dict(email=self.email.data)


class LoginForm(Form):
    """The default login form"""

    email = TextField("Email Address",
        validators=[Required(message="Email not provided")])
    password = PasswordField("Password",
        validators=[Required(message="Password not provided")])
    remember = BooleanField("Remember Me")
    next = HiddenField()
    submit = SubmitField("Login")

    def __init__(self, *args, **kwargs):
        super(LoginForm, self).__init__(*args, **kwargs)
        self.next.data = request.args.get('next', None)


class RegisterForm(Form):
    """The default register form"""

    email = TextField("Email Address",
        validators=[Required(message='Email not provided'), Email()])
    password = PasswordField("Password",
        validators=[Required(message="Password not provided")])
    password_confirm = PasswordField("Retype Password",
        validators=[EqualTo('password', message="Passwords do not match")])

    def to_dict(self):
        return dict(email=self.email.data, password=self.password.data)


class ResetPasswordForm(Form):
    token = HiddenField(validators=[Required()])
    email = HiddenField(validators=[Required()])
    password = PasswordField("Password",
        validators=[Required(message="Password not provided")])
    password_confirm = PasswordField("Retype Password",
        validators=[EqualTo('password', message="Passwords do not match")])

    def to_dict(self):
        return dict(token=self.token.data,
                    email=self.email.data,
                    password=self.password.data)
