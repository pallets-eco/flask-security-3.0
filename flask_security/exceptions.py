# -*- coding: utf-8 -*-
"""
    flask.ext.security.exceptions
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security exceptions module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""


class SecurityError(Exception):
    def __init__(self, message=None, user=None):
        super(SecurityError, self).__init__(message)
        self.user = user


class BadCredentialsError(SecurityError):
    """Raised when an authentication attempt fails due to an error with the
    provided credentials.
    """


class AuthenticationError(SecurityError):
    """Raised when an authentication attempt fails due to invalid configuration
    or an unknown reason.
    """


class UserNotFoundError(SecurityError):
    """Raised by a user datastore when there is an attempt to find a user by
    their identifier, often username or email, and the user is not found.
    """


class RoleNotFoundError(SecurityError):
    """Raised by a user datastore when there is an attempt to find a role and
    the role cannot be found.
    """


class UserDatastoreError(SecurityError):
    """Raised when a user datastore experiences an unexpected error
    """


class UserCreationError(SecurityError):
    """Raised when an error occurs when creating a user
    """


class RoleCreationError(SecurityError):
    """Raised when an error occurs when creating a role
    """


class ConfirmationError(SecurityError):
    """Raised when an confirmation error occurs
    """


class ResetPasswordError(SecurityError):
    """Raised when a password reset error occurs
    """


class PasswordlessLoginError(SecurityError):
    """Raised when a passwordless login error occurs
    """
    def __init__(self, message=None, user=None, next=None):
        super(PasswordlessLoginError, self).__init__(message, user)
        self.next = next
