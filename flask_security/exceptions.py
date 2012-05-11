# -*- coding: utf-8 -*-
"""
    flask.ext.security.exceptions
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security exceptions module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""


class BadCredentialsError(Exception):
    """Raised when an authentication attempt fails due to an error with the
    provided credentials.
    """


class AuthenticationError(Exception):
    """Raised when an authentication attempt fails due to invalid configuration
    or an unknown reason.
    """


class UserNotFoundError(Exception):
    """Raised by a user datastore when there is an attempt to find a user by
    their identifier, often username or email, and the user is not found.
    """


class RoleNotFoundError(Exception):
    """Raised by a user datastore when there is an attempt to find a role and
    the role cannot be found.
    """


class UserIdNotFoundError(Exception):
    """Raised by a user datastore when there is an attempt to find a user by
    ID and the user is not found.
    """


class UserDatastoreError(Exception):
    """Raised when a user datastore experiences an unexpected error
    """


class UserCreationError(Exception):
    """Raised when an error occurs when creating a user
    """


class RoleCreationError(Exception):
    """Raised when an error occurs when creating a role
    """


class ConfirmationError(Exception):
    """Raised when an unknown confirmation error occurs
    """


class ConfirmationExpiredError(Exception):
    """Raised when a user attempts to confirm their email but their token
    has expired
    """
    def __init__(self, msg, user=None):
        super(ConfirmationExpiredError, self).__init__(msg)
        self.user = user
