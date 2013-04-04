from flask import current_app
from werkzeug.local import LocalProxy

from ..utils import md5

from werkzeug.datastructures import ImmutableList
from flask.ext.login import AnonymousUser as AnonymousUserBase, \
     UserMixin as BaseUserMixin

# Convenient references
_security = LocalProxy(lambda: current_app.extensions['security'])

class RoleMixin(object):
    """Mixin for `Role` model definitions"""
    def __eq__(self, other):
        return (self.name == other or \
                self.name == getattr(other, 'name', None))

    def __ne__(self, other):
        return (self.name != other and
                self.name != getattr(other, 'name', None))

class UserMixin(BaseUserMixin):
    """Mixin for `User` model definitions"""

    def is_active(self):
        """Returns `True` if the user is active."""
        return self.active

    def get_auth_token(self):
        """Returns the user's authentication token."""
        data = [str(self.id), md5(self.password)]
        return _security.remember_token_serializer.dumps(data)

    def has_role(self, role):
        """Returns `True` if the user identifies with the specified role.

        :param role: A role name or `Role` instance"""
        return role in self.roles

class AnonymousUser(AnonymousUserBase):
    """AnonymousUser definition"""

    def __init__(self):
        super(AnonymousUser, self).__init__()
        self.roles = ImmutableList()

    def has_role(self, *args):
        """Returns `False`"""
        return False
