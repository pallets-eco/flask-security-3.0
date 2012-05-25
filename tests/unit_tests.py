
import unittest

from flask_security import RoleMixin, UserMixin, AnonymousUser


class Role(RoleMixin):
    def __init__(self, name, description=None):
        self.name = name
        self.description = description


class User(UserMixin):
    def __init__(self, username, email, roles):
        self.username = username
        self.email = email
        self.roles = roles

admin = Role('admin')
admin2 = Role('admin')
editor = Role('editor')

user = User('matt', 'matt@lp.com', [admin, editor])


class SecurityEntityTests(unittest.TestCase):

    def test_role_mixin_equal(self):
        self.assertEqual(admin, admin2)

    def test_role_mixin_not_equal(self):
        self.assertNotEqual(admin, editor)

    def test_user_mixin_has_role_with_string(self):
        self.assertTrue(user.has_role('admin'))

    def test_user_mixin_has_role_with_role_obj(self):
        self.assertTrue(user.has_role(Role('admin')))

    def test_anonymous_user_has_no_roles(self):
        au = AnonymousUser()
        self.assertEqual(0, len(au.roles))
        self.assertFalse(au.has_role('admin'))
