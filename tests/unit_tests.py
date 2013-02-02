# -*- coding: utf-8 -*-

import unittest

from flask_security import RoleMixin, UserMixin, AnonymousUser
from flask_security.datastore import Datastore, UserDatastore


class Role(RoleMixin):
    def __init__(self, name):
        self.name = name


class User(UserMixin):
    def __init__(self, email, roles):
        self.email = email
        self.roles = roles

admin = Role('admin')
admin2 = Role('admin')
editor = Role('editor')

user = User('matt@lp.com', [admin, editor])


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


class DatastoreTests(unittest.TestCase):

    def setUp(self):
        super(DatastoreTests, self).setUp()
        self.ds = UserDatastore(None, None)

    def test_unimplemented_datastore_methods(self):
        ds = Datastore(None)
        self.assertRaises(NotImplementedError, ds.put, None)
        self.assertRaises(NotImplementedError, ds.delete, None)

    def test_unimplemented_user_datastore_methods(self):
        self.assertRaises(NotImplementedError, self.ds.find_user, None)
        self.assertRaises(NotImplementedError, self.ds.find_role, None)

    def test_toggle_active(self):
        user.active = True
        rv = self.ds.toggle_active(user)
        self.assertTrue(rv)
        self.assertFalse(user.active)
        rv = self.ds.toggle_active(user)
        self.assertTrue(rv)
        self.assertTrue(user.active)

    def test_deactivate_user(self):
        user.active = True
        rv = self.ds.deactivate_user(user)
        self.assertTrue(rv)
        self.assertFalse(user.active)

    def test_activate_user(self):
        ds = UserDatastore(None, None)
        user.active = False
        ds.activate_user(user)
        self.assertTrue(user.active)

    def test_deactivate_returns_false_if_already_false(self):
        user.active = False
        self.assertFalse(self.ds.deactivate_user(user))

    def test_activate_returns_false_if_already_true(self):
        user.active = True
        self.assertFalse(self.ds.activate_user(user))
