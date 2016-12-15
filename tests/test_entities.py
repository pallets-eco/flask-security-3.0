# -*- coding: utf-8 -*-
"""
    test_entities
    ~~~~~~~~~~~~~

    Entity tests
"""

from flask_security import AnonymousUser, RoleMixin, UserMixin


class Role(RoleMixin):

    def __init__(self, name):
        self.name = name


class User(UserMixin):

    def __init__(self, roles):
        self.roles = roles


def test_role_mixin_equal():
    admin1 = Role('admin')
    admin2 = Role('admin')
    assert admin1 == admin2


def test_role_mixin_not_equal():
    admin = Role('admin')
    editor = Role('editor')
    assert admin != editor


def test_user_mixin_has_role_with_string():
    admin = Role('admin')
    editor = Role('editor')
    user = User([admin, editor])
    assert user.has_role('admin') is True
    assert user.has_role('editor') is True
    assert user.has_role(admin) is True
    assert user.has_role(editor) is True


def test_anonymous_user_has_no_roles():
    user = AnonymousUser()
    assert not user.has_role('admin')
