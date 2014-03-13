# -*- coding: utf-8 -*-
"""
    test_datastore
    ~~~~~~~~~~~~~~

    Datastore tests
"""

from pytest import raises

from flask_security import UserMixin
from flask_security.datastore import Datastore, UserDatastore


class User(UserMixin):
    pass


def test_unimplemented_datastore_methods():
    datastore = Datastore(None)
    with raises(NotImplementedError):
        datastore.put(None)
    with raises(NotImplementedError):
        datastore.delete(None)


def test_unimplemented_user_datastore_methods():
    datastore = UserDatastore(None, None)
    with raises(NotImplementedError):
        datastore.find_user(None)
    with raises(NotImplementedError):
        datastore.find_role(None)


def test_toggle_active():
    datastore = UserDatastore(None, None)
    user = User()
    user.active = True
    assert datastore.toggle_active(user) is True
    assert not user.active
    assert datastore.toggle_active(user) is True
    assert user.active is True


def test_deactivate_user():
    datastore = UserDatastore(None, None)
    user = User()
    user.active = True
    assert datastore.deactivate_user(user) is True
    assert not user.active


def test_activate_user():
    datastore = UserDatastore(None, None)
    user = User()
    user.active = False
    assert datastore.activate_user(user) is True
    assert user.active is True


def test_deactivate_returns_false_if_already_false():
    datastore = UserDatastore(None, None)
    user = User()
    user.active = False
    assert not datastore.deactivate_user(user)


def test_activate_returns_false_if_already_true():
    datastore = UserDatastore(None, None)
    user = User()
    user.active = True
    assert not datastore.activate_user(user)
