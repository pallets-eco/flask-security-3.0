# -*- coding: utf-8 -*-
"""
    flask.ext.security.script
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security script module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""
from __future__ import print_function

try:
    import simplejson as json
except ImportError:
    import json

import re

from flask import current_app
from flask.ext.script import Command, Option, Manager
from werkzeug.local import LocalProxy

from .utils import encrypt_password


_datastore = LocalProxy(lambda: current_app.extensions['security'].datastore)


manager = Manager(usage="Flask-Security extension commands")


def pprint(obj):
    print(json.dumps(obj, sort_keys=True, indent=4))


def commit(fn):
    def wrapper(*args, **kwargs):
        fn(*args, **kwargs)
        _datastore.commit()
    return wrapper


def get_user(user_identifier):
    user = _datastore.get_user(user_identifier)
    if user is None:
        raise ValueError("User '%s' doesn't exist" % user_identifier)
    return user


def find_role(role_name):
    role = _datastore.find_role(role_name)
    if role is None:
        raise ValueError("Role '%s' doesn't exist" % role_name)
    return role


class CreateUserCommand(Command):
    """Create a user"""

    option_list = (
        Option('-e', '--email', dest='email', required=True),
        Option('-p', '--password', dest='password', required=True),
        Option('-a', '--active', dest='active', default=''),
    )

    @commit
    def run(self, **kwargs):
        # sanitize active input
        ai = re.sub(r'\s', '', str(kwargs['active']))
        kwargs['active'] = ai.lower() in ['', 'y', 'yes', '1', 'active']

        from flask_security.forms import ConfirmRegisterForm
        from werkzeug.datastructures import MultiDict

        form = ConfirmRegisterForm(MultiDict(kwargs), csrf_enabled=False)

        if form.validate():
            kwargs['password'] = encrypt_password(kwargs['password'])
            _datastore.create_user(**kwargs)
            print('User created successfully.')
            kwargs['password'] = '****'
            pprint(kwargs)
        else:
            print('Error creating user')
            pprint(form.errors)


class DeleteUserCommand(Command):
    """Delete a user"""

    option_list = (
        Option('-u', '--user', dest='user_identifier', required=True),
    )

    @commit
    def run(self, user_identifier):
        _datastore.delete_user(get_user(user_identifier))
        print("User '%s' has been deleted" % user_identifier)


class CreateRoleCommand(Command):
    """Create a role"""

    option_list = (
        Option('-n', '--name', dest='name', required=True),
        Option('-d', '--desc', dest='description', default=None),
    )

    @commit
    def run(self, **kwargs):
        _datastore.create_role(**kwargs)
        print('Role "%(name)s" created successfully.' % kwargs)


class _RoleCommand(Command):
    option_list = (
        Option('-u', '--user', dest='user_identifier', required=True),
        Option('-r', '--role', dest='role_name', required=True),
    )


class AddRoleCommand(_RoleCommand):
    """Add a role to a user"""

    @commit
    def run(self, user_identifier, role_name):
        _datastore.add_role_to_user(
            get_user(user_identifier), find_role(role_name))
        print("Role '%s' added to user '%s' successfully" % (role_name, user_identifier))


class RemoveRoleCommand(_RoleCommand):
    """Add a role to a user"""

    @commit
    def run(self, user_identifier, role_name):
        _datastore.remove_role_from_user(
            get_user(user_identifier), find_role(role_name))
        print("Role '%s' removed from user '%s' successfully" % (role_name, user_identifier))


class _ToggleActiveCommand(Command):
    option_list = (
        Option('-u', '--user', dest='user_identifier', required=True),
    )


class DeactivateUserCommand(_ToggleActiveCommand):
    """Deactive a user"""

    @commit
    def run(self, user_identifier):
        _datastore.deactivate_user(get_user(user_identifier))
        print("User '%s' has been deactivated" % user_identifier)


class ActivateUserCommand(_ToggleActiveCommand):
    """Activate a user"""

    @commit
    def run(self, user_identifier):
        _datastore.activate_user(get_user(user_identifier))
        print("User '%s' has been activated" % user_identifier)


_commands_name = [
    ('create_user',  CreateUserCommand),
    ('delete_user',  DeleteUserCommand),
    ('create_role',  CreateRoleCommand),
    ('add_role',     AddRoleCommand),
    ('remove_role',  RemoveRoleCommand),
    ('deactivate',   DeactivateUserCommand),
    ('activate',     ActivateUserCommand),
]


for name, cls in _commands_name:
    manager.add_command(name, cls())
