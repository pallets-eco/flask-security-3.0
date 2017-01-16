# -*- coding: utf-8 -*-
"""
    test_script
    ~~~~~~~~~~~~~~

    Script command tests
"""

import pytest
from flask_script import Manager
import flask_security.script as s

from utils import init_app_with_options


commands = [
    ('create-user', s.CreateUserCommand),
    ('create-role', s.CreateRoleCommand),
    ('remove-role', s.RemoveRoleCommand),
    ('add-role', s.AddRoleCommand),
    ('activate-user', s.ActivateUserCommand),
    ('deactivate-user', s.DeactivateUserCommand),
]


@pytest.fixture
def manager(app, datastore):
    init_app_with_options(app, datastore)

    m = Manager(app)
    for name, cmd in commands:
        m.add_command(name, cmd)

    return m


@pytest.mark.parametrize('command', [x for (x, y) in commands])
def test_exits_nonzero_without_arguments(manager, datastore, command):
    '''All the commands so far require at least one argument, so should
    exit(nonzero) cleanly if no arguments are provided.'''

    with pytest.raises(SystemExit) as excinfo:
        manager.handle('manage', args=(command, ))
    assert excinfo.value.code != 0


def test_create_active_user(manager, datastore):
    manager.handle('manage', args=(
        'create-user',
        '--email', 'test@example.com',
        '--password', 'too many cooks',
        '--active'))
    user = datastore.find_user(email='test@example.com')
    assert user is not None
    assert user.active


def test_create_existing_user(manager, datastore):
    with pytest.raises(SystemExit) as excinfo:
        manager.handle('manage', args=(
            'create-user',
            '--email', 'tiya@lp.com',
            '--password', 'too many cooks',
            '--active'))

    assert excinfo.value.code != 0


def test_toggle_user_active(manager, datastore):
    email = 'tiya@lp.com'
    user = datastore.find_user(email=email)
    assert user is not None
    assert not user.active

    manager.handle('manage', args=(
        'activate-user',
        '--user', email,
    ))
    user = datastore.find_user(email=email)
    assert user is not None
    assert user.active

    manager.handle('manage', args=(
        'deactivate-user',
        '--user', email,
    ))
    user = datastore.find_user(email=email)
    assert user is not None
    assert not user.active


def test_create_role(manager, datastore):
    assert datastore.find_role('cook') is None
    manager.handle('manage', args=(
        'create-role',
        '--name', 'cook',
        '--desc', 'broth artisans',
    ))
    role = datastore.find_role('cook')
    assert role is not None
    assert role.description == 'broth artisans'


def test_toggle_role(manager, datastore):
    email = 'tiya@lp.com'
    role = 'admin'

    user = datastore.find_user(email=email)
    assert not user.has_role(role)

    manager.handle('manage', args=(
        'add-role',
        '--user', email,
        '--role', role,
    ))
    user = datastore.find_user(email=email)
    assert user.has_role(role)

    manager.handle('manage', args=(
        'remove-role',
        '--user', email,
        '--role', role,
    ))
    user = datastore.find_user(email=email)
    assert not user.has_role(role)
