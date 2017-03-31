# -*- coding: utf-8 -*-
"""
    test_hashing
    ~~~~~~~~~~~~

    hashing tests
"""

from pytest import raises
from utils import authenticate, init_app_with_options

from flask_security.utils import encrypt_password, verify_password


def test_verify_password_bcrypt_double_hash(app, sqlalchemy_datastore):
    init_app_with_options(app, sqlalchemy_datastore, **{
        'SECURITY_PASSWORD_HASH': 'bcrypt',
        'SECURITY_PASSWORD_SALT': 'salty',
        'SECURITY_PASSWORD_SINGLE_HASH': False,
    })
    with app.app_context():
        assert verify_password('pass', encrypt_password('pass'))


def test_verify_password_bcrypt_single_hash(app, sqlalchemy_datastore):
    init_app_with_options(app, sqlalchemy_datastore, **{
        'SECURITY_PASSWORD_HASH': 'bcrypt',
        'SECURITY_PASSWORD_SALT': None,
        'SECURITY_PASSWORD_SINGLE_HASH': True,
    })
    with app.app_context():
        assert verify_password('pass', encrypt_password('pass'))


def test_login_with_bcrypt_enabled(app, sqlalchemy_datastore):
    init_app_with_options(app, sqlalchemy_datastore, **{
        'SECURITY_PASSWORD_HASH': 'bcrypt',
        'SECURITY_PASSWORD_SALT': 'salty',
        'SECURITY_PASSWORD_SINGLE_HASH': False,
    })
    response = authenticate(app.test_client(), follow_redirects=True)
    assert b'Home Page' in response.data


def test_missing_hash_salt_option(app, sqlalchemy_datastore):
    with raises(RuntimeError):
        init_app_with_options(app, sqlalchemy_datastore, **{
            'SECURITY_PASSWORD_HASH': 'bcrypt',
            'SECURITY_PASSWORD_SINGLE_HASH': False,
        })


def test_single_hash_should_have_no_salt(app, sqlalchemy_datastore):
    with raises(RuntimeError):
        init_app_with_options(app, sqlalchemy_datastore, **{
            'SECURITY_PASSWORD_HASH': 'bcrypt',
            'SECURITY_PASSWORD_SALT': 'salty',
            'SECURITY_PASSWORD_SINGLE_HASH': True,
        })
