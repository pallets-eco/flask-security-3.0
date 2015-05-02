# -*- coding: utf-8 -*-
"""
    test_hashing
    ~~~~~~~~~~~~

    hashing tests
"""

from pytest import raises

from flask_security.utils import verify_password, encrypt_password

from utils import authenticate, init_app_with_options


def test_verify_password_bcrypt(app, sqlalchemy_datastore):
    init_app_with_options(app, sqlalchemy_datastore, **{
        'SECURITY_PASSWORD_HASH': 'bcrypt',
        'SECURITY_PASSWORD_SALT': 'salty'
    })
    with app.app_context():
        assert verify_password('pass', encrypt_password('pass'))


def test_login_with_bcrypt_enabled(app, sqlalchemy_datastore):
    init_app_with_options(app, sqlalchemy_datastore, **{
        'SECURITY_PASSWORD_HASH': 'bcrypt',
        'SECURITY_PASSWORD_SALT': 'salty'
    })
    response = authenticate(app.test_client(), follow_redirects=True)
    assert b'Home Page' in response.data


def test_missing_hash_salt_option(app, sqlalchemy_datastore):
    with raises(RuntimeError):
        init_app_with_options(app, sqlalchemy_datastore, **{
            'SECURITY_PASSWORD_HASH': 'bcrypt',
        })
