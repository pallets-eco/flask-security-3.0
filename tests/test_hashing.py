# -*- coding: utf-8 -*-
"""
    test_hashing
    ~~~~~~~~~~~~

    hashing tests
"""

from pytest import raises

from flask_security.utils import verify_password, verify_and_update_password, encrypt_password, \
        get_hmac

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


def test_passlib_compatibility(app, sqlalchemy_datastore):
    init_app_with_options(app, sqlalchemy_datastore, **{
        'SECURITY_PASSWORD_HASH': 'bcrypt',
        'SECURITY_PASSWORD_SALT': 'salty'
    })
    with app.app_context():
        # encrypt solely with passlib
        enc = app.extensions['security'].pwd_context.encrypt('pass')
        assert verify_password('pass', enc)

        user = app.security.datastore.create_user(password=enc)
        assert verify_and_update_password('pass', user)
        assert user.password == enc

        # passlib should be able to verify our encryption
        enc = encrypt_password('pass')
        assert app.extensions['security'].pwd_context.verify('pass', enc)

        # ensure we can verify legacy HMAC encryption
        enc = encrypt_password(get_hmac('pass'))
        assert verify_password('pass', enc)

        user = app.security.datastore.create_user(password=enc)
        assert verify_and_update_password('pass', user)
        assert user.password != enc
