# -*- coding: utf-8 -*-
"""
    test_trackable
    ~~~~~~~~~~~~~~

    Trackable tests
"""

from utils import authenticate, logout, init_app_with_options


def test_trackable_flag(app, sqlalchemy_datastore):
    init_app_with_options(app, sqlalchemy_datastore, **{
        'SECURITY_TRACKABLE': True
    })

    client = app.test_client()

    e = 'matt@lp.com'
    authenticate(client, email=e)
    logout(client)
    authenticate(client, email=e)

    with app.app_context():
        user = app.security.datastore.find_user(email=e)
        assert user.last_login_at is not None
        assert user.current_login_at is not None
        assert user.last_login_ip == 'untrackable'
        assert user.current_login_ip == 'untrackable'
        assert user.login_count == 2
