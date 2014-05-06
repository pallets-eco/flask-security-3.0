# -*- coding: utf-8 -*-
"""
    test_trackable
    ~~~~~~~~~~~~~~

    Trackable tests
"""

import pytest

from utils import authenticate, logout

pytestmark = pytest.mark.trackable()


def test_trackable_flag(app, client):
    e = 'matt@lp.com'
    authenticate(client, email=e)
    logout(client)
    authenticate(client, email=e, headers={'X-Forwarded-For': '127.0.0.1'})

    with app.app_context():
        user = app.security.datastore.find_user(email=e)
        assert user.last_login_at is not None
        assert user.current_login_at is not None
        assert user.last_login_ip == 'untrackable'
        assert user.current_login_ip == '127.0.0.1'
        assert user.login_count == 2
