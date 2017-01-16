# -*- coding: utf-8 -*-
"""
    flask_security.ldap.datastore
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security ldap datastore module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

import six
import ldap

from ..datastore import SQLAlchemyUserDatastore
from ..utils import config_value


class LDAPUserDatastore(SQLAlchemyUserDatastore):
    def __init__(self, db, user_model, role_model):
        SQLAlchemyUserDatastore.__init__(self, db, user_model, role_model)

    def _get_ldap_con(self):
        con = ldap.initialize(six.u(config_value("LDAP_URI")),
                              bytes_mode=False)
        con.simple_bind_s(six.u(config_value("LDAP_BIND_DN")),
                          six.u(config_value("LDAP_BIND_PASSWORD")))
        return con

    def _close_ldap_con(self, con):
        con.unbind_s()

    def query_ldap_user(self, identifier):
        con = self._get_ldap_con()
        results = con.search_s(
            six.u(config_value("LDAP_BASE")), ldap.SCOPE_SUBTREE,
            six.u(config_value("LDAP_SEARCH_FILTER")).format(identifier)
        )
        self._close_ldap_con(con)
        if len(results) > 0:
            return results[0]
        else:
            return (None, None)

    def verify_password(self, user_dn, password):
        con = self._get_ldap_con()
        valid = True
        try:
            con.simple_bind_s(user_dn, password)
        except ldap.INVALID_CREDENTIALS:
            valid = False
        self._close_ldap_con(con)
        return valid
