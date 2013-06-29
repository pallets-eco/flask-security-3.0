# -*- coding: utf-8 -*-
"""
flask.ext.security.inline
~~~~~~~~~~~~~~~~~~~~~~~~

Flask-Security inline forms

:copyright: (c) 2013 by Thrisp/Huratta
:license: MIT, see LICENSE for more details.
"""
from flask import current_app, get_template_attribute
from werkzeug import LocalProxy
from .utils import url_for_security, config_value

_security = LocalProxy(lambda: current_app.extensions['security'])


def _ctx(endpoint):
    return _security._run_ctx_processor(endpoint)


def get_inline_macro(mwhere, mname):
    return get_template_attribute(mwhere, mname)


def inline_form(which):
    m = config_value('inline_{}'.format(which))
    mwhere, mname, mform = m[0], m[1], m[2]
    return get_inline_macro(mwhere, mname)(url_for_security,
                                           form=mform(),
                                           **_ctx(which))
