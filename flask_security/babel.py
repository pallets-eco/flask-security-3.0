# -*- coding: utf-8 -*-
"""
    flask_security.babel
    ~~~~~~~~~~~~~~~~~~~~

    I18N support for Flask-Security.
"""

from flask_babelex import Domain
from wtforms.i18n import messages_path

wtforms_domain = Domain(messages_path(), domain='wtforms')


class Translations(object):
    """Fixes WTForms translation support and uses wtforms translations."""

    def gettext(self, string):
        return wtforms_domain.gettext(string)

    def ngettext(self, singular, plural, n):
        return wtforms_domain.ngettext(singular, plural, n)
