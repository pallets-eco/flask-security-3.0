from flask_babelex import Domain
from flask_security import translations
from wtforms.i18n import messages_path


class CustomDomain(Domain):
    def __init__(self):
        super(CustomDomain, self).__init__(
            translations.__path__[0], domain='security')

domain = CustomDomain()

gettext = domain.gettext
ngettext = domain.ngettext
lazy_gettext = domain.lazy_gettext


wtforms_domain = Domain(messages_path(), domain='wtforms')


class Translations(object):
    ''' Fixes WTForms translation support and uses wtforms translations '''

    def gettext(self, string):
        return wtforms_domain.gettext(string)

    def ngettext(self, singular, plural, n):
        return wtforms_domain.ngettext(singular, plural, n)
