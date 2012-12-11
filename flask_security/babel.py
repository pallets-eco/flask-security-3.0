
try:
    from flask.ext.babel import gettext, ngettext, lazy_gettext
    babel_installed = True
except ImportError:
    babel_installed = False
    def gettext(string, **variables):
        return string % variables

    def ngettext(singular, plural, num, **variables):
        return (singular if num == 1 else plural) % variables

    def lazy_gettext(string, **variables):
        return gettext(string, **variables)

_ = gettext
