#!/bin/sh
pybabel extract -F babel.ini -k _gettext -k _ngettext -k lazy_gettext -o security.pot --project Flask-Security ../flask_security
pybabel compile -f -D security -d ../flask_security/translations/

