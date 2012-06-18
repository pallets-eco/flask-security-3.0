# -*- coding: utf-8 -*-
"""
    flask.ext.security.signals
    ~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security signals module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

import blinker


signals = blinker.Namespace()

user_registered = signals.signal("user-registered")

user_confirmed = signals.signal("user-confirmed")

confirm_instructions_sent = signals.signal("confirm-instructions-sent")

password_reset = signals.signal("password-reset")

password_reset_requested = signals.signal("password-reset-requested")

reset_instructions_sent = signals.signal("reset-instructions-sent")
