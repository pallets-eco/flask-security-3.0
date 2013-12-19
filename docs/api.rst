API
===

Core
----
.. autoclass:: flask_security.core.Security
    :members:

.. data:: flask_security.core.current_user

   A proxy for the current user.


Protecting Views
----------------
.. autofunction:: flask_security.decorators.login_required

.. autofunction:: flask_security.decorators.roles_required

.. autofunction:: flask_security.decorators.roles_accepted

.. autofunction:: flask_security.decorators.http_auth_required

.. autofunction:: flask_security.decorators.auth_token_required


User Object Helpers
-------------------
.. autoclass:: flask_security.core.UserMixin
   :members:

.. autoclass:: flask_security.core.RoleMixin
   :members:

.. autoclass:: flask_security.core.AnonymousUser
   :members:


Datastores
----------
.. autoclass:: flask_security.datastore.UserDatastore
    :members:

.. autoclass:: flask_security.datastore.SQLAlchemyUserDatastore
    :members:
    :inherited-members:

.. autoclass:: flask_security.datastore.MongoEngineUserDatastore
    :members:
    :inherited-members:

.. autoclass:: flask_security.datastore.PeeweeUserDatastore
    :members:
    :inherited-members:


Utils
-----
.. autofunction:: flask_security.utils.login_user

.. autofunction:: flask_security.utils.logout_user

.. autofunction:: flask_security.utils.get_hmac

.. autofunction:: flask_security.utils.verify_password

.. autofunction:: flask_security.utils.verify_and_update_password

.. autofunction:: flask_security.utils.encrypt_password

.. autofunction:: flask_security.utils.url_for_security

.. autofunction:: flask_security.utils.get_within_delta

.. autofunction:: flask_security.utils.send_mail

.. autofunction:: flask_security.utils.get_token_status

Signals
-------
See the `Flask documentation on signals`_ for information on how to use these
signals in your code.

See the documentation for the signals provided by the Flask-Login and
Flask-Principal extensions. In addition to those signals, Flask-Security
sends the following signals.

.. data:: user_registered

   Sent when a user registers on the site. It is passed a dict with
   the `user` and `confirm_token`, the user being logged in and the
   (if so configured) the confirmation token issued.

.. data:: user_confirmed

   Sent when a user is confirmed. It is passed `user`, which is the
   user being confirmed.

.. data:: confirm_instructions_sent

   Sent when a user requests confirmation instructions. It is passed
   the `user`.

.. data:: login_instructions_sent

   Sent when passwordless login is used and user logs in. It is passed
   a dict with the `user` and `login_token`, the user being logged in
   and the (if so configured) the login token issued.

.. data:: password_reset

   Sent when a user completes a password reset. It is passed the
   `user`.

.. data:: password_changed

   Sent when a user completes a password change. It is passed the
   `user`.

.. data:: reset_password_instructions_sent

   Sent when a user requests a password reset. It is passed a dict
   with the `user` and `token`, the user being logged in and
   the (if so configured) the reset token issued.

All signals are also passed a `app` keyword argument, which is the
current application.

.. _Flask documentation on signals: http://flask.pocoo.org/docs/signals/
