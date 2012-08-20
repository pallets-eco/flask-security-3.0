Features
========

Flask-Security allows you to quickly add common security mechanisms to your
Flask application. They include:


.. session-based-auth:

Session Based Authentication
----------------------------

Session based authentication is fulfilled entirely by the `Flask-Login`_
extension. Flask-Security handles the configuration of Flask-Login automatically
based on a few of its own configuration values and uses Flask-Login's
`alternative token`_ feature for remembering users when their session has
expired.


.. role-management:

Role/Identity Based Access
--------------------------

Flask-Security implements very basic role management out of the box. This means
that you can associate a high level role or multiple roles to any user. For
instance, you may assign roles such as `Admin`, `Editor`, `SuperUser`, or a
combination of said roles to a user. Access control is based on the role name
and all roles should be uniquely named. This feature is implemented using the
`Flask-Principal`_ extension. If you'd like to implement more granular access
control you can refer to the Flask-Princpal `documentation on this topic`_.


.. password-encryption:

Password Encryption
-------------------

Password encryption is enabled with `passlib`_. Passwords are stored in plain
text by default but you can easily configure the encryption algorithm and salt
value in your application configuration. You should **always use an encryption
algorithm** in your production environment. Bcrypt is a popular algorithm as
of writing this documentation. Bear in mind passlib does not assume which
algorithm you will choose and may require additional libraries to be installed.


.. basic-http-auth:

Basic HTTP Authentication
-------------------------

Basic HTTP authentication is achievable using a simple view method decorator.
This feature expects the incoming authentication information to identify a user
in the system. This means that the username must be equal to their email address.


.. token-authentication:

Token Authentication
--------------------

Token based authentication is enabled by retrieving the user auth token by
performing an HTTP POST with the authentication details as JSON data against the
authentication endpoint. A successful call to this endpoint will return the
user's ID and their authentication token. This token can be used in subsequent
requests to protected resources. The auth token is supplied in the request
through an HTTP header or query string parameter. By default the HTTP header
name is `X-Auth-Token` and the default query string parameter name is
`auth_token`. Authentication tokens are generated using the user's password.
Thus if the user changes his or her password their existing authentication token
will become invalid. A new token will need to be retrieved using the user's new
password.


.. email-confirmation:

Email Confirmation
------------------

If desired you can require that new users confirm their email address.
Flask-Security will send an email message to any new users with an confirmation
link. Upon navigating to the confirmation link, the user will be automatically
logged in. There is also view for resending a confirmation link to a given email
if the user happens to try to use an expired token or has lost the previous
email. Confirmation links can be configured to expire after a specified amount
of time.

.. password-recovery:

Password Reset/Recovery
-----------------------

Password reset and recovery is available for when a user forgets his or her
password. Flask-Security sends an email to the user with a link to a view which
they can reset their password. Once the password is reset they are automatically
logged in and can use the new password from then on. Password reset links  can
be configured to expire after a specified amount of time.


.. user-registration:

User Registration
-----------------

Flask-Security comes packaged with a basic user registration view. This view is
very simple and new users need only supply an email address and their password.
This view can be overrided if your registration process requires more fields.


.. login-tracking:

Login Tracking
--------------

Flask-Security can, if configured, keep track of basic login events and
statistics. They include:

* Last login date
* Current login date
* Last login IP address
* Current login IP address
* Total login count



.. _Flask-Login: http://packages.python.org/Flask-Login/
.. _alternative token: http://packages.python.org/Flask-Login/#alternative-tokens
.. _Flask-Principal: http://packages.python.org/Flask-Principal/
.. _documentation on this topic: http://packages.python.org/Flask-Principal/#granular-resource-protection
.. _passlib: http://packages.python.org/passlib/
