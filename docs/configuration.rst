Configuration
=============

The following configuration values are used by Flask-Security:

Core
--------------

.. tabularcolumns:: |p{6.5cm}|p{8.5cm}|

======================================== =======================================
``SECURITY_BLUEPRINT_NAME``              Specifies the name for the
                                         Flask-Security blueprint. Defaults to
                                         ``security``.
``SECURITY_URL_PREFIX``                  Specifies the URL prefix for the
                                         Flask-Security blueprint. Defaults to
                                         ``None``.
``SECURITY_FLASH_MESSAGES``              Specifies wether or not to flash
                                         messages during security procedures.
                                         Defaults to ``True``.
``SECURITY_PASSWORD_HASH``               Specifies the password hash algorith to
                                         use when encrypting and decrypting
                                         passwords. Recommended values for
                                         production systems are ``bcrypt``,
                                         ``sha512_crypt``, or ``pbkdf2_sha512``.
                                         Defaults to ``plaintext``.
``SECURITY_PASSWORD_SALT``               Specifies the HMAC salt. This is only
                                         used if the password hash type is set
                                         to something other than plain text.
                                         Defaults to ``None``.
``SECURITY_EMAIL_SENDER``                Specifies the email address to send
                                         emails as. Defaults to
                                         ``no-reply@localhost``.
``SECURITY_TOKEN_AUTHENTICATION_KEY``    Specifies the query sting parameter to
                                         read when using token authentication.
                                         Defaults to ``auth_token``.
``SECURITY_TOKEN_AUTHENTICATION_HEADER`` Specifies the HTTP header to read when
                                         using token authentication. Defaults to
                                         ``Authentication-Token``.
``SECURITY_DEFAULT_HTTP_AUTH_REALM``     Specifies the default authentication
                                         realm when using basic HTTP auth.
                                         Defaults to ``Login Required``
======================================== =======================================


URLs and Views
--------------

.. tabularcolumns:: |p{6.5cm}|p{8.5cm}|

=============================== ================================================
``SECURITY_LOGIN_URL``          Specifies the login URL. Defaults to ``/login``.
``SECURITY_LOGOUT_URL``         Specifies the logout URL. Defaults to
                                ``/logout``.
``SECURITY_REGISTER_URL``       Specifies the register URL. Defaults to
                                ``/register``.
``SECURITY_RESET_URL``          Specifies the password reset URL. Defaults to
                                ``/reset``.
``SECURITY_CONFIRM_URL``        Specifies the email confirmation URL. Defaults
                                to ``/confirm``.
``SECURITY_POST_LOGIN_VIEW``    Specifies the default view to redirect to after
                                a user logs in. This value can be set to a URL
                                or an endpoint name. Defaults to ``/``.
``SECURITY_POST_LOGOUT_VIEW``   Specifies the default view to redirect to after
                                a user logs out. This value can be set to a URL
                                or an endpoint name. Defaults to ``/``.
``SECURITY_CONFIRM_ERROR_VIEW`` Specifies the view to redirect to if a
                                confirmation error occurs. This value can be set
                                to a URL or an endpoint name. If this value is
                                ``None`` the user is presented the default view
                                to resend a confirmation link. Defaults to
                                ``None``.
``SECURITY_POST_REGISTER_VIEW`` Specifies the view to redirect to after a user
                                successfully registers. This value can be set to
                                a URL or an endpoint name. If this value is
                                ``None`` the user is redirected to the value of
                                ``SECURITY_POST_LOGIN_VIEW``. Defaults to
                                ``None``.
``SECURITY_POST_CONFIRM_VIEW``  Specifies the view to redirect to after a user
                                successfully confirms their email. This value
                                can be set to a URL or an endpoint name. If this
                                value is ``None`` the user is redirected  to the
                                value of ``SECURITY_POST_LOGIN_VIEW``. Defaults
                                to ``None``.
``SECURITY_POST_RESET_VIEW``    Specifies the view to redirect to after a user
                                successfully resets their password. This value
                                can be set to a URL or an endpoint name. If this
                                value is ``None`` the user is redirected  to the
                                value of ``SECURITY_POST_LOGIN_VIEW``. Defaults to
                                ``None``.
``SECURITY_UNAUTHORIZED_VIEW``  Specifies the view to redirect to if a user
                                attempts to access a URL/endpoint that they do
                                not have permission to access. If this value is
                                ``None`` the user is presented with a default
                                HTTP 403 response. Defaults to ``None``.
=============================== ================================================


Template Paths
--------------

.. tabularcolumns:: |p{6.5cm}|p{8.5cm}|

======================================== =======================================
``SECURITY_FORGOT_PASSWORD_TEMPLATE``    Specifies the path to the template for
                                         the forgot password page. Defaults to
                                         ``security/forgot_password.html``.
``SECURITY_LOGIN_USER_TEMPLATE``         Specifies the path to the template for
                                         the user login page. Defaults to
                                         ``security/login_user.html``.
``SECURITY_REGISTER_USER_TEMPLATE``      Specifies the path to the template for
                                         the user registration page. Defaults to
                                         ``security/register_user.html``.
``SECURITY_RESET_PASSWORD_TEMPLATE``     Specifies the path to the template for
                                         the reset password page. Defaults to
                                         ``security/reset_password.html``.
``SECURITY_SEND_CONFIRMATION_TEMPLATE``  Specifies the path to the template for
                                         the resend confirmation instructions
                                         page. Defaults to
                                         ``security/send_confirmation.html``.
``SECURITY_SEND_LOGIN_TEMPLATE``         Specifies the path to the template for
                                         the send login instructions page for
                                         passwordless logins. Defaults to
                                         ``security/send_login.html``.
======================================== =======================================


Feature Flags
-------------

.. tabularcolumns:: |p{6.5cm}|p{8.5cm}|

========================= ======================================================
``SECURITY_CONFIRMABLE``  Specifies if users are required to confirm their email
                          address when registering a new account. If this value
                          is `True` Flask-Security creates an endpoint to handle
                          confirmations and requests to resend confirmation
                          instructions. The URL for this endpoint is specified
                          by the ``SECURITY_CONFIRM_URL`` configuration option.
                          Defaults to ``False``.
``SECURITY_REGISTERABLE`` Specifies if Flask-Security should create a user
                          registration endpoint. The URL for this endpoint is
                          specified by the ``SECURITY_REGISTER_URL``
                          configuration option. Defaults to ``False``.
``SECURITY_RECOVERABLE``  Specifies if Flask-Security should create a password
                          reset/recover endpoint. The URL for this endpoint is
                          specified by the ``SECURITY_RESET_URL`` configuration
                          option. Defaults to ``False``.
``SECURITY_TRACKABLE``    Specifies if Flask-Security should track basic user
                          login statistics. If set to ``True`` ensure your
                          models have the required fields/attribues. Defaults to
                          ``False``
``SECURITY_PASSWORDLESS`` Specifies if Flask-Security should enable the
                          passwordless login feature. If set to ``True`` users
                          are not required to enter a password to login but are
                          sent an email with a login link. This feature is
                          experimental and should be used with caution. Defaults
                          to ``False``.
========================= ======================================================

Email
----------

.. tabularcolumns:: |p{6.5cm}|p{8.5cm}|

=========================================== ====================================
``SECURITY_EMAIL_SUBJECT_REGISTER``         Sets the subject for the
                                            confirmation email. Defaults to
                                            ``Welcome``
``SECURITY_EMAIL_SUBJECT_PASSWORDLESS``     Sets the subject for the
                                            passwordless feature. Defaults to
                                            ``Login instructions``
``SECURITY_EMAIL_SUBJECT_PASSWORD_NOTICE``  Sets subject for the password
                                            notice. Defaults to
                                            ``Your password has been reset``
``SECURITY_EMAIL_SUBJECT_PASSWORD_RESET``   Sets the subject for the password
                                            reset. Defaults to
                                            ``Password reset instructions``
``SECURITY_EMAIL_SUBJECT_CONFIRM``          Sets the subject for the email
                                            confirmation message. Defaults to
                                            ``Please confirm your email``
=========================================== ====================================

Miscellaneous
-------------

.. tabularcolumns:: |p{6.5cm}|p{8.5cm}|

======================================= ========================================
``SECURITY_SEND_REGISTER_EMAIL``        Specifies whether registration email is
                                        sent. Defaults to ``True``.
``SECURITY_CONFIRM_EMAIL_WITHIN``       Specifies the amount of time a user has
                                        before their confirmation link expires.
                                        Always pluralized the time unit for this
                                        value. Defaults to ``5 days``.
``SECURITY_RESET_PASSWORD_WITHIN``      Specifies the amount of time a user has
                                        before their password reset link
                                        expires. Always pluralized the time unit
                                        for this value. Defaults to ``5 days``.
``SECURITY_LOGIN_WITHIN``               Specifies the amount of time a user has
                                        before a login link expires. This is
                                        only used when the passwordless login
                                        feature is enabled. Always pluralized
                                        the time unit for this value. Defaults
                                        to ``1 days``.
``SECURITY_LOGIN_WITHOUT_CONFIRMATION`` Specifies if a user may login before
                                        confirming their email when the value
                                        of ``SECURITY_CONFIRMABLE`` is set to
                                        ``True``. Defaults to ``False``.
``SECURITY_CONFIRM_SALT``               Specifies the salt value when generating
                                        confirmation links/tokens. Defaults to
                                        ``confirm-salt``.
``SECURITY_RESET_SALT``                 Specifies the salt value when generating
                                        password reset links/tokens. Defaults to
                                        ``reset-salt``.
``SECURITY_LOGIN_SALT``                 Specifies the salt value when generating
                                        login links/tokens. Defaults to
                                        ``login-salt``.
``SECURITY_REMEMBER_SALT``              Specifies the salt value when generating
                                        remember tokens. Remember tokens are
                                        used instead of user ID's as it is more
                                        secure. Defaults to ``remember-salt``.
``SECURITY_DEFAULT_REMEMBER_ME``        Specifies the default "remember me"
                                        value used when logging in a user.
                                        Defaults to ``False``.
======================================= ========================================
