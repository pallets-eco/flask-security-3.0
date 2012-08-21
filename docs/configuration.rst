Configuration
=============

Flask-Security configuration options.

* :attr:`SECURITY_URL_PREFIX`: Specifies the URL prefix for the Security
  blueprint.
* :attr:`SECURITY_FLASH_MESSAGES`: Specifies wether or not to flash messages
  during security mechanisms.
* :attr:`SECURITY_PASSWORD_HASH`: Specifies the encryption method to use. e.g.:
  plaintext, bcrypt, etc.
* :attr:`SECURITY_AUTH_URL`: Specifies the URL to to handle authentication.
* :attr:`SECURITY_LOGOUT_URL`: Specifies the URL to process a logout request.
* :attr:`SECURITY_REGISTER_URL`: Specifies the URL for user registrations.
* :attr:`SECURITY_RESET_URL`: Specifies the URL for password resets.
* :attr:`SECURITY_CONFIRM_URL`: Specifies the URL for account confirmations.
* :attr:`SECURITY_LOGIN_VIEW`: Specifies the URL to redirect to when
  authentication is required.
* :attr:`SECURITY_CONFIRM_ERROR_VIEW`: Specifies the URL to redirect to when
  an confirmation error occurs.
* :attr:`SECURITY_POST_LOGIN_VIEW`: Specifies the URL to redirect to after a
  user logins in.
* :attr:`SECURITY_POST_LOGOUT_VIEW`: Specifies the URL to redirect to after a
  user logs out.
* :attr:`SECURITY_POST_FORGOT_VIEW`: Specifies the URL to redirect to after a
  user requests password reset instructions.
* :attr:`SECURITY_RESET_PASSWORD_ERROR_VIEW`: Specifies the URL to redirect to
  after an error occurs during the password reset process.
* :attr:`SECURITY_POST_REGISTER_VIEW`: Specifies the URL to redirect to after a
  user successfully registers.
* :attr:`SECURITY_POST_CONFIRM_VIEW`: Specifies the URL to redirect to after a
  user successfully confirms their account.
* :attr:`SECURITY_UNAUTHORIZED_VIEW`: Specifies the URL to redirect to when a
  user attempts to access a view they don't have permission to view.
* :attr:`SECURITY_CONFIRMABLE`: Enables confirmation features. Defaults to
  `False`.
* :attr:`SECURITY_REGISTERABLE`: Enables user registration features. Defaults to
  `False`.
* :attr:`SECURITY_RECOVERABLE`: Enables password reset/recovery features.
  Defaults to `False`.
* :attr:`SECURITY_TRACKABLE`: Enables login tracking features. Defaults to
  `False`.
* :attr:`SECURITY_CONFIRM_EMAIL_WITHIN`: Specifies the amount of time a user
  has to confirm their account/email. Default is `5 days`.
* :attr:`SECURITY_RESET_PASSWORD_WITHIN`: Specifies the amount of time a user
  has to reset their password. Default is `5 days`.
* :attr:`SECURITY_LOGIN_WITHOUT_CONFIRMATION`: Specifies if users can login
  without first confirming their accounts. Defaults to `False`
* :attr:`SECURITY_EMAIL_SENDER`: Specifies the email address to send emails on
  behalf of. Defaults to `no-reply@localhost`.
* :attr:`SECURITY_TOKEN_AUTHENTICATION_KEY`: Specifies the query string argument
  to use during token authentication. Defaults to `auth_token`.
* :attr:`SECURITY_TOKEN_AUTHENTICATION_HEADER`: Specifies the header name to use
  during token authentication. Defaults to `X-Auth-Token`.
* :attr:`SECURITY_CONFIRM_SALT`: Specifies the salt value to use for account
  confirmation tokens. Defaults to `confirm-salt`.
* :attr:`SECURITY_RESET_SALT`: Specifies the salt value to use for password
  reset tokens. Defaults to `reset-salt`.
* :attr:`SECURITY_AUTH_SALT`: Specifies the salt value to use for token based
  authentication tokens. Defaults to `auth-salt`.
* :attr:`SECURITY_DEFAULT_HTTP_AUTH_REALM`: Specifies the default basic HTTP
  authentication realm. Defaults to `Login Required`.