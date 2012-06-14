
from functools import wraps

from flask import current_app as app, Response, request, abort

_default_http_auth_msg = """
    <h1>Unauthorized</h1>
    <p>The server could not verify that you are authorized to access the URL
    requested. You either supplied the wrong credentials (e.g. a bad password),
    or your browser doesn't understand how to supply the credentials required.</p>
    <p>In case you are allowed to request the document, please check your
    user-id and password and try again.</p>
    """


def _check_token():
    header_key = app.security.token_authentication_header
    args_key = app.security.token_authentication_key

    header_token = request.headers.get(header_key, None)
    token = request.args.get(args_key, header_token)

    try:
        app.security.datastore.find_user(authentication_token=token)
    except:
        return False

    return True


def _check_http_auth():
    auth = request.authorization or dict(username=None, password=None)

    try:
        user = app.security.datastore.find_user(email=auth.username)
    except:
        return False

    return app.security.pwd_context.verify(auth.password, user.password)


def http_auth_required(fn):
    headers = {'WWW-Authenticate': 'Basic realm="Login Required"'}

    @wraps(fn)
    def decorated(*args, **kwargs):
        if _check_http_auth():
            return fn(*args, **kwargs)

        return Response(_default_http_auth_msg, 401, headers)

    return decorated


def auth_token_required(fn):

    @wraps(fn)
    def decorated(*args, **kwargs):
        if _check_token():
            return fn(*args, **kwargs)

        abort(401)

    return decorated
