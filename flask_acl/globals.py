import functools

import werkzeug as wz
import flask.globals

# Proxy to the current app's AuthManager
current_auth = wz.local.LocalProxy(functools.partial(flask.globals._lookup_app_object, 'auth_manager'))
