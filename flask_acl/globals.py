import functools

import werkzeug as wz
from flask import current_app

# Proxy to the current app's AuthManager
current_authz = wz.local.LocalProxy(lambda: current_app.authz_manager)
