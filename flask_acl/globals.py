import functools

import werkzeug as wz
from flask import current_app

# Proxy to the current app's AuthManager
current_auth = wz.local.LocalProxy(lambda: current_app.auth_manager)
