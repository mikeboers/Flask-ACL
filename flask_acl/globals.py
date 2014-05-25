import functools

import werkzeug as wz
from flask import current_app

#: Proxy to the current Flask app's :class:`.ACLManager`.
current_acl_manager = wz.local.LocalProxy(lambda: current_app.acl_manager)
