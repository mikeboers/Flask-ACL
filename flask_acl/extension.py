from __future__ import absolute_import

import functools
import logging
from pprint import pformat
from urllib import urlencode

import flask
from flask import request, current_app
from flask.ext.login import current_user
import werkzeug as wz

from flask_acl.core import iter_object_acl, get_object_context, check
from flask_acl.permission import default_permission_sets
from flask_acl.predicate import default_predicates


log = logging.getLogger(__name__)


class _Redirect(Exception):
    pass


class ACLManager(object):

    """Flask extension for registration and checking of ACLs on routes and other objects."""

    login_view = 'login'

    def __init__(self, app=None):
        self._context_processors = []
        self.permission_sets = default_permission_sets.copy()
        self.predicates = default_predicates.copy()
        if app:
            self.init_app(app)

    def init_app(self, app):

        app.acl_manager = self
        app.extensions['acl'] = self

        app.config.setdefault('ACL_ROUTE_DEFAULT_STATE', True)

        # I suspect that Werkzeug has something for this already...
        app.errorhandler(_Redirect)(lambda r: flask.redirect(r.args[0]))


    def predicate(self, name, predicate=None):
        """Define a new predicate (direclty, or as a decorator).

        E.g.::

            @authz.predicate
            def ROOT(user, **ctx):
                # return True of user is in group "wheel".
        """
        if predicate is None:
            return functools.partial(self.predicate, name)
        self.predicates[name] = predicate
        return predicate

    def permission_set(self, name, permission_set=None):
        """Define a new permission set (directly, or as a decorator)."""
        if permission_set is None:
            return functools.partial(self.permission_set, name)
        self.permission_sets[name] = permission_set
        return permission_set


    def context_processor(self, func):
        """Register a function to build authorization contexts.

        The function is called with no arguments, and must return a dict of new
        context material.

        """
        self._context_processors.append(func)

    def route_acl(self, *acl, **options):
        """Decorator to attach an ACL to a route.

        E.g::
        
            @app.route('/url/to/view')
            @authz.route_acl('''
                ALLOW WHEEL ALL
                DENY  ANY   ALL
            ''')
            def my_admin_function():
                pass

        """

        def _route_acl(func):

            func.__acl__ = acl

            @functools.wraps(func)
            def wrapped(*args, **kwargs):
                permission = 'http.' + request.method.lower()
                local_opts = options.copy()
                local_opts.setdefault('default', current_app.config['ACL_ROUTE_DEFAULT_STATE'])
                self.assert_can(permission, func, **local_opts)
                return func(*args, **kwargs)

            return wrapped
        return _route_acl

    def can(self, permission, obj, **kwargs):
        """Check if we can do something with an object.

        :param permission: The permission to look for.
        :param obj: The object to check the ACL of.
        :param **kwargs: The context to pass to predicates.

        >>> auth.can('read', some_object)
        >>> auth.can('write', another_object, group=some_group)

        """

        context = {'user': current_user}
        for func in self._context_processors:
            context.update(func())
        context.update(get_object_context(obj))
        context.update(kwargs)
        return check(permission, iter_object_acl(obj), **context)

    def assert_can(self, permission, obj, **kwargs):
        """Make sure we have a permission, or abort the request.

        :param permission: The permission to look for.
        :param obj: The object to check the ACL of.
        :param flash: The message to flask if denied (keyword only).
        :param stealth: Abort with a 404? (keyword only).
        :param **kwargs: The context to pass to predicates.

        """
        flash_message = kwargs.pop('flash', None)
        stealth = kwargs.pop('stealth', False)
        default = kwargs.pop('default', None)

        res = self.can(permission, obj, **kwargs)
        res = default if res is None else res

        if not res:
            if flash_message and not stealth:
                flask.flash(flash_message, 'danger')
            if current_user.is_authenticated():
                if flash_message is not False:
                    flask.flash(flash_message or 'You are not permitted to "%s" this resource' % permission)
                flask.abort(403)
            elif not stealth and self.login_view:
                if flash_message is not False:
                    flask.flash(flash_message or 'Please login for access.')
                raise _Redirect(flask.url_for(self.login_view) + '?' + urlencode(dict(next=
                    flask.request.script_root + flask.request.path
                )))
            else:
                flask.abort(404)

    def can_route(self, endpoint, method=None, **kwargs):
        """Make sure we can route to the given endpoint or url.

        This checks for `http.get` permission (or other methods) on the ACL of
        route functions, attached via the `ACL` decorator.

        :param endpoint: A URL or endpoint to check for permission to access.
        :param method: The HTTP method to check; defaults to `'GET'`.
        :param **kwargs: The context to pass to predicates.

        """

        view = flask.current_app.view_functions.get(endpoint)
        if not view:
            endpoint, args = flask._request_ctx.top.match(endpoint)
            view = flask.current_app.view_functions.get(endpoint)
        if not view:
            return False

        return self.can('http.' + (method or 'GET').lower(), view, **kwargs)

