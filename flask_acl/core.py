from __future__ import absolute_import

import functools
import logging
from pprint import pformat
from urllib import urlencode

import werkzeug as wz
import flask.globals
from flask import request
from flask.ext.login import current_user

from . import acl


log = logging.getLogger(__name__)




class _Redirect(Exception):
    pass

class AuthManager(object):

    login_view = 'login'

    def __init__(self, app=None):
        self._context_processors = []
        self._string_permission_sets = {}
        self._string_predicates = {}
        if app:
            self.init_app(app)

    def init_app(self, app):

        app.auth_manager = self

        # I suspect that Werkzeug has something for this already...
        app.errorhandler(_Redirect)(lambda r: flask.redirect(r.args[0]))

    def context_processor(self, func):
        """Register a function to build auth contexts.

        The function is called with no arguments, and must return a dict of new
        context material.

        """
        self._context_processors.append(func)

    def ACL(self, *acl, **options):
        def _ACL(func):

            func.__acl__ = acl

            @functools.wraps(func)
            def wrapped(*args, **kwargs):
                permission = 'http.' + request.method.lower()
                self.assert_can(permission, func, **options)
                return func(*args, **kwargs)

            return wrapped
        return _ACL

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
        context.update(acl.get_context(obj))
        context.update(kwargs)

        # log.debug('can context: %s' % pformat(context))
        for state, predicate, permissions in acl.iter_aces(obj):
            pred_match = predicate(**context)
            perm_match = permission in permissions
            # log.debug('can %s %r(%s) %r -> %s %s' % (
            #     'ALLOW' if state else 'DENY',
            #     predicate, pred_match,
            #     permissions,
            #     'ALLOW' if (pred_match and perm_match) else 'DENY', permission
            # ))
            if pred_match and perm_match:
                return state
        return None

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

        if not self.can(permission, obj, **kwargs):
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


