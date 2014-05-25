from . import *

from flask_acl.globals import current_acl_manager


class TestExtension(FlaskTestCase):

    def test_app_registry(self):
        self.assertIs(self.flask.acl_manager, self.authz)

    def test_current_acl_manager(self):
        with self.flask.test_request_context('/'):
            self.assertIs(current_acl_manager._get_current_object(), self.authz)

    def test_route_default(self):
        @self.flask.route('/default_allow')
        @self.authz.route_acl('')
        def default_allow():
            return 'allowed'
        with self.client:
            rv = self.client.get('/default_allow')
            self.assertEqual(rv.status_code, 200)
            self.assertEqual(rv.data, 'allowed')

    def test_route_default_deny(self):
        self.flask.config['ACL_ROUTE_DEFAULT_STATE'] = False
        @self.flask.route('/default_deny')
        @self.authz.route_acl('')
        def default_deny():
            return 'allowed'
        with self.client:
            rv = self.client.get('/default_deny', follow_redirects=True)
            self.assertEqual(rv.status_code, 401)
            self.assertEqual(rv.data, 'please login')

    def test_route_allow(self):

        @self.flask.route('/allow')
        @self.authz.route_acl('''
            ALLOW ANY ALL
        ''')
        def allow():
            return 'allowed'

        with self.client:
            rv = self.client.get('/allow')
            self.assertEqual(rv.status_code, 200)
            self.assertEqual(rv.data, 'allowed')

    def test_route_deny(self):

        @self.flask.route('/deny')
        @self.authz.route_acl('''
            DENY ANY ALL
        ''')
        def deny():
            return 'allowed'

        with self.client:
            rv = self.client.get('/deny', follow_redirects=True)
            self.assertEqual(rv.status_code, 401)
            self.assertEqual(rv.data, 'please login')

    def test_route_deny_stealth(self):

        @self.flask.route('/stealth')
        @self.authz.route_acl('''
            DENY ANY ALL
        ''', stealth=True)
        def stealth():
            return 'allowed'

        with self.client:
            rv = self.client.get('/stealth')
            self.assertEqual(rv.status_code, 404)


