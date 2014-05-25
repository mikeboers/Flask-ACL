from . import *

from flask_acl.globals import current_authz


class TestExtension(FlaskTestCase):

    def test_app_registry(self):
        self.assertIs(self.flask.authz_manager, self.authz)

    def test_current_authz(self):
        with self.flask.test_request_context('/'):
            self.assertIs(current_authz._get_current_object(), self.authz)

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
            self.assertEqual(rv.status_code, 200)
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


