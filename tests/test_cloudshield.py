"""
CloudShield Test Suite
Validates application initialization, routes, authentication, and PDF report generation.
"""
import unittest
from app import create_app
from models import db, User

class TestCloudShield(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing')
        self.client = self.app.test_client()
        with self.app.app_context():
            db.create_all()
            if not User.query.filter_by(username='test_admin').first():
                admin = User(username='test_admin', email='admin@test.local', role='admin')
                admin.set_password('TestAdmin1234!')
                db.session.add(admin)
                db.session.commit()

    def test_login_page(self):
        res = self.client.get('/auth/login')
        self.assertEqual(res.status_code, 200)
        self.assertIn(b'CloudShield', res.data)

    def test_routes_logged_in(self):
        # Login
        res = self.client.post('/auth/login', data={
            'username': 'test_admin',
            'password': 'TestAdmin1234!'
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)

        routes = [
            '/dashboard/',
            '/resources/',
            '/resources/create',
            '/posture/',
            '/events/',
            '/alerts/',
            '/incidents/',
            '/incidents/create',
            '/forensics/',
            '/evidence/',
            '/evidence/upload',
            '/reports/',
            '/audit/',
            '/settings/',
            '/settings/users/create',
            '/settings/profile',
            '/response/',
        ]
        for r in routes:
            with self.subTest(route=r):
                res = self.client.get(r)
                self.assertEqual(res.status_code, 200, f"Route {r} failed with {res.status_code}")

    def test_pdf_reports(self):
        # Login
        self.client.post('/auth/login', data={
            'username': 'test_admin',
            'password': 'TestAdmin1234!'
        }, follow_redirects=True)

        res = self.client.get('/reports/posture')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, 'application/pdf')

        res = self.client.get('/reports/events?days=1')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, 'application/pdf')

        res = self.client.get('/reports/evidence-integrity')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, 'application/pdf')

if __name__ == '__main__':
    unittest.main()
