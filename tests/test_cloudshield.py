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

    def test_user_creation_and_role_alteration(self):
        # Login as admin
        self.client.post('/auth/login', data={
            'username': 'test_admin',
            'password': 'TestAdmin1234!'
        }, follow_redirects=True)

        # 1. Invalid email should fail
        res = self.client.post('/settings/users/create', data={
            'username': 'sec_user1',
            'email': 'not-an-email',
            'password': 'SecurePassword123!',
            'role': 'analyst'
        }, follow_redirects=True)
        self.assertIn(b'valid email', res.data)

        # 2. Weak password (missing symbol or uppercase or numbers) should fail
        res = self.client.post('/settings/users/create', data={
            'username': 'sec_user2',
            'email': 'sec2@test.local',
            'password': 'alllowercaseonly123',
            'role': 'analyst'
        }, follow_redirects=True)
        self.assertIn(b'uppercase', res.data)

        res = self.client.post('/settings/users/create', data={
            'username': 'sec_user3',
            'email': 'sec3@test.local',
            'password': 'NO_NUMBERS_OR_LOWER!',
            'role': 'analyst'
        }, follow_redirects=True)
        self.assertIn(b'lowercase', res.data)

        # 3. Valid user creation should succeed
        res = self.client.post('/settings/users/create', data={
            'username': 'sec_analyst_new',
            'email': 'analyst_new@test.local',
            'password': 'StrongPassword2026!#',
            'role': 'analyst'
        }, follow_redirects=True)
        self.assertIn(b'successfully provisioned', res.data)

        with self.app.app_context():
            u = User.query.filter_by(username='sec_analyst_new').first()
            self.assertIsNotNone(u)
            self.assertEqual(u.role, 'analyst')
            user_id = u.id

        # 4. Alter user and role via /settings/users/<id>/edit
        res = self.client.post(f'/settings/users/{user_id}/edit', data={
            'username': 'sec_analyst_altered',
            'email': 'altered_analyst@test.local',
            'role': 'admin',
            'password': ''  # keep password
        }, follow_redirects=True)
        self.assertIn(b'successfully updated', res.data)

        with self.app.app_context():
            u = User.query.get(user_id)
            self.assertEqual(u.username, 'sec_analyst_altered')
            self.assertEqual(u.role, 'admin')
            self.assertEqual(u.email, 'altered_analyst@test.local')

    def test_cloud_resource_count_consistency(self):
        # Login as admin
        self.client.post('/auth/login', data={
            'username': 'test_admin',
            'password': 'TestAdmin1234!'
        }, follow_redirects=True)

        from models import CloudResource
        with self.app.app_context():
            initial_count = CloudResource.query.filter(CloudResource.status != 'deleted').count()

        # Create new cloud resource
        res = self.client.post('/resources/create', data={
            'name': 'test-audit-database',
            'resource_type': 'database',
            'owner': 'sec-team',
            'encryption_enabled': 'on',
            'logging_enabled': 'on'
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)

        with self.app.app_context():
            new_count = CloudResource.query.filter(CloudResource.status != 'deleted').count()
            self.assertEqual(new_count, initial_count + 1)
            created_r = CloudResource.query.filter_by(name='test-audit-database').first()
            self.assertIsNotNone(created_r)
            self.assertEqual(created_r.is_demo, True)
            self.assertIsNotNone(created_r.risk_score)

        # Check list page
        res = self.client.get('/resources/')
        self.assertEqual(res.status_code, 200)
        self.assertIn(f'Cloud Resources ({new_count})'.encode(), res.data)

if __name__ == '__main__':
    unittest.main()
