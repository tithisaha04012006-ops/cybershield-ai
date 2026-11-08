"""
End-to-end integration and API tests for CyberShield AI.
Tests Flask endpoints, scanner heuristics, SQLite database CRUD, and CSV exports.
"""

import unittest
import json
from app import app
import database

class CyberShieldAppTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        # Ensure database is clean or initialized
        database.init_db()

    def test_01_home_page(self):
        """Test GET / renders successfully with 200 OK."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'CyberShield AI', response.data)
        self.assertIn(b'Secure Your Digital World with', response.data)
        self.assertIn(b'Scan Website', response.data)

    def test_02_dashboard_page(self):
        """Test GET /dashboard renders successfully with 200 OK."""
        response = self.client.get('/dashboard')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Security Operations Dashboard', response.data)
        self.assertIn(b'Total Scanned', response.data)

    def test_03_scan_safe_url(self):
        """Test scanning a reputable safe URL."""
        payload = {'url': 'https://github.com'}
        response = self.client.post('/api/scan',
                                    data=json.dumps(payload),
                                    content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['success'])
        self.assertEqual(data['risk_level'], 'Low')
        self.assertLessEqual(data['risk_score'], 34)
        self.assertTrue(data['is_https'])
        self.assertFalse(data['is_ip'])

    def test_04_scan_high_risk_ip_phishing(self):
        """Test scanning an IP-based phishing link."""
        payload = {'url': 'http://192.168.1.1/paypal-update-account/verify.php?token=xyz'}
        response = self.client.post('/api/scan',
                                    data=json.dumps(payload),
                                    content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['success'])
        self.assertEqual(data['risk_level'], 'High')
        self.assertGreaterEqual(data['risk_score'], 70)
        self.assertFalse(data['is_https'])
        self.assertTrue(data['is_ip'])
        self.assertGreater(len(data['warnings']), 0)

    def test_05_scan_typosquatting(self):
        """Test scanning brand typosquatting link."""
        payload = {'url': 'http://paypa1-secure-billing-service.top/auth'}
        response = self.client.post('/api/scan',
                                    data=json.dumps(payload),
                                    content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['success'])
        self.assertIn(data['risk_level'], ['Medium', 'High'])
        self.assertGreater(data['risk_score'], 40)

    def test_06_scan_invalid_inputs(self):
        """Test empty URL or invalid strings."""
        # Empty payload
        resp_empty = self.client.post('/api/scan', data=json.dumps({}), content_type='application/json')
        self.assertEqual(resp_empty.status_code, 400)

        # Invalid spaces
        resp_spaces = self.client.post('/api/scan', data=json.dumps({'url': 'not a valid url'}), content_type='application/json')
        self.assertEqual(resp_spaces.status_code, 400)

    def test_07_api_stats(self):
        """Test GET /api/stats endpoint."""
        response = self.client.get('/api/stats')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['success'])
        self.assertIn('total_scanned', data['stats'])
        self.assertIn('low_risk_count', data['stats'])
        self.assertIn('high_risk_count', data['stats'])

    def test_08_api_scans_list_and_detail(self):
        """Test retrieving recent scans and single scan by ID."""
        resp_list = self.client.get('/api/scans?limit=5')
        self.assertEqual(resp_list.status_code, 200)
        data = resp_list.get_json()
        self.assertTrue(data['success'])
        self.assertGreater(len(data['scans']), 0)

        first_id = data['scans'][0]['id']
        resp_detail = self.client.get(f'/api/scan/{first_id}')
        self.assertEqual(resp_detail.status_code, 200)
        data_detail = resp_detail.get_json()
        self.assertTrue(data_detail['success'])
        self.assertEqual(data_detail['scan']['id'], first_id)

    def test_09_contact_report(self):
        """Test submitting a threat report or feedback."""
        payload = {
            'name': 'Security Researcher',
            'email': 'researcher@example.org',
            'subject': 'Reported zero-day phishing link',
            'message': 'Observed deceptive domain targeting banking users.',
            'report_type': 'threat_report'
        }
        response = self.client.post('/api/contact',
                                    data=json.dumps(payload),
                                    content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['success'])
        self.assertIn('report_id', data)

    def test_10_export_csv(self):
        """Test CSV export functionality."""
        response = self.client.get('/api/export/csv')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, 'text/csv')
        self.assertIn(b'ID,URL,Hostname,Risk Score', response.data)


if __name__ == '__main__':
    unittest.main()
