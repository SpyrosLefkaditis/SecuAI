"""
Test suite for SecuAI Flask application
Tests API endpoints, authentication, and UI functionality
"""

import pytest
import json
import tempfile
import os
from app import app
from models import db, User, Alert, Block, Whitelist


@pytest.fixture
def client():
    """Create test client with temporary database"""
    # Create temporary database file
    db_fd, app.config['DATABASE'] = tempfile.mkstemp()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{app.config["DATABASE"]}'
    app.config['WTF_CSRF_ENABLED'] = False
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            
            # Create test admin user
            admin = User(email='test@secuai.local', is_admin=True)
            admin.set_password('testpass123')
            db.session.add(admin)
            db.session.commit()
            
        yield client
    
    os.close(db_fd)
    os.unlink(app.config['DATABASE'])


@pytest.fixture
def auth_client(client):
    """Authenticated test client"""
    # Login as admin
    client.post('/login', data={
        'email': 'test@secuai.local',
        'password': 'testpass123'
    })
    return client


class TestRoutes:
    """Test Flask routes and API endpoints"""
    
    def test_dashboard_route(self, client):
        """Test main dashboard page loads"""
        response = client.get('/')
        assert response.status_code == 200
        assert b'SecuAI' in response.data
        assert b'Dashboard' in response.data
    
    def test_login_route_get(self, client):
        """Test login page loads"""
        response = client.get('/login')
        assert response.status_code == 200
        assert b'Login' in response.data
        assert b'admin@secuai.local' in response.data
    
    def test_login_route_post_valid(self, client):
        """Test valid login"""
        response = client.post('/login', data={
            'email': 'test@secuai.local',
            'password': 'testpass123'
        })
        assert response.status_code == 302  # Redirect after successful login
    
    def test_login_route_post_invalid(self, client):
        """Test invalid login"""
        response = client.post('/login', data={
            'email': 'test@secuai.local',
            'password': 'wrongpassword'
        })
        assert response.status_code == 200
        assert b'Invalid credentials' in response.data
    
    def test_admin_route_unauthorized(self, client):
        """Test admin route requires authentication"""
        response = client.get('/admin')
        assert response.status_code == 302  # Redirect to login
    
    def test_admin_route_authorized(self, auth_client):
        """Test admin route with authentication"""
        response = auth_client.get('/admin')
        assert response.status_code == 200
        assert b'Administration Panel' in response.data
    
    def test_logout_route(self, auth_client):
        """Test logout functionality"""
        response = auth_client.get('/logout')
        assert response.status_code == 302  # Redirect after logout
        
        # Should no longer have access to admin
        response = auth_client.get('/admin')
        assert response.status_code == 302  # Redirect to login


class TestAnalysisAPI:
    """Test log analysis API endpoints"""
    
    def test_analyze_api_post_json(self, client):
        """Test analysis API with JSON data"""
        test_logs = """
        Oct 15 10:30:15 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2
        Oct 15 10:30:20 server sshd[12346]: Failed password for admin from 192.168.1.100 port 22 ssh2
        Oct 15 10:30:25 server sshd[12347]: Failed password for user from 192.168.1.100 port 22 ssh2
        """
        
        response = client.post('/api/analyze',
                             data=json.dumps({'log_text': test_logs}),
                             content_type='application/json')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'success'
        assert 'findings' in data
        assert len(data['findings']) >= 1
        assert data['findings'][0]['ip'] == '192.168.1.100'
    
    def test_analyze_api_post_form(self, client):
        """Test analysis API with form data"""
        test_logs = "Oct 15 10:31:01 server kernel: [12345.678] SYN flood detected from 10.0.0.50"
        
        response = client.post('/api/analyze', data={'log_text': test_logs})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'success'
        assert 'findings' in data
    
    def test_analyze_api_empty_data(self, client):
        """Test analysis API with empty data"""
        response = client.post('/api/analyze',
                             data=json.dumps({'log_text': ''}),
                             content_type='application/json')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
    
    def test_upload_route_no_file(self, client):
        """Test file upload without file"""
        response = client.post('/upload', data={})
        assert response.status_code == 302  # Redirect
        
        # Check for flash message (would need to follow redirect to verify)
    
    def test_upload_route_with_file(self, client):
        """Test file upload with log file"""
        # Create temporary log file
        test_log_content = """
        Oct 15 10:30:15 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2
        Oct 15 10:31:01 server kernel: [12345.678] Port scan detected from 10.0.0.50
        """
        
        response = client.post('/upload', data={
            'logfile': (tempfile.NamedTemporaryFile(mode='w+', suffix='.log', delete=False), 'test.log')
        })
        
        # Should process file and redirect
        assert response.status_code == 302


class TestBlockingAPI:
    """Test IP blocking API endpoints"""
    
    def test_block_api_recommend(self, client):
        """Test block recommendation"""
        response = client.post('/api/block',
                             data=json.dumps({'ip': '203.0.113.1', 'action': 'recommend'}),
                             content_type='application/json')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'success'
        assert data['action'] == 'recommend'
        assert data['ip'] == '203.0.113.1'
    
    def test_block_api_approve(self, client):
        """Test block approval (simulation)"""
        response = client.post('/api/block',
                             data=json.dumps({'ip': '203.0.113.2', 'action': 'approve'}),
                             content_type='application/json')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'success'
        assert data['action'] == 'approve'
        assert 'approved_simulated' in data['block_status']
    
    def test_block_api_invalid_ip(self, client):
        """Test blocking with invalid IP"""
        response = client.post('/api/block',
                             data=json.dumps({'ip': '', 'action': 'recommend'}),
                             content_type='application/json')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
    
    def test_block_api_real_blocking_disabled(self, client):
        """Test that real blocking is disabled by default"""
        response = client.post('/api/block',
                             data=json.dumps({'ip': '203.0.113.3', 'action': 'apply'}),
                             content_type='application/json')
        
        assert response.status_code == 403
        data = json.loads(response.data)
        assert 'disabled for safety' in data['error']
    
    def test_blocks_api_get(self, client):
        """Test getting list of blocks"""
        # First create a block
        client.post('/api/block',
                   data=json.dumps({'ip': '203.0.113.4', 'action': 'approve'}),
                   content_type='application/json')
        
        # Then get the list
        response = client.get('/api/blocks')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'blocks' in data
        assert len(data['blocks']) >= 1


class TestHoneypotAPI:
    """Test honeypot API endpoints"""
    
    def test_honeypot_api_single_ip(self, client):
        """Test honeypot API with single IP report"""
        honeypot_data = {
            'ip': '172.16.0.100',
            'attack_type': 'ssh_bruteforce',
            'severity': 'high'
        }
        
        response = client.post('/api/honeypot',
                             data=json.dumps(honeypot_data),
                             content_type='application/json')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'success'
    
    def test_honeypot_api_bulk_import(self, client):
        """Test honeypot API with bulk import"""
        honeypot_data = {
            'ips': [
                {'ip': '172.16.0.101', 'severity': 'high'},
                {'ip': '172.16.0.102', 'severity': 'medium'}
            ]
        }
        
        response = client.post('/api/honeypot',
                             data=json.dumps(honeypot_data),
                             content_type='application/json')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'success'
    
    def test_honeypot_api_no_data(self, client):
        """Test honeypot API with no IP data"""
        response = client.post('/api/honeypot',
                             data=json.dumps({}),
                             content_type='application/json')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data


class TestDatabase:
    """Test database operations"""
    
    def test_user_model(self):
        """Test User model functionality"""
        with app.app_context():
            db.create_all()
            
            user = User(email='test@example.com')
            user.set_password('testpass')
            
            db.session.add(user)
            db.session.commit()
            
            # Test password verification
            from werkzeug.security import check_password_hash
            assert check_password_hash(user.password_hash, 'testpass')
            assert not check_password_hash(user.password_hash, 'wrongpass')
            
            db.session.delete(user)
            db.session.commit()
    
    def test_alert_model(self, client):
        """Test Alert model functionality"""
        with app.app_context():
            alert = Alert(
                ip='192.168.1.100',
                reason='Test alert',
                confidence=0.8,
                details='{"test": "data"}',
                source='test'
            )
            
            db.session.add(alert)
            db.session.commit()
            
            # Test alert retrieval
            retrieved = Alert.query.filter_by(ip='192.168.1.100').first()
            assert retrieved is not None
            assert retrieved.reason == 'Test alert'
            assert retrieved.confidence == 0.8
            
            # Test to_dict method
            alert_dict = retrieved.to_dict()
            assert alert_dict['ip'] == '192.168.1.100'
            assert alert_dict['confidence'] == 0.8
    
    def test_block_model(self, client):
        """Test Block model functionality"""
        with app.app_context():
            block = Block(
                ip='203.0.113.1',
                action='simulate',
                is_active=True,
                applied=False,
                details='Test block'
            )
            
            db.session.add(block)
            db.session.commit()
            
            # Test block retrieval
            retrieved = Block.query.filter_by(ip='203.0.113.1').first()
            assert retrieved is not None
            assert retrieved.action == 'simulate'
            assert retrieved.is_active is True
            assert retrieved.applied is False


class TestSecurity:
    """Test security-related functionality"""
    
    def test_csrf_protection_disabled_in_testing(self, client):
        """Verify CSRF is disabled for testing"""
        # This test ensures our test configuration is correct
        assert app.config['WTF_CSRF_ENABLED'] is False
    
    def test_admin_route_protection(self, client):
        """Test that admin routes require authentication"""
        protected_routes = ['/admin']
        
        for route in protected_routes:
            response = client.get(route)
            assert response.status_code == 302  # Redirect to login
    
    def test_password_hashing(self):
        """Test that passwords are properly hashed"""
        with app.app_context():
            user = User(email='test@example.com')
            user.set_password('plaintext_password')
            
            # Password should be hashed
            assert user.password_hash != 'plaintext_password'
            assert len(user.password_hash) > 50  # Hashed passwords are long
    
    def test_simulation_mode_safety(self, client):
        """Test that simulation mode prevents real blocking"""
        response = client.post('/api/block',
                             data=json.dumps({'ip': '203.0.113.99', 'action': 'apply'}),
                             content_type='application/json')
        
        # Should be blocked for safety
        assert response.status_code == 403


if __name__ == '__main__':
    pytest.main([__file__, '-v'])