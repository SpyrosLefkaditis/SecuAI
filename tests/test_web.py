"""
SecuAI Web Application Tests
Test suite for Flask routes and web functionality
"""

import pytest
import json
import tempfile
import os
from unittest.mock import patch, MagicMock

# Import Flask app and components
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
from models import db, User, Alert, Block, AuditLog, Whitelist


@pytest.fixture
def client():
    """Create a test client"""
    # Create a temporary database for testing
    db_fd, app.config['DATABASE'] = tempfile.mkstemp()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SECRET_KEY'] = 'test-secret-key'
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            # Create test admin user
            admin = User(email='test@secuai.local', is_admin=True)
            admin.set_password('testpass')
            db.session.add(admin)
            db.session.commit()
        yield client
    
    os.close(db_fd)
    os.unlink(app.config['DATABASE'])


@pytest.fixture
def auth_client(client):
    """Create an authenticated test client"""
    # Login the test user
    client.post('/login', data={
        'email': 'test@secuai.local',
        'password': 'testpass'
    })
    return client


class TestRoutes:
    """Test Flask routes"""
    
    def test_dashboard_route(self, client):
        """Test dashboard loads successfully"""
        response = client.get('/')
        assert response.status_code == 200
        assert b'SecuAI' in response.data
        assert b'Dashboard' in response.data
    
    def test_login_route_get(self, client):
        """Test login page loads"""
        response = client.get('/login')
        assert response.status_code == 200
        assert b'Sign In' in response.data
    
    def test_login_route_post_valid(self, client):
        """Test valid login"""
        response = client.post('/login', data={
            'email': 'test@secuai.local',
            'password': 'testpass'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        # Should redirect to admin page after successful login
    
    def test_login_route_post_invalid(self, client):
        """Test invalid login"""
        response = client.post('/login', data={
            'email': 'wrong@email.com',
            'password': 'wrongpass'
        })
        
        assert response.status_code == 200
        assert b'Invalid credentials' in response.data
    
    def test_admin_route_unauthorized(self, client):
        """Test admin route without login"""
        response = client.get('/admin')
        assert response.status_code == 302  # Redirect to login
    
    def test_admin_route_authorized(self, auth_client):
        """Test admin route with login"""
        response = auth_client.get('/admin')
        assert response.status_code == 200
        assert b'Administration Panel' in response.data


class TestAPIRoutes:
    """Test API endpoints"""
    
    def test_analyze_api_empty_data(self, client):
        """Test analyze API with empty data"""
        response = client.post('/api/analyze', 
                              json={'log_text': ''})
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
    
    def test_analyze_api_valid_data(self, client):
        """Test analyze API with valid log data"""
        sample_logs = """
        Oct 15 10:30:15 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2
        Oct 15 10:30:20 server sshd[12346]: Failed password for admin from 192.168.1.100 port 22 ssh2
        Oct 15 10:30:25 server sshd[12347]: Failed password for user from 192.168.1.100 port 22 ssh2
        Oct 15 10:30:30 server sshd[12348]: Failed password for test from 192.168.1.100 port 22 ssh2
        """
        
        response = client.post('/api/analyze', 
                              json={'log_text': sample_logs})
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert 'status' in data
        assert data['status'] == 'success'
        assert 'findings' in data
        assert len(data['findings']) > 0
    
    def test_analyze_api_form_data(self, client):
        """Test analyze API with form data"""
        sample_logs = "Oct 15 10:31:02 server kernel: Possible port scan from 10.0.0.50"
        
        response = client.post('/api/analyze', 
                              data={'log_text': sample_logs})
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['status'] == 'success'
    
    def test_block_api_missing_ip(self, client):
        """Test block API without IP"""
        response = client.post('/api/block', 
                              json={'action': 'recommend'})
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert 'error' in data
    
    def test_block_api_recommend(self, client):
        """Test block API recommendation"""
        response = client.post('/api/block', 
                              json={'ip': '203.0.113.1', 'action': 'recommend'})
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['status'] == 'success'
        assert data['action'] == 'recommend'
    
    def test_block_api_approve(self, client):
        """Test block API approval (simulation)"""
        response = client.post('/api/block', 
                              json={'ip': '203.0.113.1', 'action': 'approve'})
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['status'] == 'success'
        assert data['action'] == 'approve'
    
    def test_blocks_api_get(self, client):
        """Test getting blocks list"""
        # First create a block
        client.post('/api/block', 
                   json={'ip': '203.0.113.1', 'action': 'approve'})
        
        # Then get blocks list
        response = client.get('/api/blocks')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert 'blocks' in data
        assert isinstance(data['blocks'], list)
    
    def test_honeypot_api_single_ip(self, client):
        """Test honeypot API with single IP"""
        response = client.post('/api/honeypot', 
                              json={'ip': '172.16.0.100', 'attack_type': 'ssh_bruteforce'})
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['status'] == 'success'
    
    def test_honeypot_api_bulk_ips(self, client):
        """Test honeypot API with bulk IP data"""
        honeypot_data = {
            'ips': [
                {'ip': '1.1.1.1', 'attacks': ['scan']},
                {'ip': '2.2.2.2', 'attacks': ['bruteforce']}
            ]
        }
        
        response = client.post('/api/honeypot', json=honeypot_data)
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['status'] == 'success'


class TestFileUpload:
    """Test file upload functionality"""
    
    def test_upload_no_file(self, client):
        """Test upload without file"""
        response = client.post('/upload', data={})
        assert response.status_code == 302  # Redirect back to dashboard
    
    def test_upload_valid_file(self, client):
        """Test upload with valid log file"""
        # Create a temporary log file
        log_content = """
Oct 15 10:30:15 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2
Oct 15 10:30:20 server sshd[12346]: Failed password for admin from 192.168.1.100 port 22 ssh2
Oct 15 10:30:25 server sshd[12347]: Failed password for user from 192.168.1.100 port 22 ssh2
        """
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(log_content)
            temp_file_path = f.name
        
        try:
            with open(temp_file_path, 'rb') as test_file:
                response = client.post('/upload', 
                                     data={'logfile': (test_file, 'test.log')},
                                     content_type='multipart/form-data')
            
            assert response.status_code == 302  # Redirect after successful upload
        finally:
            os.unlink(temp_file_path)


class TestDatabaseModels:
    """Test database models"""
    
    def test_user_model(self, client):
        """Test User model"""
        with app.app_context():
            user = User(email='testuser@example.com')
            user.set_password('testpassword')
            
            db.session.add(user)
            db.session.commit()
            
            # Test password verification
            from werkzeug.security import check_password_hash
            assert check_password_hash(user.password_hash, 'testpassword')
            assert not check_password_hash(user.password_hash, 'wrongpassword')
    
    def test_alert_model(self, client):
        """Test Alert model"""
        with app.app_context():
            alert = Alert(
                ip='192.168.1.100',
                reason='Test alert',
                confidence=0.8,
                source='test'
            )
            
            db.session.add(alert)
            db.session.commit()
            
            # Test to_dict method
            alert_dict = alert.to_dict()
            assert alert_dict['ip'] == '192.168.1.100'
            assert alert_dict['reason'] == 'Test alert'
            assert alert_dict['confidence'] == 0.8
    
    def test_block_model(self, client):
        """Test Block model"""
        with app.app_context():
            block = Block(
                ip='203.0.113.1',
                action='simulate',
                is_active=True,
                applied=False
            )
            
            db.session.add(block)
            db.session.commit()
            
            # Test to_dict method
            block_dict = block.to_dict()
            assert block_dict['ip'] == '203.0.113.1'
            assert block_dict['action'] == 'simulate'
            assert block_dict['is_active'] is True


class TestSecurity:
    """Test security features"""
    
    def test_csrf_protection(self, client):
        """Test CSRF protection on forms"""
        # This would test CSRF tokens if implemented
        pass
    
    def test_input_validation(self, client):
        """Test input validation"""
        # Test with malicious input
        response = client.post('/api/analyze', 
                              json={'log_text': '<script>alert("xss")</script>'})
        assert response.status_code == 200  # Should handle gracefully
    
    def test_sql_injection_protection(self, client):
        """Test SQL injection protection"""
        # Test with SQL injection attempt
        response = client.post('/api/analyze', 
                              json={'log_text': "'; DROP TABLE alerts; --"})
        assert response.status_code == 200  # Should handle gracefully


if __name__ == '__main__':
    pytest.main([__file__, '-v'])