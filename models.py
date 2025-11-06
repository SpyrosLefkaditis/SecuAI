"""
SecuAI Database Models
SQLAlchemy models for users, alerts, blocks, audit logs, and whitelist
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash

db = SQLAlchemy()


class User(UserMixin, db.Model):
    """Admin users table"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<User {self.email}>'
    
    def set_password(self, password):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)


class Alert(db.Model):
    """Security alerts table"""
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), nullable=False, index=True)  # Support IPv6
    reason = db.Column(db.String(255), nullable=False)
    confidence = db.Column(db.Float, default=0.5, nullable=False)
    details = db.Column(db.Text)  # JSON string with additional data
    source = db.Column(db.String(100), nullable=False)  # api, upload:filename, honeypot, etc.
    status = db.Column(db.String(20), default='new', nullable=False)  # new, reviewed, ignored, blocked
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    reviewed_at = db.Column(db.DateTime)
    reviewed_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Relationships
    reviewer = db.relationship('User', backref='reviewed_alerts')
    
    def __repr__(self):
        return f'<Alert {self.ip}: {self.reason}>'
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'ip': self.ip,
            'reason': self.reason,
            'confidence': self.confidence,
            'details': self.details,
            'source': self.source,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'reviewed_at': self.reviewed_at.isoformat() if self.reviewed_at else None
        }


class Block(db.Model):
    """Blocked IPs table"""
    __tablename__ = 'blocks'
    
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), nullable=False, index=True)
    action = db.Column(db.String(20), nullable=False)  # recommend, approve, simulate, apply
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    applied = db.Column(db.Boolean, default=False, nullable=False)  # True if actually applied to firewall
    details = db.Column(db.Text)  # Additional info about the block
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    expires_at = db.Column(db.DateTime)  # Optional expiration
    
    # Relationships
    creator = db.relationship('User', backref='created_blocks')
    
    def __repr__(self):
        return f'<Block {self.ip}: {self.action}>'
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'ip': self.ip,
            'action': self.action,
            'is_active': self.is_active,
            'applied': self.applied,
            'details': self.details,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None
        }


class AuditLog(db.Model):
    """Audit log for all security actions"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(100), nullable=False, index=True)
    details = db.Column(db.Text, nullable=False)
    ip_address = db.Column(db.String(45))  # IP being acted upon
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    session_id = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Relationships
    user = db.relationship('User', backref='audit_logs')
    
    def __repr__(self):
        return f'<AuditLog {self.action}: {self.details[:50]}>'
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'action': self.action,
            'details': self.details,
            'ip_address': self.ip_address,
            'user_id': self.user_id,
            'created_at': self.created_at.isoformat()
        }


class Whitelist(db.Model):
    """IP whitelist table"""
    __tablename__ = 'whitelist'
    
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), nullable=False, unique=True, index=True)
    description = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Relationships
    creator = db.relationship('User', backref='whitelist_entries')
    
    def __repr__(self):
        return f'<Whitelist {self.ip}: {self.description}>'
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'ip': self.ip,
            'description': self.description,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat()
        }


# Index creation for performance
def create_indexes():
    """Create additional database indexes for performance"""
    try:
        # Composite indexes for common queries
        db.Index('idx_alerts_ip_created', Alert.ip, Alert.created_at)
        db.Index('idx_alerts_confidence_created', Alert.confidence, Alert.created_at)
        db.Index('idx_blocks_ip_active', Block.ip, Block.is_active)
        db.Index('idx_audit_user_created', AuditLog.user_id, AuditLog.created_at)
    except Exception as e:
        print(f"Index creation warning: {e}")