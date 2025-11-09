#!/usr/bin/env python3
"""
SecuAI - Log and Network Anomaly Detector
Main Flask application for hackathon MVP
"""

import os
import json
import logging
import threading
import subprocess
import time
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
from decouple import config

from models import db, User, Alert, Block, AuditLog, Whitelist
from analyzer import analyze_logs, ml_enrich
from agents.host_blocker import simulate_block, can_apply_real_block
from firewall_manager import firewall_manager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Flask app configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = config('SECRET_KEY', default='dev-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secai.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create uploads directory
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def clear_sample_data():
    """Clear any sample/hardcoded data from database"""
    try:
        # Remove old hardcoded alerts that might exist
        old_alerts = Alert.query.filter(
            Alert.created_at < datetime.utcnow() - timedelta(hours=1)
        ).all()
        
        for alert in old_alerts:
            if any(sample_ip in alert.ip for sample_ip in ['198.51.100', '203.0.113', '192.168.1', '10.0.0']):
                logger.info(f"Removing sample alert: {alert.ip}")
                db.session.delete(alert)
        
        # Remove old blocks that look like sample data
        old_blocks = Block.query.filter(
            Block.created_at < datetime.utcnow() - timedelta(hours=1)
        ).all()
        
        for block in old_blocks:
            if any(sample_ip in block.ip for sample_ip in ['198.51.100', '203.0.113', '192.168.1', '10.0.0']):
                logger.info(f"Removing sample block: {block.ip}")
                db.session.delete(block)
        
        db.session.commit()
        logger.info("✅ Sample data cleanup completed")
        
    except Exception as e:
        logger.error(f"Error clearing sample data: {e}")
        db.session.rollback()


def start_log_monitor():
    """Start log monitor in background thread"""
    def run_monitor():
        try:
            time.sleep(2)  # Wait for Flask app to fully start
            logger.info("🚀 Starting integrated log monitor...")
            
            # Import here to avoid circular imports
            from log_monitor import LogMonitor
            monitor = LogMonitor()
            
            # Run monitor in the background without blocking
            monitor.start_monitoring()
            
        except Exception as e:
            logger.error(f"Error starting log monitor: {e}")
    
    # Start monitor in daemon thread (dies when main process dies)
    monitor_thread = threading.Thread(target=run_monitor, daemon=True, name="LogMonitor")
    monitor_thread.start()
    logger.info("✅ Log monitor thread started in background")


# Routes
@app.route('/')
@login_required
def dashboard():
    """Main dashboard page - requires authentication"""
    try:
        # Get dashboard statistics
        alerts_today = Alert.query.filter(
            Alert.created_at >= datetime.now().replace(hour=0, minute=0, second=0)
        ).count()
        
        critical_alerts = Alert.query.filter(Alert.confidence >= 0.8).count()
        blocked_ips = Block.query.filter(Block.is_active == True).count()
        
        stats = {
            'alerts_today': alerts_today,
            'critical_alerts': critical_alerts,
            'blocked_ips': blocked_ips
        }
        
        return render_template('index.html', stats=stats)
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return render_template('index.html', stats={'alerts_today': 0, 'critical_alerts': 0, 'blocked_ips': 0})


@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """Analyze log data via API"""
    try:
        if request.is_json:
            data = request.get_json()
            log_text = data.get('log_text', '')
        else:
            log_text = request.form.get('log_text', '')
        
        if not log_text:
            return jsonify({'error': 'No log text provided'}), 400
        
        # Analyze logs
        findings = analyze_logs(log_text)
        
        # Enrich with ML if available
        enriched_findings = []
        for finding in findings:
            enriched = ml_enrich(finding)
            enriched_findings.append(enriched)
            
            # Save to database
            alert = Alert(
                ip=finding['ip'],
                reason=finding['reason'],
                confidence=enriched.get('confidence', finding.get('confidence', 0.5)),
                details=json.dumps(enriched),
                source='api'
            )
            db.session.add(alert)
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'findings': enriched_findings,
            'count': len(enriched_findings)
        })
        
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        return jsonify({'error': 'Analysis failed', 'details': str(e)}), 500


@app.route('/upload', methods=['POST'])
def upload_file():
    """Upload and analyze log file"""
    try:
        if 'logfile' not in request.files:
            flash('No file selected')
            return redirect(url_for('dashboard'))
        
        file = request.files['logfile']
        if file.filename == '':
            flash('No file selected')
            return redirect(url_for('dashboard'))
        
        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # Read and analyze file
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                log_content = f.read()
            
            findings = analyze_logs(log_content)
            
            # Save findings to database
            for finding in findings:
                enriched = ml_enrich(finding)
                alert = Alert(
                    ip=finding['ip'],
                    reason=finding['reason'],
                    confidence=enriched.get('confidence', finding.get('confidence', 0.5)),
                    details=json.dumps(enriched),
                    source=f'upload:{filename}'
                )
                db.session.add(alert)
            
            db.session.commit()
            
            # Clean up uploaded file
            os.remove(filepath)
            
            flash(f'Successfully analyzed {len(findings)} findings from {filename}')
            return redirect(url_for('dashboard'))
            
    except Exception as e:
        logger.error(f"Upload error: {e}")
        flash(f'Upload failed: {str(e)}')
        return redirect(url_for('dashboard'))





@app.route('/api/honeypot', methods=['POST'])
def api_honeypot():
    """Ingest honeypot feed data"""
    try:
        data = request.get_json()
        
        if 'ips' in data:
            # Bulk import from feed
            for ip_data in data['ips']:
                ip = ip_data.get('ip')
                if ip:
                    # Create high-priority alert
                    alert = Alert(
                        ip=ip,
                        reason='Honeypot detected malicious activity',
                        confidence=0.9,
                        details=json.dumps(ip_data),
                        source='honeypot_feed'
                    )
                    db.session.add(alert)
        
        elif 'ip' in data:
            # Single IP report
            ip = data['ip']
            alert = Alert(
                ip=ip,
                reason='Honeypot interaction detected',
                confidence=0.8,
                details=json.dumps(data),
                source='honeypot'
            )
            db.session.add(alert)
        
        else:
            return jsonify({'error': 'No IP data provided'}), 400
        
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Honeypot data ingested'})
        
    except Exception as e:
        logger.error(f"Honeypot API error: {e}")
        return jsonify({'error': 'Honeypot ingestion failed'}), 500


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if email and password:
            user = User.query.filter_by(email=email).first()
            if user and check_password_hash(user.password_hash, password):
                login_user(user, remember=request.form.get('remember'))
                
                # Log successful login
                audit_log = AuditLog(
                    user_id=user.id,
                    action='login',
                    details=f'Successful login from {request.remote_addr}',
                    ip_address=request.remote_addr
                )
                db.session.add(audit_log)
                db.session.commit()
                
                next_page = request.args.get('next')
                if next_page:
                    return redirect(next_page)
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password', 'error')
                
                # Log failed login attempt
                audit_log = AuditLog(
                    user_id=None,
                    action='failed_login',
                    details=f'Failed login attempt for {email} from {request.remote_addr}',
                    ip_address=request.remote_addr
                )
                db.session.add(audit_log)
                db.session.commit()
        else:
            flash('Please enter both email and password', 'error')
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """User logout"""
    # Log logout
    audit_log = AuditLog(
        user_id=current_user.id,
        action='logout',
        details=f'User logged out from {request.remote_addr}',
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)
    db.session.commit()
    
    logout_user()
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('login'))


@app.route('/alerts')
@login_required
def alerts_page():
    """Security alerts page with date filtering"""
    try:
        # Get date range parameters
        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')
        
        # Default to last 48 hours if no dates specified
        if not start_date_str or not end_date_str:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(hours=48)
        else:
            try:
                start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
                end_date = datetime.strptime(end_date_str, '%Y-%m-%d') + timedelta(days=1) - timedelta(seconds=1)
            except ValueError:
                # Fallback to 48 hours if date parsing fails
                end_date = datetime.utcnow()
                start_date = end_date - timedelta(hours=48)
        
        # Query alerts within date range
        alerts_query = Alert.query.filter(
            Alert.created_at >= start_date,
            Alert.created_at <= end_date
        ).order_by(Alert.created_at.desc())
        
        # Get all alerts for the date range (remove limit to show all within timeframe)
        alerts = alerts_query.all()
        
        # Get summary statistics for the date range
        total_alerts = len(alerts)
        critical_alerts = len([a for a in alerts if a.confidence >= 0.8])
        medium_alerts = len([a for a in alerts if 0.6 <= a.confidence < 0.8])
        low_alerts = len([a for a in alerts if a.confidence < 0.6])
        
        # Get unique IPs
        unique_ips = len(set([a.ip for a in alerts]))
        
        date_range_info = {
            'start_date': start_date,
            'end_date': end_date,
            'start_date_str': start_date.strftime('%Y-%m-%d'),
            'end_date_str': end_date.strftime('%Y-%m-%d'),
            'total_alerts': total_alerts,
            'critical_alerts': critical_alerts,
            'medium_alerts': medium_alerts,
            'low_alerts': low_alerts,
            'unique_ips': unique_ips,
            'is_default_range': not start_date_str and not end_date_str
        }
        
        return render_template('alerts.html', alerts=alerts, date_range=date_range_info)
    except Exception as e:
        logger.error(f"Alerts page error: {e}")
        flash(f'Error loading alerts: {str(e)}')
        return redirect(url_for('dashboard'))




@app.route('/api/alerts')
@login_required
def api_alerts():
    """API endpoint for alerts with date filtering"""
    try:
        # Get date range parameters
        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')
        
        # Default to last 48 hours if no dates specified
        if not start_date_str or not end_date_str:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(hours=48)
        else:
            try:
                start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
                end_date = datetime.strptime(end_date_str, '%Y-%m-%d') + timedelta(days=1) - timedelta(seconds=1)
            except ValueError:
                return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD'}), 400
        
        # Query alerts within date range
        alerts_query = Alert.query.filter(
            Alert.created_at >= start_date,
            Alert.created_at <= end_date
        ).order_by(Alert.created_at.desc())
        
        alerts = alerts_query.all()
        
        # Format alerts for JSON response
        alerts_data = []
        for alert in alerts:
            alerts_data.append({
                'id': alert.id,
                'ip': alert.ip,
                'reason': alert.reason,
                'confidence': alert.confidence,
                'source': alert.source,
                'created_at': alert.created_at.isoformat(),
                'details': alert.details
            })
        
        # Get summary statistics
        total_alerts = len(alerts)
        critical_alerts = len([a for a in alerts if a.confidence >= 0.8])
        medium_alerts = len([a for a in alerts if 0.6 <= a.confidence < 0.8])
        low_alerts = len([a for a in alerts if a.confidence < 0.6])
        unique_ips = len(set([a.ip for a in alerts]))
        
        return jsonify({
            'alerts': alerts_data,
            'summary': {
                'total_alerts': total_alerts,
                'critical_alerts': critical_alerts,
                'medium_alerts': medium_alerts,
                'low_alerts': low_alerts,
                'unique_ips': unique_ips,
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            }
        })
        
    except Exception as e:
        logger.error(f"Alerts API error: {e}")
        return jsonify({'error': 'Failed to load alerts'}), 500


@app.route('/analysis')
@login_required
def analysis_page():
    """Log analysis page"""
    try:
        return render_template('analysis.html')
    except Exception as e:
        logger.error(f"Analysis page error: {e}")
        flash(f'Error loading analysis page: {str(e)}')
        return redirect(url_for('dashboard'))


@app.route('/firewall')
@app.route('/firewall/')
@login_required
def firewall_page():
    """Firewall management page"""
    try:
        # Get blacklisted IPs from database
        blacklisted_ips = Block.query.filter(Block.is_active == True).order_by(Block.created_at.desc()).all()
        
        # Get whitelisted IPs from database  
        whitelisted_ips = Whitelist.query.filter(Whitelist.is_active == True).order_by(Whitelist.created_at.desc()).all()
        
        # Get recent security alerts
        recent_alerts = Alert.query.order_by(Alert.created_at.desc()).limit(10).all()
        
        return render_template('firewall.html', 
                             blacklisted_ips=blacklisted_ips,
                             whitelisted_ips=whitelisted_ips,
                             recent_alerts=recent_alerts,
                             blacklisted_count=len(blacklisted_ips),
                             whitelisted_count=len(whitelisted_ips))
    except Exception as e:
        logger.error(f"Firewall page error: {e}")
        flash(f'Error loading firewall page: {str(e)}')
        return redirect(url_for('dashboard'))


@app.route('/admin')
@login_required
def admin():
    """Admin interface"""
    try:
        # Get audit log
        audit_logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(50).all()
        
        # Get alerts for admin management
        alerts = Alert.query.order_by(Alert.created_at.desc()).limit(100).all()
        
        # Get whitelist
        whitelist = Whitelist.query.filter(Whitelist.is_active == True).all()
        
        # Get user count
        user_count = User.query.count()
        
        return render_template('admin.html', 
                             audit_logs=audit_logs, 
                             alerts=alerts,
                             whitelist=whitelist, 
                             user_count=user_count)
        
    except Exception as e:
        logger.error(f"Admin error: {e}")
        flash(f'Admin panel error: {str(e)}')
        return redirect(url_for('dashboard'))


# Firewall API Endpoints
@app.route('/api/firewall/blacklist', methods=['POST'])
@login_required
def api_firewall_blacklist():
    """Add IP to blacklist via firewall manager"""
    try:
        data = request.get_json()
        ip = data.get('ip', '').strip()
        reason = data.get('reason', 'Manual block')
        
        if not ip:
            return jsonify({'status': 'error', 'error': 'IP address is required'})
        
        # Use firewall manager to block IP
        result = firewall_manager.block_ip(ip, reason)
        
        if result['status'] == 'success':
            # Also save to database
            existing_block = Block.query.filter_by(ip=ip).first()
            if existing_block:
                existing_block.is_active = True
                existing_block.reason = reason
                existing_block.created_at = datetime.utcnow()
            else:
                new_block = Block(
                    ip=ip,
                    reason=reason,
                    is_active=True
                )
                db.session.add(new_block)
            
            db.session.commit()
            
            # Log the action
            audit_log = AuditLog(
                user_id=current_user.id,
                action='firewall_block',
                details=f'Blocked IP {ip} - {reason}',
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)
            db.session.commit()
            
            logger.info(f"User {current_user.username} blocked IP {ip} via firewall")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Firewall blacklist API error: {e}")
        return jsonify({'status': 'error', 'error': str(e)})


@app.route('/api/firewall/whitelist', methods=['POST'])
@login_required
def api_firewall_whitelist():
    """Add IP to whitelist via firewall manager"""
    try:
        data = request.get_json()
        ip = data.get('ip', '').strip()
        description = data.get('description', 'Manual whitelist')
        
        if not ip:
            return jsonify({'status': 'error', 'error': 'IP address is required'})
        
        # Use firewall manager to whitelist IP
        result = firewall_manager.whitelist_ip(ip, description)
        
        if result['status'] == 'success':
            # Also save to database
            existing_whitelist = Whitelist.query.filter_by(ip=ip).first()
            if existing_whitelist:
                existing_whitelist.is_active = True
                existing_whitelist.description = description
                existing_whitelist.created_at = datetime.utcnow()
            else:
                new_whitelist = Whitelist(
                    ip=ip,
                    description=description,
                    is_active=True
                )
                db.session.add(new_whitelist)
            
            db.session.commit()
            
            # Log the action
            audit_log = AuditLog(
                user_id=current_user.id,
                action='firewall_whitelist',
                details=f'Whitelisted IP {ip} - {description}',
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)
            db.session.commit()
            
            logger.info(f"User {current_user.username} whitelisted IP {ip} via firewall")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Firewall whitelist API error: {e}")
        return jsonify({'status': 'error', 'error': str(e)})


@app.route('/api/firewall/unblock', methods=['POST'])
@login_required
def api_firewall_unblock():
    """Remove IP from blacklist via firewall manager"""
    try:
        data = request.get_json()
        ip = data.get('ip', '').strip()
        
        if not ip:
            return jsonify({'status': 'error', 'error': 'IP address is required'})
        
        # Use firewall manager to unblock IP
        result = firewall_manager.unblock_ip(ip)
        
        if result['status'] == 'success':
            # Update database
            existing_block = Block.query.filter_by(ip=ip).first()
            if existing_block:
                existing_block.is_active = False
                db.session.commit()
            
            # Log the action
            audit_log = AuditLog(
                user_id=current_user.id,
                action='firewall_unblock',
                details=f'Unblocked IP {ip}',
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)
            db.session.commit()
            
            logger.info(f"User {current_user.username} unblocked IP {ip} via firewall")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Firewall unblock API error: {e}")
        return jsonify({'status': 'error', 'error': str(e)})


@app.route('/api/firewall/status')
@login_required
def api_firewall_status():
    """Get firewall status"""
    try:
        status = firewall_manager.get_firewall_status()
        return jsonify(status)
    except Exception as e:
        logger.error(f"Firewall status API error: {e}")
        return jsonify({'status': 'error', 'error': str(e)})


# Global variable to track if monitor is started
monitor_started = False

def initialize_monitor():
    """Initialize log monitor if not already started"""
    global monitor_started
    if not monitor_started:
        # Clear any old sample data
        clear_sample_data()
        
        # Start integrated log monitor
        start_log_monitor()
        monitor_started = True
        logger.info("🚀 SecuAI initialization complete")

# Initialize on first route access
@app.before_request
def before_request():
    """Initialize components before any request"""
    initialize_monitor()

def create_app():
    """Application factory function"""
    with app.app_context():
        db.create_all()
        
        # Create default admin user if none exists
        if not User.query.first():
            admin = User(email='admin@secai.local', is_admin=True)
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            logger.info("✅ Default admin user created (admin@secai.local / admin123)")
        
        # Initialize monitor immediately when running directly
        initialize_monitor()
    
    return app

if __name__ == '__main__':
    # Create and run the app
    create_app()
    app.run(host='0.0.0.0', port=5000, debug=config('DEBUG', default=True, cast=bool))