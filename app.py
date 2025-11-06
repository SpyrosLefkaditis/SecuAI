#!/usr/bin/env python3
"""
SecuAI - Log and Network Anomaly Detector
Main Flask application for hackathon MVP
"""

import os
import json
import logging
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
from decouple import config

from models import db, User, Alert, Block, AuditLog, Whitelist
from analyzer import analyze_logs, ml_enrich
from agents.host_blocker import simulate_block, can_apply_real_block

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
        
        # Get recent alerts
        recent_alerts = Alert.query.order_by(Alert.created_at.desc()).limit(10).all()
        
        # Get recent blocks
        recent_blocks = Block.query.filter(Block.is_active == True).order_by(Block.created_at.desc()).limit(5).all()
        
        stats = {
            'alerts_today': alerts_today,
            'critical_alerts': critical_alerts,
            'blocked_ips': blocked_ips
        }
        
        return render_template('index.html', stats=stats, alerts=recent_alerts, blocks=recent_blocks)
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return render_template('index.html', stats={'alerts_today': 0, 'critical_alerts': 0, 'blocked_ips': 0}, alerts=[], blocks=[])


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


@app.route('/api/block', methods=['POST'])
def api_block():
    """Block an IP address"""
    try:
        data = request.get_json()
        ip = data.get('ip')
        action = data.get('action', 'recommend')  # recommend, approve, simulate, apply
        
        if not ip:
            return jsonify({'error': 'IP address required'}), 400
        
        # Check if IP is whitelisted
        whitelist_entry = Whitelist.query.filter_by(ip=ip, is_active=True).first()
        if whitelist_entry:
            return jsonify({'error': 'IP is whitelisted', 'status': 'blocked'}), 403
        
        # Handle different actions
        if action == 'recommend':
            # Just create a recommendation
            block = Block(ip=ip, action='recommend', is_active=False, applied=False)
            db.session.add(block)
            
            # Log audit
            audit = AuditLog(
                action='block_recommend',
                details=f'Recommended blocking {ip}',
                user_id=getattr(current_user, 'id', None)
            )
            db.session.add(audit)
            
            status = 'recommended'
            
        elif action == 'approve':
            # Approve and simulate block
            result = simulate_block(ip)
            
            block = Block(ip=ip, action='approve', is_active=True, applied=False, details=result['message'])
            db.session.add(block)
            
            # Log audit
            audit = AuditLog(
                action='block_approve',
                details=f'Approved and simulated blocking {ip}: {result["message"]}',
                user_id=getattr(current_user, 'id', None)
            )
            db.session.add(audit)
            
            status = 'approved_simulated'
            
        elif action == 'apply' and can_apply_real_block():
            # Real blocking (disabled by default for safety)
            return jsonify({'error': 'Real blocking is disabled for safety', 'status': 'blocked'}), 403
            
        else:
            return jsonify({'error': 'Invalid action'}), 400
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'action': action,
            'ip': ip,
            'block_status': status
        })
        
    except Exception as e:
        logger.error(f"Block error: {e}")
        return jsonify({'error': 'Block operation failed', 'details': str(e)}), 500


@app.route('/api/blocks')
def api_blocks():
    """Get list of blocked IPs"""
    try:
        blocks = Block.query.filter(Block.is_active == True).order_by(Block.created_at.desc()).all()
        
        result = []
        for block in blocks:
            result.append({
                'id': block.id,
                'ip': block.ip,
                'action': block.action,
                'applied': block.applied,
                'created_at': block.created_at.isoformat(),
                'details': block.details
            })
        
        return jsonify({'blocks': result})
        
    except Exception as e:
        logger.error(f"Blocks API error: {e}")
        return jsonify({'error': 'Failed to get blocks'}), 500


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
    """Security alerts page"""
    try:
        alerts = Alert.query.order_by(Alert.created_at.desc()).limit(100).all()
        return render_template('alerts.html', alerts=alerts)
    except Exception as e:
        logger.error(f"Alerts page error: {e}")
        flash(f'Error loading alerts: {str(e)}')
        return redirect(url_for('dashboard'))


@app.route('/blocks')
@login_required
def blocks_page():
    """IP blocks management page"""
    try:
        active_blocks = Block.query.filter(Block.is_active == True).order_by(Block.created_at.desc()).all()
        return render_template('blocks.html', blocks=active_blocks)
    except Exception as e:
        logger.error(f"Blocks page error: {e}")
        flash(f'Error loading blocks: {str(e)}')
        return redirect(url_for('dashboard'))


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





if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    # Run in debug mode for development
    app.run(host='0.0.0.0', port=5000, debug=config('DEBUG', default=True, cast=bool))