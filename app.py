"""
CyberShield AI – AI-Powered Web Threat Detection & Digital Trust Intelligence
=============================================================================
Flask Application Entry Point
HackMatrix '26 Project
"""

import os
import json
import csv
import io
from flask import Flask, render_template, request, jsonify, Response, send_file
from scanner_engine import analyze_url
import database

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cybershield-ai-hackmatrix-2026-secret-key')

# Initialize SQLite database on startup
database.init_db()


# -----------------------------------------------------------------------------
# Frontend Page Routes
# -----------------------------------------------------------------------------

@app.route('/')
def home():
    """Serves the main landing page with interactive scanner, features, and docs."""
    stats = database.get_statistics()
    return render_template('index.html', stats=stats)


@app.route('/dashboard')
def dashboard():
    """Serves the full Cybersecurity Analytics & History Dashboard."""
    stats = database.get_statistics()
    recent_scans = database.get_recent_scans(limit=30)
    return render_template('dashboard.html', stats=stats, recent_scans=recent_scans)


# -----------------------------------------------------------------------------
# RESTful API Endpoints
# -----------------------------------------------------------------------------

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """
    Scans a submitted website URL using the heuristic threat detection engine.
    Stores the result in SQLite and returns comprehensive analysis data.
    """
    data = request.get_json(silent=True) or request.form

    raw_url = data.get('url') if data else None
    if not raw_url:
        return jsonify({
            'success': False,
            'error': 'Website URL is required. Please enter a valid URL to analyze.'
        }), 400

    # Run security analysis
    analysis = analyze_url(raw_url)

    if not analysis.get('success'):
        return jsonify(analysis), 400

    # Save to SQLite database
    try:
        scan_id = database.save_scan(analysis)
        analysis['id'] = scan_id
    except Exception as e:
        # If DB write fails, still return analysis with fallback
        analysis['id'] = None
        analysis['db_warning'] = str(e)

    return jsonify(analysis)


@app.route('/api/scans', methods=['GET'])
def api_scans():
    """Retrieves recent scan records."""
    limit = request.args.get('limit', default=25, type=int)
    limit = max(1, min(limit, 100))
    scans = database.get_recent_scans(limit=limit)
    return jsonify({
        'success': True,
        'count': len(scans),
        'scans': scans
    })


@app.route('/api/scan/<int:scan_id>', methods=['GET'])
def api_scan_detail(scan_id):
    """Retrieves full detailed report for a specific historical scan."""
    scan = database.get_scan_by_id(scan_id)
    if not scan:
        return jsonify({
            'success': False,
            'error': f'Scan report with ID #{scan_id} was not found.'
        }), 404

    return jsonify({
        'success': True,
        'scan': scan
    })


@app.route('/api/stats', methods=['GET'])
def api_stats():
    """Returns aggregated real-time security statistics."""
    stats = database.get_statistics()
    return jsonify({
        'success': True,
        'stats': stats
    })


@app.route('/api/clear-history', methods=['POST'])
def api_clear_history():
    """Clears all scan history from the SQLite database."""
    try:
        database.clear_all_scans()
        return jsonify({
            'success': True,
            'message': 'Scan history successfully cleared.'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to clear database: {str(e)}'
        }), 500


@app.route('/api/contact', methods=['POST'])
def api_contact():
    """Handles threat reporting or contact feedback form submissions."""
    data = request.get_json(silent=True) or request.form

    name = data.get('name', '').strip()
    email = data.get('email', '').strip()
    subject = data.get('subject', 'CyberShield Threat Report').strip()
    message = data.get('message', '').strip()
    report_type = data.get('report_type', 'threat_report').strip()

    if not name or not email or not message:
        return jsonify({
            'success': False,
            'error': 'Name, email, and message are required fields.'
        }), 400

    try:
        report_id = database.save_contact_report(name, email, subject, message, report_type)
        return jsonify({
            'success': True,
            'message': 'Thank you! Your threat report has been securely registered with our threat triage pipeline.',
            'report_id': report_id
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Could not register report: {str(e)}'
        }), 500


@app.route('/api/export/csv', methods=['GET'])
def export_csv():
    """Exports all scan history as a CSV file."""
    scans = database.get_recent_scans(limit=500)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'URL', 'Hostname', 'Risk Score', 'Trust Score', 'Risk Level', 'HTTPS', 'Raw IP', 'Warnings Count', 'Timestamp'])

    for s in scans:
        writer.writerow([
            s['id'],
            s['url'],
            s['hostname'],
            s['risk_score'],
            s['trust_score'],
            s['risk_level'],
            'Yes' if s['is_https'] else 'No',
            'Yes' if s['is_ip'] else 'No',
            s['warnings_count'],
            s['created_at']
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=cybershield_scan_history.csv"}
    )


# -----------------------------------------------------------------------------
# Error Handlers
# -----------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'error': 'Endpoint not found.'}), 404
    return render_template('index.html', stats=database.get_statistics()), 404


@app.errorhandler(500)
def server_error(e):
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'error': 'Internal server error occurred.'}), 500
    return "<h3>Internal Server Error</h3><p>Please try again or check console logs.</p>", 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '0.0.0.0')
    is_production = bool(os.environ.get('RENDER') or os.environ.get('DYNO'))
    print(f"\n========================================================")
    print(f" CyberShield AI - Threat Detection Server")
    print(f" HackMatrix '26 Engine")
    print(f" Live at: http://{host}:{port}")
    print(f"========================================================\n")
    app.run(host=host, port=port, debug=not is_production)
