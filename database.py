"""
CyberShield AI - Database Module (SQLite)
=========================================
Handles initialization, persistence of scan history, aggregated statistics,
and security threat reports using Python's built-in sqlite3.
"""

import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.environ.get('DATABASE_PATH', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cybershield.db'))
os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)


def get_db_connection():
    """Returns a connection to the SQLite database with row factory enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes database schema and populates starter demo data if empty."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Table: scans
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            hostname TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            trust_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            is_https INTEGER NOT NULL,
            is_ip INTEGER NOT NULL,
            warnings_count INTEGER NOT NULL,
            details_json TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Table: contact_reports
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS contact_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            subject TEXT,
            message TEXT NOT NULL,
            report_type TEXT DEFAULT 'general',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()

    # Check if empty - seed initial realistic demo entries for HackMatrix presentation
    cursor.execute('SELECT COUNT(*) as count FROM scans')
    count = cursor.fetchone()['count']
    if count == 0:
        seed_starter_data(cursor, conn)

    conn.close()


def seed_starter_data(cursor, conn):
    """Seed initial realistic scans so the dashboard displays live charts immediately."""
    from scanner_engine import analyze_url

    sample_urls = [
        "https://github.com",
        "https://www.wikipedia.org",
        "http://paypa1-secure-billing-service.top/auth",
        "http://192.168.1.1/paypal-update-account/verify.php?token=xyz",
        "https://docs.python.org/3/",
        "http://free-crypto-giveaway-claim2026.xyz/login"
    ]

    for sample_url in sample_urls:
        analysis = analyze_url(sample_url)
        if analysis.get('success'):
            cursor.execute('''
                INSERT INTO scans (
                    url, hostname, risk_score, trust_score, risk_level,
                    is_https, is_ip, warnings_count, details_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '-' || (abs(random()) % 180) || ' minutes'))
            ''', (
                analysis['url'],
                analysis['hostname'],
                analysis['risk_score'],
                analysis['trust_score'],
                analysis['risk_level'],
                1 if analysis['is_https'] else 0,
                1 if analysis['is_ip'] else 0,
                len(analysis['warnings']),
                json.dumps(analysis)
            ))
    conn.commit()


def save_scan(analysis: dict) -> int:
    """Inserts a completed scan analysis and returns the generated row ID."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO scans (
            url, hostname, risk_score, trust_score, risk_level,
            is_https, is_ip, warnings_count, details_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    ''', (
        analysis['url'],
        analysis['hostname'],
        analysis['risk_score'],
        analysis['trust_score'],
        analysis['risk_level'],
        1 if analysis['is_https'] else 0,
        1 if analysis['is_ip'] else 0,
        len(analysis['warnings']),
        json.dumps(analysis)
    ))

    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def get_recent_scans(limit: int = 25):
    """Retrieves recent scans ordered chronologically descending."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT id, url, hostname, risk_score, trust_score, risk_level,
               is_https, is_ip, warnings_count, created_at
        FROM scans
        ORDER BY id DESC
        LIMIT ?
    ''', (limit,))

    rows = cursor.fetchall()
    conn.close()

    results = []
    for row in rows:
        results.append({
            'id': row['id'],
            'url': row['url'],
            'hostname': row['hostname'],
            'risk_score': row['risk_score'],
            'trust_score': row['trust_score'],
            'risk_level': row['risk_level'],
            'is_https': bool(row['is_https']),
            'is_ip': bool(row['is_ip']),
            'warnings_count': row['warnings_count'],
            'created_at': row['created_at']
        })
    return results


def get_scan_by_id(scan_id: int):
    """Retrieves full scan analysis record by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    try:
        details = json.loads(row['details_json'])
    except Exception:
        details = {}

    details['id'] = row['id']
    details['db_created_at'] = row['created_at']
    return details


def get_statistics():
    """Calculates aggregated metrics for dashboard and statistics widgets."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT COUNT(*) as total FROM scans')
    total = cursor.fetchone()['total']

    cursor.execute("SELECT COUNT(*) as count FROM scans WHERE risk_level = 'Low'")
    low_count = cursor.fetchone()['count']

    cursor.execute("SELECT COUNT(*) as count FROM scans WHERE risk_level = 'Medium'")
    med_count = cursor.fetchone()['count']

    cursor.execute("SELECT COUNT(*) as count FROM scans WHERE risk_level = 'High'")
    high_count = cursor.fetchone()['count']

    cursor.execute('SELECT AVG(risk_score) as avg_score FROM scans')
    avg_score_raw = cursor.fetchone()['avg_score']
    avg_score = round(avg_score_raw, 1) if avg_score_raw is not None else 0

    cursor.execute('SELECT COUNT(*) as https_count FROM scans WHERE is_https = 1')
    https_count = cursor.fetchone()['https_count']

    # HTTPS adoption percentage
    https_percent = round((https_count / total * 100), 1) if total > 0 else 0

    conn.close()

    return {
        'total_scanned': total,
        'low_risk_count': low_count,
        'medium_risk_count': med_count,
        'high_risk_count': high_count,
        'avg_risk_score': avg_score,
        'https_adoption_percent': https_percent,
        'threat_ratio': round(((med_count + high_count) / total * 100), 1) if total > 0 else 0
    }


def clear_all_scans():
    """Clears all scan history from the database."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('DELETE FROM scans')
    # Reset autoincrement sequence
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='scans'")

    conn.commit()
    conn.close()
    return True


def save_contact_report(name: str, email: str, subject: str, message: str, report_type: str = 'general'):
    """Saves user-submitted contact or threat report."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO contact_reports (name, email, subject, message, report_type)
        VALUES (?, ?, ?, ?, ?)
    ''', (name.strip(), email.strip(), subject.strip() if subject else '', message.strip(), report_type))

    report_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return report_id
