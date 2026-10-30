"""
Database module for Digital Image Forensics Tool.
Uses SQLite for storage of user accounts, roles (Administrator vs User), and analysis history.
"""

import sqlite3
import os
import json
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensics.db")


def get_db_connection():
    """Establish connection to SQLite database with Row factory."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database tables, ensure roles exist, and seed default accounts."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Users table with role column ('admin' or 'user')
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # Check if 'role' column exists in case table was created earlier without it
    cursor.execute("PRAGMA table_info(users)")
    columns = [col["name"] for col in cursor.fetchall()]
    if "role" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
        conn.commit()

    # Analysis history table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analysis_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            filename TEXT NOT NULL,
            filesize TEXT,
            image_format TEXT,
            resolution TEXT,
            md5 TEXT,
            sha256 TEXT,
            verdict TEXT,
            authenticity_score INTEGER,
            software_detected TEXT,
            camera_info TEXT,
            gps_info TEXT,
            findings_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
        );
    """)

    # Ensure default Administrator and User accounts exist
    cursor.execute("SELECT id, username, role FROM users WHERE username = 'admin'")
    admin_row = cursor.fetchone()
    if not admin_row:
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, full_name, role)
            VALUES (?, ?, ?, ?, ?)
        """, (
            "admin",
            "admin@forensics.local",
            generate_password_hash("admin123"),
            "Lab Administrator",
            "admin"
        ))
    else:
        # Ensure role is set to 'admin'
        cursor.execute("UPDATE users SET role = 'admin' WHERE username = 'admin'")

    cursor.execute("SELECT id FROM users WHERE username = 'user1'")
    if not cursor.fetchone():
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, full_name, role)
            VALUES (?, ?, ?, ?, ?)
        """, (
            "user1",
            "user1@forensics.local",
            generate_password_hash("password123"),
            "Forensic Analyst",
            "user"
        ))

    conn.commit()
    conn.close()


def create_user(username, email, password, full_name="", role="user"):
    """Register a new user account."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        pw_hash = generate_password_hash(password)
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, full_name, role)
            VALUES (?, ?, ?, ?, ?)
        """, (username.strip(), email.strip().lower(), pw_hash, full_name.strip(), role))
        conn.commit()
        user_id = cursor.lastrowid
        return {"success": True, "user_id": user_id}
    except sqlite3.IntegrityError as e:
        err_msg = str(e).lower()
        if "username" in err_msg:
            return {"success": False, "error": "Username is already registered."}
        elif "email" in err_msg:
            return {"success": False, "error": "Email address is already registered."}
        return {"success": False, "error": "User already exists."}
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        conn.close()


def verify_user(identifier, password):
    """Authenticate user with username/email and password."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM users
        WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)
    """, (identifier.strip(), identifier.strip()))
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user["password_hash"], password):
        return dict(user)
    return None


def get_user_by_id(user_id):
    """Fetch user by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, full_name, role, created_at FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None


def get_all_users_with_stats():
    """Fetch all users and their respective scan statistics for the Administrator."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT 
            u.id, 
            u.username, 
            u.email, 
            u.full_name, 
            u.role, 
            u.created_at,
            COUNT(h.id) AS scan_count,
            MAX(h.created_at) AS last_scan_date
        FROM users u
        LEFT JOIN analysis_history h ON u.id = h.user_id
        GROUP BY u.id
        ORDER BY u.id ASC
    """)
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return users


def delete_user(user_id):
    """Delete a user account (admin only). Prevents deleting the primary admin."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if user is primary admin
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    if row and row["username"] == "admin":
        conn.close()
        return False, "Cannot delete primary system administrator account."
    
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    affected = cursor.rowcount
    conn.close()
    return affected > 0, "User account deleted successfully."


def save_analysis_record(user_id, analysis_data):
    """Save forensic analysis results to the database associated with user_id."""
    fi = analysis_data.get("file_info", {})
    hashes = analysis_data.get("hashes", {})
    exif = analysis_data.get("exif", {})
    verdict = analysis_data.get("verdict", {})

    filename = fi.get("filename", "unknown_image")
    filesize = fi.get("filesize_formatted", "-")
    img_format = fi.get("format", "-")
    resolution = fi.get("resolution", "-")
    md5 = hashes.get("md5", "-")
    sha256 = hashes.get("sha256", "-")
    risk_level = verdict.get("risk_level", "UNKNOWN")
    auth_score = verdict.get("authenticity_score", 0)

    # Software detected
    software_str = ""
    if exif.get("software_detected"):
        software_str = exif.get("detected_software_name") or exif.get("software") or "Detected"
    elif exif.get("software"):
        software_str = exif.get("software")

    # Camera summary
    cam = exif.get("camera", {})
    cam_str = f"{cam.get('Make', '')} {cam.get('Model', '')}".strip()

    # GPS summary
    gps = exif.get("gps")
    gps_str = f"{gps['latitude']}°, {gps['longitude']}°" if gps else ""

    # JSON of findings
    findings_json = json.dumps(verdict.get("findings", []))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO analysis_history (
            user_id, filename, filesize, image_format, resolution,
            md5, sha256, verdict, authenticity_score, software_detected,
            camera_info, gps_info, findings_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id, filename, filesize, img_format, resolution,
        md5, sha256, risk_level, auth_score, software_str,
        cam_str, gps_str, findings_json
    ))
    conn.commit()
    record_id = cursor.lastrowid
    conn.close()
    return record_id


def get_user_history(user_id=None, is_admin=False, limit=100):
    """
    Fetch analysis history:
    - If is_admin=True, fetch records across ALL users.
    - If is_admin=False, fetch records belonging specifically to user_id.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    if is_admin:
        cursor.execute("""
            SELECT h.*, u.username, u.full_name as user_full_name, u.role as user_role
            FROM analysis_history h
            LEFT JOIN users u ON h.user_id = u.id
            ORDER BY h.id DESC
            LIMIT ?
        """, (limit,))
    else:
        cursor.execute("""
            SELECT h.*, u.username, u.full_name as user_full_name, u.role as user_role
            FROM analysis_history h
            LEFT JOIN users u ON h.user_id = u.id
            WHERE h.user_id = ?
            ORDER BY h.id DESC
            LIMIT ?
        """, (user_id, limit))

    records = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return records


def get_history_record_by_id(record_id):
    """Fetch single analysis record by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT h.*, u.username
        FROM analysis_history h
        LEFT JOIN users u ON h.user_id = u.id
        WHERE h.id = ?
    """, (record_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def delete_history_record(record_id, user_id=None, is_admin=False):
    """Delete a record from analysis history. Admin can delete any; users only their own."""
    conn = get_db_connection()
    cursor = conn.cursor()
    if is_admin:
        cursor.execute("DELETE FROM analysis_history WHERE id = ?", (record_id,))
    else:
        cursor.execute("DELETE FROM analysis_history WHERE id = ? AND user_id = ?", (record_id, user_id))
    conn.commit()
    affected = cursor.rowcount
    conn.close()
    return affected > 0


def get_dashboard_statistics(user_id=None, is_admin=False):
    """Return summary stats of scans."""
    conn = get_db_connection()
    cursor = conn.cursor()

    base_query = "SELECT COUNT(*) as total, " \
                 "SUM(CASE WHEN verdict LIKE '%AUTHENTIC%' THEN 1 ELSE 0 END) as authentic_count, " \
                 "SUM(CASE WHEN verdict LIKE '%MANIPULATION%' OR verdict LIKE '%HIGH%' THEN 1 ELSE 0 END) as tampered_count, " \
                 "SUM(CASE WHEN verdict LIKE '%SUSPICIOUS%' OR verdict LIKE '%STRIPPED%' OR verdict LIKE '%MEDIUM%' THEN 1 ELSE 0 END) as suspicious_count " \
                 "FROM analysis_history"

    if is_admin or not user_id:
        cursor.execute(base_query)
    else:
        cursor.execute(base_query + " WHERE user_id = ?", (user_id,))

    row = cursor.fetchone()
    conn.close()

    total = row["total"] or 0
    return {
        "total_scans": total,
        "authentic_count": row["authentic_count"] or 0,
        "tampered_count": row["tampered_count"] or 0,
        "suspicious_count": row["suspicious_count"] or 0,
    }


if __name__ == "__main__":
    init_db()
    print("Database initialized successfully at:", DB_PATH)
