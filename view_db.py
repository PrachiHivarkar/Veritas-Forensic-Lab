"""
Helper script to view all tables and records in forensics.db from the terminal.
Usage: python view_db.py
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensics.db")


def view_database():
    if not os.path.exists(DB_PATH):
        print(f"[-] Database file not found at {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    print("=" * 85)
    print("   FORENSICS.DB - SQLITE DATABASE INSPECTION TOOL")
    print(f"   Location: {DB_PATH}")
    print("=" * 85)

    # 1. Inspect Users Table with Role
    print("\n--- [TABLE: users] ---")
    cursor.execute("SELECT id, username, email, full_name, role, created_at FROM users")
    users = cursor.fetchall()
    if users:
        print(f"{'ID':<4} | {'Username':<14} | {'Role':<8} | {'Email':<25} | {'Full Name':<20}")
        print("-" * 85)
        for u in users:
            print(f"{u['id']:<4} | {u['username']:<14} | {u['role']:<8} | {u['email']:<25} | {u['full_name'] or '-':<20}")
    else:
        print("No users found.")

    # 2. Inspect Analysis History Table
    print("\n--- [TABLE: analysis_history] ---")
    cursor.execute("""
        SELECT h.id, u.username, h.filename, h.image_format, h.resolution, h.md5, h.verdict, h.authenticity_score, h.created_at
        FROM analysis_history h
        LEFT JOIN users u ON h.user_id = u.id
        ORDER BY h.id DESC
    """)
    history = cursor.fetchall()
    if history:
        print(f"{'ID':<4} | {'Analyst':<12} | {'File Name':<20} | {'Score':<6} | {'Verdict':<32}")
        print("-" * 85)
        for h in history:
            analyst = h['username'] or 'System'
            print(f"{h['id']:<4} | {analyst:<12} | {h['filename'][:18]:<20} | {h['authenticity_score']}%{'':<3} | {h['verdict']:<32}")
    else:
        print("No analysis records found yet.")

    print("\n" + "=" * 85 + "\n")
    conn.close()


if __name__ == "__main__":
    view_database()
