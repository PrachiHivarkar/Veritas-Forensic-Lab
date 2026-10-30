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

    print("=" * 80)
    print("   FORENSICS.DB - SQLITE DATABASE INSPECTION TOOL")
    print(f"   Location: {DB_PATH}")
    print("=" * 80)

    # 1. Inspect Users Table
    print("\n--- [TABLE: users] ---")
    cursor.execute("SELECT id, username, email, full_name, created_at FROM users")
    users = cursor.fetchall()
    if users:
        print(f"{'ID':<4} | {'Username':<15} | {'Email':<28} | {'Full Name':<25}")
        print("-" * 80)
        for u in users:
            print(f"{u['id']:<4} | {u['username']:<15} | {u['email']:<28} | {u['full_name'] or '-':<25}")
    else:
        print("No users found.")

    # 2. Inspect Analysis History Table
    print("\n--- [TABLE: analysis_history] ---")
    cursor.execute("""
        SELECT id, user_id, filename, image_format, resolution, md5, verdict, authenticity_score, created_at
        FROM analysis_history
        ORDER BY id DESC
    """)
    history = cursor.fetchall()
    if history:
        print(f"{'ID':<4} | {'File Name':<22} | {'Format':<6} | {'Score':<6} | {'Verdict':<32}")
        print("-" * 80)
        for h in history:
            print(f"{h['id']:<4} | {h['filename'][:20]:<22} | {h['image_format']:<6} | {h['authenticity_score']}%{'':<3} | {h['verdict']:<32}")
    else:
        print("No analysis records found yet.")

    print("\n" + "=" * 80 + "\n")
    conn.close()


if __name__ == "__main__":
    view_database()
