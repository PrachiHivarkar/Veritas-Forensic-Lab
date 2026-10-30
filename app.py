"""
Digital Image Forensics Tool - Web Platform & REST API Server
A unified platform for image authentication, Error Level Analysis (ELA),
cryptographic verification, and user management.
"""

import os
import io
import json
from functools import wraps
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session, flash
from flask_cors import CORS
import forensic_engine
import pdf_report_generator
import database

app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)
app.secret_key = os.environ.get("SECRET_KEY", "digital_forensics_lab_auth_key_2026")
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32 MB max upload

# Initialize database on server startup
database.init_db()

# In-memory storage for active session analysis
LAST_ANALYSIS = {}
LAST_IMAGE_BYTES = None
LAST_FILENAME = "image"

SAMPLE_INFO = [
    {
        "id": "sample_authentic.jpg",
        "title": "Authentic Camera Capture",
        "badge": "Genuine EXIF + GPS",
        "badge_color": "success",
        "desc": "DSLR photo with genuine camera hardware EXIF, lens profile, and embedded GPS coordinates."
    },
    {
        "id": "sample_tampered.jpg",
        "title": "Manipulated / Spliced Image",
        "badge": "Photoshop + Splice",
        "badge_color": "danger",
        "desc": "Altered image with spliced objects, editing software signature, and timestamp inconsistencies."
    },
    {
        "id": "sample_stripped.png",
        "title": "Metadata Stripped Image",
        "badge": "Metadata Stripped",
        "badge_color": "warning",
        "desc": "Web/social media graphic with camera metadata scrubbed during compression."
    }
]


# -------------------------------------------------------------
# Authentication & Role Decorators
# -------------------------------------------------------------

def login_required(f):
    """Decorator to require login before accessing routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to access the system.", "info")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to restrict access to Lab Administrators only."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Administrator login required.", "danger")
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            flash("Access denied. Administrator privileges required.", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function


@app.context_processor
def inject_user():
    """Make current_user and user role accessible in all Jinja templates."""
    user = None
    if "user_id" in session:
        user = database.get_user_by_id(session["user_id"])
    return dict(current_user=user)


# -------------------------------------------------------------
# Web Page Routes
# -------------------------------------------------------------

@app.route("/")
def index():
    """Home / Analysis dashboard. Requires login; redirects to /login if not authenticated."""
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session.get("user_id")
    is_admin = (session.get("role") == "admin")
    stats = database.get_dashboard_statistics(user_id=user_id, is_admin=is_admin)
    return render_template("index.html", stats=stats)


@app.route("/login", methods=["GET", "POST"])
def login():
    """User and Administrator login page."""
    if "user_id" in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "").strip()

        if not identifier or not password:
            flash("Please enter both username/email and password.", "danger")
            return render_template("login.html")

        user = database.verify_user(identifier, password)
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["full_name"] = user["full_name"]
            session["role"] = user.get("role", "user")

            role_title = "Lab Administrator" if user.get("role") == "admin" else "Forensic Analyst"
            flash(f"Welcome, {user['full_name'] or user['username']} ({role_title})!", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid username/email or password. Please try again.", "danger")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """New user registration page."""
    if "user_id" in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        if not username or not email or not password:
            flash("All required fields must be filled out.", "danger")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")

        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "danger")
            return render_template("register.html")

        # Standard users are registered with role 'user'
        result = database.create_user(username, email, password, full_name, role="user")
        if result["success"]:
            session["user_id"] = result["user_id"]
            session["username"] = username
            session["full_name"] = full_name
            session["role"] = "user"
            flash("Account registered successfully! You are now logged in.", "success")
            return redirect(url_for("index"))
        else:
            flash(result["error"], "danger")

    return render_template("register.html")


@app.route("/logout")
def logout():
    """Clear session and log out."""
    session.clear()
    flash("You have been signed out successfully.", "info")
    return redirect(url_for("login"))


@app.route("/history")
@login_required
def history():
    """
    Display investigation history:
    - Administrator sees audit logs across ALL users.
    - Regular users see only their own analyses.
    """
    user_id = session.get("user_id")
    is_admin = (session.get("role") == "admin")
    records = database.get_user_history(user_id=user_id, is_admin=is_admin, limit=100)
    stats = database.get_dashboard_statistics(user_id=user_id, is_admin=is_admin)
    return render_template("history.html", records=records, stats=stats, is_admin=is_admin)


@app.route("/admin/users")
@admin_required
def admin_users():
    """Lab Administrator panel to view and manage all registered users."""
    users = database.get_all_users_with_stats()
    return render_template("admin_users.html", users=users)


@app.route("/admin/users/delete/<int:target_user_id>", methods=["POST"])
@admin_required
def delete_user_route(target_user_id):
    """Delete a user account (Lab Administrator only)."""
    success, msg = database.delete_user(target_user_id)
    if success:
        flash(msg, "success")
    else:
        flash(msg, "danger")
    return redirect(url_for("admin_users"))


@app.route("/about")
def about():
    """About project, forensic methodologies, and system architecture."""
    return render_template("about.html")


# -------------------------------------------------------------
# REST API Endpoints
# -------------------------------------------------------------

@app.route("/api/samples", methods=["GET"])
@login_required
def get_samples():
    """Get list of pre-configured sample images."""
    return jsonify({"samples": SAMPLE_INFO})


@app.route("/api/sample-image/<name>", methods=["GET"])
def serve_sample(name):
    """Serve sample file from static/samples folder."""
    safe_name = os.path.basename(name)
    sample_path = os.path.join(app.static_folder, "samples", safe_name)
    if os.path.exists(sample_path):
        return send_file(sample_path)
    return jsonify({"error": "Sample not found"}), 404


@app.route("/api/analyze", methods=["POST"])
@login_required
def analyze_image():
    """Core image analysis endpoint. Automatically saves record to SQLite database."""
    global LAST_IMAGE_BYTES, LAST_FILENAME, LAST_ANALYSIS
    file_bytes = None
    filename = "uploaded_image"

    # Check if a sample was requested via JSON
    if request.is_json:
        data = request.get_json()
        sample_id = data.get("sample")
        if sample_id:
            safe_id = os.path.basename(sample_id)
            sample_path = os.path.join(app.static_folder, "samples", safe_id)
            if os.path.exists(sample_path):
                with open(sample_path, "rb") as f:
                    file_bytes = f.read()
                filename = safe_id
            else:
                return jsonify({"error": f"Sample {sample_id} not found"}), 404

    # Otherwise check multipart upload
    if file_bytes is None:
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded or sample selected"}), 400
        uploaded_file = request.files["file"]
        if uploaded_file.filename == "":
            return jsonify({"error": "Empty filename"}), 400
        filename = uploaded_file.filename
        file_bytes = uploaded_file.read()

    try:
        results = forensic_engine.analyze_full_image(file_bytes, filename=filename)
        LAST_IMAGE_BYTES = file_bytes
        LAST_FILENAME = filename
        LAST_ANALYSIS = results

        # Save record to SQLite database linked to current authenticated user
        user_id = session.get("user_id")
        record_id = database.save_analysis_record(user_id, results)
        results["record_id"] = record_id

        return jsonify(results)
    except Exception as e:
        return jsonify({"error": f"Failed to analyze image: {str(e)}"}), 500


@app.route("/api/ela", methods=["POST"])
@login_required
def recalculate_ela():
    """Recompute ELA with custom quality and scale parameters."""
    global LAST_IMAGE_BYTES
    if not LAST_IMAGE_BYTES:
        return jsonify({"error": "No image loaded yet to compute ELA"}), 400

    data = request.get_json() or {}
    quality = int(data.get("quality", 90))
    scale = int(data.get("scale", 15))

    quality = max(30, min(99, quality))
    scale = max(1, min(50, scale))

    try:
        ela_res = forensic_engine.perform_ela(LAST_IMAGE_BYTES, quality=quality, scale=scale)
        if LAST_ANALYSIS:
            LAST_ANALYSIS["ela"] = ela_res
        return jsonify(ela_res)
    except Exception as e:
        return jsonify({"error": f"ELA calculation error: {str(e)}"}), 500


@app.route("/api/download-report/<fmt>", methods=["GET"])
@login_required
def download_report(fmt):
    """Download forensic report in PDF, TXT, or JSON format."""
    global LAST_ANALYSIS, LAST_FILENAME
    if not LAST_ANALYSIS:
        return jsonify({"error": "No forensic analysis data available. Analyze an image first."}), 400

    base_name = os.path.splitext(LAST_FILENAME)[0]

    if fmt == "pdf":
        try:
            pdf_bytes = pdf_report_generator.generate_pdf_report_bytes(LAST_ANALYSIS)
            return send_file(
                io.BytesIO(pdf_bytes),
                mimetype="application/pdf",
                as_attachment=True,
                download_name=f"Forensic_Report_{base_name}.pdf"
            )
        except Exception as e:
            return jsonify({"error": f"PDF generation failed: {str(e)}"}), 500

    elif fmt == "txt":
        txt_content = pdf_report_generator.generate_text_report(LAST_ANALYSIS)
        return send_file(
            io.BytesIO(txt_content.encode("utf-8")),
            mimetype="text/plain; charset=utf-8",
            as_attachment=True,
            download_name=f"Forensic_Report_{base_name}.txt"
        )

    elif fmt == "json":
        clean_json = {
            "file_info": LAST_ANALYSIS.get("file_info"),
            "hashes": LAST_ANALYSIS.get("hashes"),
            "exif": {
                "has_exif": LAST_ANALYSIS.get("exif", {}).get("has_exif"),
                "camera": LAST_ANALYSIS.get("exif", {}).get("camera"),
                "exposure": LAST_ANALYSIS.get("exif", {}).get("exposure"),
                "software": LAST_ANALYSIS.get("exif", {}).get("software"),
                "software_detected": LAST_ANALYSIS.get("exif", {}).get("software_detected"),
                "timestamps": LAST_ANALYSIS.get("exif", {}).get("timestamps"),
                "gps": LAST_ANALYSIS.get("exif", {}).get("gps"),
                "all_tags": LAST_ANALYSIS.get("exif", {}).get("all_tags"),
            },
            "ela_metrics": {
                "mean_error": LAST_ANALYSIS.get("ela", {}).get("mean_error"),
                "max_error": LAST_ANALYSIS.get("ela", {}).get("max_error"),
                "variance": LAST_ANALYSIS.get("ela", {}).get("variance"),
                "quality_tested": LAST_ANALYSIS.get("ela", {}).get("quality_tested"),
                "scale_applied": LAST_ANALYSIS.get("ela", {}).get("scale_applied"),
            },
            "verdict": LAST_ANALYSIS.get("verdict"),
            "clone_matches": LAST_ANALYSIS.get("clone_detection", {}).get("suspicious_matches", 0)
        }
        return send_file(
            io.BytesIO(json.dumps(clean_json, indent=2).encode("utf-8")),
            mimetype="application/json",
            as_attachment=True,
            download_name=f"Forensic_Data_{base_name}.json"
        )

    return jsonify({"error": f"Unknown format '{fmt}'. Use 'pdf', 'txt', or 'json'."}), 400


@app.route("/api/history/<int:record_id>", methods=["DELETE"])
@login_required
def delete_history_api(record_id):
    """Delete a record from analysis history. Administrator can delete any; users only their own."""
    user_id = session.get("user_id")
    is_admin = (session.get("role") == "admin")
    success = database.delete_history_record(record_id, user_id=user_id, is_admin=is_admin)
    if success:
        return jsonify({"success": True, "message": "Record deleted."})
    return jsonify({"success": False, "error": "Record not found or not authorized."}), 404


@app.route("/health")
def health():
    """System health check endpoint."""
    return jsonify({
        "status": "online",
        "system": "Digital Image Forensics System",
        "database": "SQLite (Connected)"
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting Digital Image Forensics Web Platform on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=True)
