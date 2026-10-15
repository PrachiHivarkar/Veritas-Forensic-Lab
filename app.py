"""
VERITAS - Digital Image Forensics Web Application Server
Flask-based backend providing REST API and interactive forensic web interface.
"""

import os
import io
import json
from flask import Flask, render_template, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
import forensic_engine
import pdf_report_generator

app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32 MB max upload

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
        "desc": "Nikon D850 DSLR photo with genuine lens profiles, ISO 100, and Pune GPS geolocation."
    },
    {
        "id": "sample_tampered.jpg",
        "title": "Manipulated / Cloned Image",
        "badge": "Photoshop + Splice",
        "badge_color": "danger",
        "desc": "Altered image with duplicated spliced objects, Photoshop metadata signature, and time mismatch."
    },
    {
        "id": "sample_stripped.png",
        "title": "Stripped Web Asset",
        "badge": "No EXIF",
        "badge_color": "warning",
        "desc": "Sanitized graphic with all camera metadata removed, simulating social media compression."
    }
]

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/samples", methods=["GET"])
def get_samples():
    return jsonify({"samples": SAMPLE_INFO})

@app.route("/api/sample-image/<name>", methods=["GET"])
def serve_sample(name):
    # Sanitize name
    safe_name = os.path.basename(name)
    sample_path = os.path.join(app.static_folder, "samples", safe_name)
    if os.path.exists(sample_path):
        return send_file(sample_path)
    return jsonify({"error": "Sample not found"}), 404

@app.route("/api/analyze", methods=["POST"])
def analyze_image():
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
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": f"Failed to analyze image: {str(e)}"}), 500

@app.route("/api/ela", methods=["POST"])
def recalculate_ela():
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
def download_report(fmt):
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
        # Create sanitized serializable dict without heavy image data URLs for compact JSON
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

@app.route("/health")
def health():
    return jsonify({"status": "online", "engine": "VERITAS Forensic Suite 2.0"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting VERITAS Forensic Web Platform on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=True)
