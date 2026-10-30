# Digital Image Forensics System & Web Platform

A comprehensive digital image forensic analysis platform for image authentication, Error Level Analysis (ELA), cryptographic file integrity verification, and audit history tracking.

---

## 📌 Project Overview

Digital images are widely used as documentation and evidence in legal proceedings, journalism, education, and cybersecurity. However, digital images can be manipulated using photo-editing tools (such as Adobe Photoshop, GIMP, Canva, or Snapseed).

This project provides a unified web platform and desktop tool to inspect digital images, verify their file integrity, analyze compression anomalies, extract camera metadata, and track investigation history in a local SQLite database.

---

## ⚡ Key Features

- **🔒 Mandatory Authentication & Role-Based Access**:
  - Secure login and registration with password hashing (`werkzeug.security`).
  - Users are greeted with the **Sign In / Registration** screen before accessing the system.
  - **Lab Administrator**:
    - Keeps track of all registered users, their scan activities, and system audit logs.
    - Dedicated **User Records** management panel (`/admin/users`).
    - Full visibility over all case logs across all users.
  - **Forensic Analyst (User)**:
    - Ingests and analyzes images.
    - Inspects and manages their own case investigation history.

- **🔐 Cryptographic File Integrity**:
  - Calculates MD5, SHA-1, SHA-256, and SHA-512 cryptographic digests to establish file fingerprints and evidence chains of custody.
  - 1-click clipboard copy for verification.

- **🔬 Error Level Analysis (ELA)**:
  - Interactive split slider to compare original photos against the ELA heatmap.
  - Real-time sliders to tune JPEG quality (30% to 98%) and scale amplifier (2x to 40x).
  - Highlights differing compression histories and spliced/pasted layers.

- **📷 Camera Hardware Fingerprinting & EXIF**:
  - Extracts Camera Make, Model, Lens Model, Shutter Speed, Aperture ($f$-stop), ISO, Focal Length, and Flash.
  - Searchable raw EXIF tags table with instant filter.

- **🕵️ Editing Software & Tamper Checks**:
  - Detects signatures of known editors (Photoshop, GIMP, Canva, Snapseed, Lightroom, PicsArt, etc.).
  - Flags timestamp discrepancies (Capture time vs File modification time).

- **🗺️ Interactive GPS Geolocation Mapping**:
  - Automatically parses EXIF GPS DMS coordinates into decimal latitude & longitude.
  - Displays capture coordinates and pinpoints location on an interactive OpenStreetMap (Leaflet.js).

- **🗄️ Persistent SQLite Database (`forensics.db`)**:
  - Automatically records every analysis into `analysis_history` table with timestamps, file metrics, verdict, and authenticity score.
  - Pre-configured system accounts:
    - **Lab Administrator**: `admin` / `admin123`
    - **Forensic Analyst**: `user1` / `password123`

- **📊 Comprehensive Forensic Reports**:
  - Download official court-ready **PDF Forensic Report** generated using ReportLab.
  - Download structured **Plain Text Report (.txt)**.
  - Export machine-readable **Forensic JSON Data**.

---

## 🚀 Getting Started

### 1. Requirements
Ensure Python 3.9 or newer is installed:
```bash
python --version
```

### 2. Install Dependencies
```bash
python -m pip install -r requirements.txt
```

### 3. Launch the Web Platform
```bash
python main.py
```
*Your browser will automatically open to `http://127.0.0.1:5000` presenting the Sign In screen.*

### 4. Default Credentials
- **Lab Administrator**:
  - Username: `admin`
  - Password: `admin123`
- **Forensic Analyst**:
  - Username: `user1`
  - Password: `password123`
- Or register a new account from the Sign In page.

### 5. Optional: Run Desktop Tkinter GUI
To run the original Tkinter desktop window:
```bash
python main.py --desktop
```

---

## 📁 Project Architecture

```
image_forensics_project/
├── app.py                   # Flask server, authentication & role routes
├── database.py              # SQLite database manager (users, roles, history)
├── forensics.db             # Local SQLite database file
├── forensic_engine.py       # Core forensic algorithms (hashes, ELA, noise, GPS, scoring)
├── pdf_report_generator.py  # ReportLab PDF, TXT, and JSON report generator
├── generate_samples.py      # Automated generator for forensic test samples
├── view_db.py               # Terminal utility to inspect SQLite database tables
├── main.py                  # Dual launcher (Web platform by default / Desktop GUI)
├── ui_app.py                # Original desktop Tkinter application
├── image_utils.py           # Original image hash & software detection utilities
├── report_generator.py      # Original desktop report generator
├── requirements.txt         # Project dependencies
├── README.md                # Documentation & system details
├── preview.html             # Project simulation preview
├── templates/
│   ├── base.html            # System layout, header banner & navbar
│   ├── index.html           # Main analysis dashboard (split slider, ELA, dossier)
│   ├── login.html           # User & Administrator sign in page
│   ├── register.html        # New user registration page
│   ├── history.html         # SQLite forensic history audit table & search
│   ├── admin_users.html     # Lab Administrator user management table
│   └── about.html           # System architecture, forensic methods & specifications
└── static/
    ├── css/style.css        # Responsive layout, split slider & clean card layouts
    ├── js/app.js            # Client-side reactivity, Leaflet GPS & ELA tuning
    └── samples/             # Authentic, tampered, and stripped test samples
```
