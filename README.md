# Digital Image Forensics System & Web Platform

A comprehensive digital image forensic analysis platform developed as a Computer Engineering Final Year Mini Project at **PES Modern College of Engineering, Pune (Savitribai Phule Pune University)**.

Guided by: **Mrs. Priyanka Hoval**  
Project Team: **Kalyani Borse (42209)**, **Shashank Dattu (42212)**, **Prachi Hivarkar (42219)**

---

## 📌 Project Overview

Digital images are widely used as documentation and evidence in legal proceedings, journalism, education, and cybersecurity. However, digital images can be manipulated using photo-editing tools (such as Adobe Photoshop, GIMP, Canva, or Snapseed).

This project provides a clean, unified web platform and desktop tool to inspect digital images, verify their file integrity, analyze compression anomalies, extract camera metadata, and track investigation history in a local SQLite database.

---

## ⚡ Key Features

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

- **🗄️ User Authentication & SQLite Database**:
  - User registration and login system with secure password hashing (`werkzeug.security`).
  - Automatic audit logging: every scan is stored in `forensics.db` with timestamp, file metrics, verdict, and authenticity score.
  - Investigation History page with search and delete options.
  - Default demo accounts for project evaluation:
    - **Student**: `student` / `password123`
    - **Admin**: `admin` / `admin123`

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
*Your browser will automatically open to `http://127.0.0.1:5000`.*

### 4. Optional: Run Desktop Tkinter GUI
To run the original Tkinter desktop window:
```bash
python main.py --desktop
```

---

## 🧪 Built-in Test Cases

The application includes 3 one-click test cases for presentation:
1. **Authentic DSLR Photo**: Nikon D850 DSLR capture with authentic hardware EXIF and Pune GPS coordinates.
2. **Manipulated Splice**: Image with duplicated spliced objects, Photoshop signature, and timestamp anomalies.
3. **Metadata Stripped Image**: Simulates social media / web compression with all camera metadata removed.

---

## 📁 Project Architecture

```
image_forensics_project/
├── app.py                   # Flask server, authentication & REST API
├── database.py              # SQLite database manager (users & history logs)
├── forensics.db             # Local SQLite database file
├── forensic_engine.py       # Core forensic algorithms (hashes, ELA, noise, GPS, scoring)
├── pdf_report_generator.py  # ReportLab PDF, TXT, and JSON report generator
├── generate_samples.py      # Automated generator for forensic test samples
├── main.py                  # Dual launcher (Web platform by default / Desktop GUI)
├── ui_app.py                # Original desktop Tkinter application
├── image_utils.py           # Original image hash & software detection utilities
├── report_generator.py      # Original desktop report generator
├── requirements.txt         # Project dependencies
├── README.md                # Documentation & academic project details
├── preview.html             # Interactive project simulator
├── templates/
│   ├── base.html            # Main academic base template with college banner & navbar
│   ├── index.html           # Main analysis dashboard with split slider & dossier
│   ├── login.html           # Student & investigator login page
│   ├── register.html        # New user registration page
│   ├── history.html         # SQLite forensic history audit table & search
│   └── about.html           # Team members, guide & SPPU project details
└── static/
    ├── css/style.css        # Academic styling, split slider & clean card layouts
    ├── js/app.js            # Client-side reactivity, Leaflet GPS & ELA tuning
    └── samples/             # Authentic, tampered, and stripped test samples
```
