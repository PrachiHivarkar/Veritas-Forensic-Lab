# VERITAS // Digital Image Forensics Lab & Platform

A comprehensive, modern digital image forensic analysis platform designed for cybersecurity, forensic investigation, and media integrity verification.

![VERITAS Forensic Suite](https://img.shields.io/badge/FORENSICS-INTELLIGENCE-cyan?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-Web%20Platform-black?style=for-the-badge&logo=flask)
![OpenCV](https://img.shields.io/badge/OpenCV-Computer%20Vision-green?style=for-the-badge&logo=opencv)

---

## ⚡ Key Forensic Capabilities

- **🔐 Cryptographic File Integrity Verification**:
  - Instant extraction of MD5, SHA-1, SHA-256, and SHA-512 cryptographic checksums.
  - 1-click clipboard copy for forensic evidence chains of custody.

- **🔬 Error Level Analysis (ELA)**:
  - Interactive split comparison slider (drag divider to compare Original vs ELA heatmap in real time).
  - Dynamic JPEG compression quality slider (30% to 99%) and scale amplifier (2x to 40x).
  - Highlights differing compression histories, composited objects, and spliced pixels.

- **📷 Camera Hardware Fingerprinting & EXIF**:
  - Extraction of Camera Make, Model, Lens Model, Serial Numbers, and Exposure parameters (Shutter Speed, Aperture, ISO, Focal Length, Flash).
  - Searchable raw EXIF tag explorer with instant client-side filtering.

- **🕵️ Editing Software & Tamper Detection**:
  - Detects signatures from Adobe Photoshop, GIMP, Snapseed, Lightroom, Canva, PicsArt, Paint.NET, Photopea, and more.
  - Flags timestamp discrepancies (Capture time vs File modification time).

- **🗺️ Interactive GPS Geolocation Mapping**:
  - Automatically parses EXIF GPS tags (Degrees/Minutes/Seconds to Decimal Latitude & Longitude).
  - Renders an interactive Leaflet map with dark tiles and pinpoint location marker.

- **📡 Sensor Noise & Luminance Analysis**:
  - High-pass noise filter revealing sensor pattern inconsistencies and blurred splicing.
  - Luminance gradient / Sobel edge analysis evaluating lighting continuity across the image.
  - Copy-move feature keypoint matching for duplicated regions.

- **📊 Comprehensive Forensic Reports**:
  - Download official **Court-Ready PDF Forensic Report** generated via ReportLab.
  - Download structured **Plain Text Report (.txt)**.
  - Export machine-readable **Forensic JSON Data**.
  - One-click browser print view.

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

> **Tip:** You can also run `python app.py` directly.

### 4. Optional: Run Desktop Tkinter Interface
If you wish to run the legacy Tkinter desktop interface:
```bash
python main.py --desktop
```

---

## 🧪 Built-in Test Presets

The web interface comes equipped with 3 one-click test presets:
1. **Authentic DSLR Photo**: Nikon D850 capture with authentic exposure, 50mm lens profile, and Pune GPS geolocation.
2. **Manipulated Splice**: Image with duplicated spliced objects, Photoshop signature, and timestamp anomalies.
3. **Sanitized Web Image**: Simulates web/social media compression where all metadata is stripped.

---

## 📁 Project Architecture

```
image_forensics_project/
├── app.py                   # Flask web server & REST API
├── forensic_engine.py       # Core forensic algorithms (hashes, ELA, noise, GPS, scoring)
├── pdf_report_generator.py  # ReportLab PDF, TXT, and JSON report generator
├── generate_samples.py      # Automated generator for forensic test samples
├── main.py                  # Dual launcher (Web platform by default / Desktop GUI)
├── ui_app.py                # Tkinter desktop application
├── image_utils.py           # Legacy hash & software check utilities
├── report_generator.py      # Legacy Tkinter report generator
├── requirements.txt         # Project dependencies
├── templates/
│   └── index.html           # Modern cyberpunk forensic web dashboard
└── static/
    ├── css/
    │   └── style.css        # Responsive dark UI, glassmorphism, split slider styles
    ├── js/
    │   └── app.js           # Client-side reactivity, Leaflet mapping, zoom & loupe
    └── samples/             # Authentic, tampered, and stripped sample images
```

---

## ⚖️ Academic & Investigative Disclaimer
This tool is developed for educational, verification, and forensic investigation purposes. Error Level Analysis and metadata indicators suggest potential post-processing but should be verified in conjunction with primary evidentiary sources.
