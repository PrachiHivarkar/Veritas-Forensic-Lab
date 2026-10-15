"""
VERITAS - Digital Image Forensics Engine
Provides cryptographic verification, EXIF parsing, GPS decoding,
Error Level Analysis (ELA), sensor noise extraction, luminance gradient,
and tamper risk scoring.
"""

import os
import io
import math
import hashlib
import base64
from datetime import datetime
from PIL import Image, ImageEnhance, ImageChops, ExifTags, TiffImagePlugin
import numpy as np
import cv2

KNOWN_EDITING_SOFTWARE = [
    "adobe photoshop", "photoshop", "gimp", "snapseed", "lightroom",
    "canva", "picsart", "paint.net", "photopea", "affinity photo",
    "corel", "paintshop", "pixelmator", "pixlr", "facetune", "vsco",
    "fotor", "befunky", "procreate", "sketchbook", "prisma", "polarr"
]

def calculate_all_hashes(file_bytes):
    """Calculate MD5, SHA-1, SHA-256, and SHA-512 hashes."""
    md5 = hashlib.md5(file_bytes).hexdigest()
    sha1 = hashlib.sha1(file_bytes).hexdigest()
    sha256 = hashlib.sha256(file_bytes).hexdigest()
    sha512 = hashlib.sha512(file_bytes).hexdigest()
    return {
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
        "sha512": sha512
    }

def _convert_gps_to_degrees(value):
    """Helper to convert the GPS coordinates stored in the EXIF to degrees in float."""
    if not value or len(value) < 3:
        return None
    try:
        def to_float(v):
            if hasattr(v, 'numerator') and hasattr(v, 'denominator'):
                return float(v.numerator) / float(v.denominator) if v.denominator != 0 else 0.0
            if isinstance(v, (tuple, list)):
                return float(v[0]) / float(v[1]) if v[1] != 0 else 0.0
            return float(v)

        d = to_float(value[0])
        m = to_float(value[1])
        s = to_float(value[2])
        return d + (m / 60.0) + (s / 3600.0)
    except Exception:
        return None

def extract_gps_info(exif_obj):
    """Extract latitude, longitude, and altitude from EXIF GPSInfo or IFD."""
    if not exif_obj:
        return None

    gps_tags = {}
    # First attempt: get_ifd(ExifTags.IFD.GPSInfo)
    if hasattr(exif_obj, "get_ifd"):
        try:
            gps_ifd = exif_obj.get_ifd(ExifTags.IFD.GPSInfo)
            if gps_ifd:
                for key, val in gps_ifd.items():
                    sub_name = ExifTags.GPSTAGS.get(key, key)
                    gps_tags[sub_name] = val
        except Exception:
            pass

    # Second attempt: standard EXIF GPSInfo tag
    if not gps_tags:
        raw_gps = None
        gps_tag_id = None
        for tag_id, name in ExifTags.TAGS.items():
            if name == "GPSInfo":
                gps_tag_id = tag_id
                break
        if gps_tag_id and gps_tag_id in exif_obj:
            raw_gps = exif_obj[gps_tag_id]

        if raw_gps and isinstance(raw_gps, dict):
            for key, val in raw_gps.items():
                sub_name = ExifTags.GPSTAGS.get(key, key)
                gps_tags[sub_name] = val

    if not gps_tags:
        return None

    lat_dms = gps_tags.get("GPSLatitude")
    lat_ref = gps_tags.get("GPSLatitudeRef", "N")
    lon_dms = gps_tags.get("GPSLongitude")
    lon_ref = gps_tags.get("GPSLongitudeRef", "E")

    if lat_dms and lon_dms:
        lat = _convert_gps_to_degrees(lat_dms)
        lon = _convert_gps_to_degrees(lon_dms)
        if lat is not None and lon is not None:
            if lat_ref == "S":
                lat = -lat
            if lon_ref == "W":
                lon = -lon
            
            altitude = None
            if "GPSAltitude" in gps_tags:
                try:
                    alt_val = gps_tags["GPSAltitude"]
                    if hasattr(alt_val, 'numerator'):
                        altitude = float(alt_val.numerator) / float(alt_val.denominator)
                    else:
                        altitude = float(alt_val)
                except Exception:
                    pass

            return {
                "latitude": round(lat, 6),
                "longitude": round(lon, 6),
                "altitude": round(altitude, 2) if altitude is not None else None,
                "lat_ref": lat_ref,
                "lon_ref": lon_ref
            }
    return None

def parse_exif(image):
    """Extract and categorize all EXIF metadata, GPS, and software tags."""
    raw_exif = {}
    parsed = {
        "has_exif": False,
        "camera": {},
        "exposure": {},
        "software": None,
        "software_detected": False,
        "detected_software_name": None,
        "timestamps": {},
        "gps": None,
        "all_tags": {}
    }

    try:
        exif = image.getexif()
        if not exif:
            return parsed

        parsed["has_exif"] = True

        for tag_id, value in exif.items():
            tag_name = ExifTags.TAGS.get(tag_id, f"Tag_{tag_id}")
            
            # Format value nicely
            clean_value = value
            if isinstance(value, bytes):
                try:
                    clean_value = value.decode("utf-8", errors="ignore").strip("\x00")
                except Exception:
                    clean_value = f"<{len(value)} bytes>"
            elif isinstance(value, (tuple, list)) and len(value) > 10:
                clean_value = f"[{len(value)} items]"
            else:
                clean_value = str(value).strip()

            parsed["all_tags"][tag_name] = clean_value

            # Software detection
            if tag_name == "Software":
                parsed["software"] = clean_value
                sw_lower = clean_value.lower()
                for editor in KNOWN_EDITING_SOFTWARE:
                    if editor in sw_lower:
                        parsed["software_detected"] = True
                        parsed["detected_software_name"] = clean_value
                        break

            # Camera hardware
            if tag_name in ("Make", "Model", "LensMake", "LensModel", "SerialNumber", "BodySerialNumber"):
                parsed["camera"][tag_name] = clean_value

            # Timestamps
            if tag_name in ("DateTime", "DateTimeOriginal", "DateTimeDigitized"):
                parsed["timestamps"][tag_name] = clean_value

            # Exposure
            if tag_name in ("ExposureTime", "FNumber", "ISOSpeedRatings", "FocalLength", "Flash", "WhiteBalance", "ExposureProgram"):
                parsed["exposure"][tag_name] = clean_value

        # Also inspect Exif IFD sub-tags if present
        try:
            for ifd_id in (ExifTags.IFD.Exif, ExifTags.IFD.GPSInfo):
                try:
                    ifd_data = exif.get_ifd(ifd_id)
                    if ifd_data:
                        for tag_id, value in ifd_data.items():
                            tag_name = ExifTags.TAGS.get(tag_id, ExifTags.GPSTAGS.get(tag_id, f"SubTag_{tag_id}"))
                            clean_value = str(value)
                            if tag_name not in parsed["all_tags"]:
                                parsed["all_tags"][tag_name] = clean_value
                            if tag_name == "Software" and not parsed["software_detected"]:
                                parsed["software"] = clean_value
                                for editor in KNOWN_EDITING_SOFTWARE:
                                    if editor in clean_value.lower():
                                        parsed["software_detected"] = True
                                        parsed["detected_software_name"] = clean_value
                                        break
                            if tag_name in ("Make", "Model", "LensMake", "LensModel") and tag_name not in parsed["camera"]:
                                parsed["camera"][tag_name] = clean_value
                            if tag_name in ("DateTimeOriginal", "DateTimeDigitized") and tag_name not in parsed["timestamps"]:
                                parsed["timestamps"][tag_name] = clean_value
                            if tag_name in ("ExposureTime", "FNumber", "ISOSpeedRatings", "FocalLength", "Flash", "WhiteBalance"):
                                parsed["exposure"][tag_name] = clean_value
                except Exception:
                    pass
        except Exception:
            pass

        # GPS Extraction
        parsed["gps"] = extract_gps_info(exif)

    except Exception as e:
        parsed["error"] = str(e)

    return parsed

def perform_ela(image_or_bytes, quality=90, scale=15):
    """
    Error Level Analysis (ELA).
    Resaves image at JPEG quality Q, calculates pixel-wise absolute difference,
    amplifies by scale, and computes error metrics.
    """
    if isinstance(image_or_bytes, (bytes, bytearray)):
        img = Image.open(io.BytesIO(image_or_bytes)).convert("RGB")
    elif isinstance(image_or_bytes, Image.Image):
        img = image_or_bytes.convert("RGB")
    else:
        img = Image.open(image_or_bytes).convert("RGB")

    # Save to in-memory buffer with specified quality
    buffer = io.BytesIO()
    img.save(buffer, "JPEG", quality=quality)
    buffer.seek(0)
    resaved = Image.open(buffer)

    # Compute difference
    diff = ImageChops.difference(img, resaved)

    # Calculate statistics from difference before extreme enhancement
    diff_arr = np.array(diff, dtype=np.float32)
    mean_error = float(np.mean(diff_arr))
    max_error = float(np.max(diff_arr))
    variance = float(np.var(diff_arr))

    # Scale the difference to make artifacts visually pronounced
    # Use ImageEnhance to amplify contrast and brightness
    enhancer = ImageEnhance.Brightness(diff)
    diff_amplified = enhancer.enhance(scale)

    # Convert amplified diff to base64
    out_buf = io.BytesIO()
    diff_amplified.save(out_buf, "PNG")
    ela_base64 = "data:image/png;base64," + base64.b64encode(out_buf.getvalue()).decode("ascii")

    return {
        "ela_image": ela_base64,
        "mean_error": round(mean_error, 2),
        "max_error": round(max_error, 2),
        "variance": round(variance, 2),
        "quality_tested": quality,
        "scale_applied": scale
    }

def perform_noise_analysis(cv_img):
    """
    Sensor Noise Extraction using high-pass filtering (Median difference).
    Inconsistencies in the noise pattern often reveal pasted/composited elements.
    """
    if len(cv_img.shape) == 3:
        gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
    else:
        gray = cv_img

    # Median blur filter to model low frequency content
    denoised = cv2.medianBlur(gray, 3)
    # High frequency noise is the residual
    noise = cv2.absdiff(gray, denoised)
    # Normalize to full 0-255 dynamic range for visualization
    noise_norm = cv2.normalize(noise, None, alpha=0, beta=255, norm_type=cv2.NORM_MINMAX)
    # Apply color map for forensic visual clarity (Inferno or Jet)
    noise_colored = cv2.applyColorMap(noise_norm, cv2.COLORMAP_INFERNO)

    _, buf = cv2.imencode(".png", noise_colored)
    return "data:image/png;base64," + base64.b64encode(buf.tobytes()).decode("ascii")

def perform_luminance_gradient(cv_img):
    """
    Luminance Gradient / Edge Analysis.
    Calculates gradient vectors to verify lighting direction and edge coherence.
    """
    if len(cv_img.shape) == 3:
        gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
    else:
        gray = cv_img

    # Sobel gradients
    grad_x = cv2.Sobel(gray, cv2.CV_32F, 1, 0, ksize=3)
    grad_y = cv2.Sobel(gray, cv2.CV_32F, 0, 1, ksize=3)
    magnitude = cv2.magnitude(grad_x, grad_y)
    mag_norm = cv2.normalize(magnitude, None, alpha=0, beta=255, norm_type=cv2.NORM_MINMAX).astype(np.uint8)

    grad_colored = cv2.applyColorMap(mag_norm, cv2.COLORMAP_VIRIDIS)
    _, buf = cv2.imencode(".png", grad_colored)
    return "data:image/png;base64," + base64.b64encode(buf.tobytes()).decode("ascii")

def perform_color_channel_separation(cv_img):
    """
    Generate YCbCr chrominance and separate color channel views.
    """
    if len(cv_img.shape) != 3:
        return {}

    # YCrCb
    ycrcb = cv2.cvtColor(cv_img, cv2.COLOR_BGR2YCrCb)
    y, cr, cb = cv2.split(ycrcb)

    # Encode Cb and Cr chrominance maps
    cb_colored = cv2.applyColorMap(cb, cv2.COLORMAP_COOL)
    cr_colored = cv2.applyColorMap(cr, cv2.COLORMAP_HOT)

    _, buf_cb = cv2.imencode(".png", cb_colored)
    _, buf_cr = cv2.imencode(".png", cr_colored)

    return {
        "chroma_cb": "data:image/png;base64," + base64.b64encode(buf_cb.tobytes()).decode("ascii"),
        "chroma_cr": "data:image/png;base64," + base64.b64encode(buf_cr.tobytes()).decode("ascii")
    }

def detect_clones_orb(cv_img):
    """
    Copy-Move / Clone Forgery Detection using ORB feature matching.
    Looks for matching keypoint clusters within the same image.
    """
    if len(cv_img.shape) == 3:
        gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
    else:
        gray = cv_img

    # Resize if image is huge for rapid response
    h, w = gray.shape
    scale = 1.0
    if max(h, w) > 1200:
        scale = 1200.0 / max(h, w)
        gray = cv2.resize(gray, (int(w * scale), int(h * scale)))

    orb = cv2.ORB_create(nfeatures=1500)
    keypoints, descriptors = orb.detectAndCompute(gray, None)

    clone_count = 0
    canvas = cv_img.copy()
    if scale != 1.0:
        canvas = cv2.resize(canvas, (int(w * scale), int(h * scale)))

    if descriptors is not None and len(descriptors) > 20:
        bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=False)
        matches = bf.knnMatch(descriptors, descriptors, k=2)

        suspicious_pairs = []
        for match in matches:
            if len(match) == 2:
                m, n = match
                # Ratio test & spatial distance filter (ignore self-match or immediate neighbors)
                if m.distance < 0.65 * n.distance:
                    pt1 = keypoints[m.queryIdx].pt
                    pt2 = keypoints[m.trainIdx].pt
                    spatial_dist = math.hypot(pt1[0] - pt2[0], pt1[1] - pt2[1])
                    if spatial_dist > 40: # Distance threshold to ignore self-points
                        suspicious_pairs.append((pt1, pt2))

        clone_count = len(suspicious_pairs)
        # Draw top suspicious connections
        for pt1, pt2 in suspicious_pairs[:30]:
            p1 = (int(pt1[0]), int(pt1[1]))
            p2 = (int(pt2[0]), int(pt2[1]))
            cv2.line(canvas, p1, p2, (0, 255, 255), 2)
            cv2.circle(canvas, p1, 4, (0, 0, 255), -1)
            cv2.circle(canvas, p2, 4, (0, 255, 0), -1)

    _, buf = cv2.imencode(".png", canvas)
    return {
        "clone_image": "data:image/png;base64," + base64.b64encode(buf.tobytes()).decode("ascii"),
        "suspicious_matches": clone_count
    }

def assess_authenticity(exif_data, ela_stats, clone_data, file_format):
    """
    Forensic Tamper Assessment & Authenticity Scoring Algorithm.
    Returns score (0-100% authenticity), risk level, and forensic findings.
    """
    authenticity_score = 90
    risk_level = "LOW"
    findings = []
    badges = []

    # 1. Editing Software Signature
    if exif_data.get("software_detected"):
        sw = exif_data.get("detected_software_name") or exif_data.get("software")
        authenticity_score -= 40
        findings.append({
            "type": "danger",
            "title": "Editing Software Signature Detected",
            "detail": f"The EXIF metadata explicitly identifies editing software: '{sw}'. This is strong evidence of post-processing or image manipulation."
        })
        badges.append({"label": "SOFTWARE TAMPER", "color": "danger"})
    elif exif_data.get("software"):
        findings.append({
            "type": "warning",
            "title": "Software Tag Present",
            "detail": f"Software tag recorded: '{exif_data['software']}'."
        })

    # 2. EXIF Metadata Availability & Camera Hardware
    if not exif_data.get("has_exif"):
        authenticity_score -= 20
        findings.append({
            "type": "warning",
            "title": "EXIF Metadata Stripped / Absent",
            "detail": "No EXIF header was found. This frequently occurs when images are processed by social media platforms, web compression tools, or forensic scrubbers."
        })
        badges.append({"label": "METADATA STRIPPED", "color": "warning"})
    else:
        cam = exif_data.get("camera", {})
        if cam.get("Make") or cam.get("Model"):
            authenticity_score += 5
            findings.append({
                "type": "success",
                "title": "Hardware Fingerprint Verified",
                "detail": f"Captured with {cam.get('Make', '')} {cam.get('Model', '')}. Camera manufacturer signatures correlate with authentic captures."
            })
            badges.append({"label": "CAMERA METADATA", "color": "success"})

        # Timestamp analysis
        ts = exif_data.get("timestamps", {})
        if "DateTimeOriginal" in ts and "DateTime" in ts:
            if ts["DateTimeOriginal"] != ts["DateTime"]:
                authenticity_score -= 15
                findings.append({
                    "type": "warning",
                    "title": "Timestamp Inconsistency",
                    "detail": f"Capture time ({ts['DateTimeOriginal']}) differs from file modification time ({ts['DateTime']})."
                })

        # GPS Geolocation
        if exif_data.get("gps"):
            authenticity_score += 5
            findings.append({
                "type": "success",
                "title": "GPS Geotag Verified",
                "detail": f"Physical geolocation recorded: {exif_data['gps']['latitude']}°, {exif_data['gps']['longitude']}°."
            })
            badges.append({"label": "GEO-TAGGED", "color": "info"})

    # 3. Error Level Analysis (ELA) Variance
    var = ela_stats.get("variance", 0)
    mean_err = ela_stats.get("mean_error", 0)
    if var > 120 or mean_err > 25:
        authenticity_score -= 25
        findings.append({
            "type": "danger",
            "title": "High Error Level Variance (Inconsistent Compression)",
            "detail": f"ELA error variance is {var:.1f} with mean {mean_err:.1f}. Significant compression anomalies suggest spliced or edited regions with differing JPEG compression histories."
        })
        badges.append({"label": "ELA ANOMALY", "color": "danger"})
    elif var > 60:
        authenticity_score -= 10
        findings.append({
            "type": "warning",
            "title": "Moderate Compression Inconsistency",
            "detail": f"ELA error variance is {var:.1f}. Minor localized variation detected."
        })
    else:
        findings.append({
            "type": "success",
            "title": "Uniform Error Level Surface",
            "detail": f"ELA variance ({var:.1f}) is consistent across the image matrix, typical of uniform compression."
        })

    # 4. Clone / Copy-Move Matches
    clone_matches = clone_data.get("suspicious_matches", 0)
    if clone_matches > 8:
        authenticity_score -= 25
        findings.append({
            "type": "danger",
            "title": f"Possible Copy-Move Forgery Detected ({clone_matches} Keypoint Matches)",
            "detail": f"Detected {clone_matches} highly correlated feature clusters in disjoint regions of the image, indicating duplicated or cloned sections."
        })
        badges.append({"label": "COPY-MOVE DETECTED", "color": "danger"})

    # Clamp score
    authenticity_score = max(5, min(98, authenticity_score))
    tampering_score = 100 - authenticity_score

    if tampering_score >= 60:
        risk_level = "HIGH RISK (MANIPULATION DETECTED)"
        verdict_color = "danger"
    elif tampering_score >= 35:
        risk_level = "MEDIUM RISK (SUSPICIOUS ARTIFACTS)"
        verdict_color = "warning"
    else:
        risk_level = "LOW RISK (LIKELY AUTHENTIC)"
        verdict_color = "success"

    return {
        "authenticity_score": authenticity_score,
        "tampering_score": tampering_score,
        "risk_level": risk_level,
        "verdict_color": verdict_color,
        "findings": findings,
        "badges": badges
    }

def analyze_full_image(file_bytes, filename="uploaded_image"):
    """
    Master pipeline: Runs full cryptographic, metadata, visual forensic,
    and algorithmic analyses on the provided image bytes.
    """
    # 1. Hashes
    hashes = calculate_all_hashes(file_bytes)

    # 2. PIL Image Object
    pil_img = Image.open(io.BytesIO(file_bytes))
    file_format = pil_img.format or "UNKNOWN"
    width, height = pil_img.size
    mode = pil_img.mode

    # Convert to base64 preview
    preview_buf = io.BytesIO()
    # Save a web-friendly preview
    preview_img = pil_img.copy()
    if preview_img.mode in ("RGBA", "P"):
        preview_img = preview_img.convert("RGB")
    preview_img.thumbnail((1200, 1200))
    preview_img.save(preview_buf, "JPEG", quality=85)
    preview_base64 = "data:image/jpeg;base64," + base64.b64encode(preview_buf.getvalue()).decode("ascii")

    # 3. OpenCV representation
    nparr = np.frombuffer(file_bytes, np.uint8)
    cv_img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

    # 4. EXIF & Metadata
    exif_info = parse_exif(pil_img)

    # 5. ELA Analysis
    ela_result = perform_ela(pil_img, quality=90, scale=15)

    # 6. Noise Analysis
    noise_base64 = perform_noise_analysis(cv_img) if cv_img is not None else ""

    # 7. Luminance Gradient
    gradient_base64 = perform_luminance_gradient(cv_img) if cv_img is not None else ""

    # 8. Color Channels
    color_channels = perform_color_channel_separation(cv_img) if cv_img is not None else {}

    # 9. Clone Detection
    clone_result = detect_clones_orb(cv_img) if cv_img is not None else {"clone_image": "", "suspicious_matches": 0}

    # 10. Authenticity Verdict
    verdict = assess_authenticity(exif_info, ela_result, clone_result, file_format)

    file_info = {
        "filename": filename,
        "filesize_bytes": len(file_bytes),
        "filesize_formatted": f"{len(file_bytes) / 1024:.2f} KB" if len(file_bytes) < 1024*1024 else f"{len(file_bytes) / (1024*1024):.2f} MB",
        "format": file_format,
        "width": width,
        "height": height,
        "resolution": f"{width} × {height}",
        "aspect_ratio": f"{round(width/height, 2)}:1" if height > 0 else "N/A",
        "color_mode": mode,
        "analysis_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    return {
        "file_info": file_info,
        "hashes": hashes,
        "exif": exif_info,
        "preview_image": preview_base64,
        "ela": ela_result,
        "noise_image": noise_base64,
        "gradient_image": gradient_base64,
        "color_channels": color_channels,
        "clone_detection": clone_result,
        "verdict": verdict
    }
