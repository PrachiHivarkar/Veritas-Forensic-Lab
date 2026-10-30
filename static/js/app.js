/**
 * Digital Image Forensics System - Client Application
 * Department of Computer Engineering, PES Modern College of Engineering, Pune.
 * Handles file ingestion, live ELA re-computation, split comparison slider,
 * Leaflet GPS mapping, magnifier loupe, and report downloads.
 */

document.addEventListener("DOMContentLoaded", () => {
    // State
    let currentAnalysis = null;
    let currentMode = "original";
    let isDraggingSplit = false;
    let leafletMap = null;
    let currentZoom = 1.0;
    let isLoupeActive = false;

    // DOM Elements
    const dropZone = document.getElementById("drop-zone");
    const fileInput = document.getElementById("file-input");
    const loadingOverlay = document.getElementById("loading-overlay");
    const loadingTitle = document.getElementById("loading-title");
    const loadingStep = document.getElementById("loading-step");
    const uploadSection = document.getElementById("upload-zone-wrapper");
    const dashboardSection = document.getElementById("results-dashboard");

    // Viewport Elements
    const mainDisplayImg = document.getElementById("main-display-img");
    const singleViewWrap = document.getElementById("single-view-wrap");
    const splitViewWrap = document.getElementById("split-view-wrap");
    const splitImgBefore = document.getElementById("split-img-before");
    const splitImgAfter = document.getElementById("split-img-after");
    const splitAfterBox = document.getElementById("split-after-box");
    const splitDivider = document.getElementById("split-divider");
    const splitContainer = document.getElementById("split-container");
    const elaControlsBar = document.getElementById("ela-controls-bar");
    const elaQualityInput = document.getElementById("ela-quality");
    const elaScaleInput = document.getElementById("ela-scale");
    const elaQualityVal = document.getElementById("ela-quality-val");
    const elaScaleVal = document.getElementById("ela-scale-val");
    const btnApplyEla = document.getElementById("btn-apply-ela");
    const guideText = document.getElementById("guide-text");
    const magnifierGlass = document.getElementById("magnifier-glass");

    // Action Buttons
    const btnNewAnalysis = document.getElementById("btn-new-analysis");
    const btnLoupe = document.getElementById("btn-loupe");
    const btnZoomIn = document.getElementById("btn-zoom-in");
    const btnZoomOut = document.getElementById("btn-zoom-out");
    const btnZoomReset = document.getElementById("btn-zoom-reset");
    const rawTagSearch = document.getElementById("raw-tag-search");

    // Initialize Event Listeners
    setupFileUpload();
    setupModeTabs();
    setupSplitSlider();
    setupElaSliders();
    setupDossierTabs();
    setupLoupeAndZoom();

    // -------------------------------------------------------------
    // File Ingestion & Drag / Drop / Paste
    // -------------------------------------------------------------
    function setupFileUpload() {
        if (!dropZone || !fileInput) return;

        dropZone.addEventListener("click", () => fileInput.click());

        fileInput.addEventListener("change", (e) => {
            if (e.target.files && e.target.files.length > 0) {
                uploadFile(e.target.files[0]);
            }
        });

        ["dragenter", "dragover"].forEach((eventName) => {
            dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                dropZone.classList.add("drag-over");
            });
        });

        ["dragleave", "drop"].forEach((eventName) => {
            dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                dropZone.classList.remove("drag-over");
            });
        });

        dropZone.addEventListener("drop", (e) => {
            if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                uploadFile(e.dataTransfer.files[0]);
            }
        });

        // Global Paste Event (Ctrl+V)
        window.addEventListener("paste", (e) => {
            if (e.clipboardData && e.clipboardData.files.length > 0) {
                const file = e.clipboardData.files[0];
                if (file.type.startsWith("image/")) {
                    uploadFile(file);
                }
            }
        });

        if (btnNewAnalysis) {
            btnNewAnalysis.addEventListener("click", () => {
                resetInvestigation();
            });
        }
    }

    function showLoading(title, step) {
        if (loadingOverlay) {
            loadingTitle.textContent = title || "Analyzing Image...";
            loadingStep.textContent = step || "Extracting metadata, ELA, and cryptographic hashes";
            loadingOverlay.classList.remove("hidden");
        }
    }

    function hideLoading() {
        if (loadingOverlay) {
            loadingOverlay.classList.add("hidden");
        }
    }

    function uploadFile(file) {
        showLoading("Analyzing Image...", `Processing ${file.name} (${(file.size / 1024).toFixed(1)} KB)`);
        const formData = new FormData();
        formData.append("file", file);

        fetch("/api/analyze", {
            method: "POST",
            body: formData
        })
        .then(res => {
            if (!res.ok) throw new Error(`Server returned HTTP ${res.status}`);
            return res.json();
        })
        .then(data => {
            hideLoading();
            if (data.error) {
                showToast("Analysis Error: " + data.error, "danger");
            } else {
                renderAnalysis(data);
                showToast(`Analysis complete and saved to database (#${data.record_id || 'new'})`, "success");
            }
        })
        .catch(err => {
            hideLoading();
            showToast("Upload failed: " + err.message, "danger");
        });
    }

    // -------------------------------------------------------------
    // Sample Loader
    // -------------------------------------------------------------
    window.loadSample = function(sampleId) {
        showLoading("Loading Test Case...", `Loading ${sampleId} for verification`);
        fetch("/api/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ sample: sampleId })
        })
        .then(res => res.json())
        .then(data => {
            hideLoading();
            if (data.error) {
                showToast("Sample Error: " + data.error, "danger");
            } else {
                renderAnalysis(data);
                showToast(`Loaded test sample: ${sampleId}`, "success");
            }
        })
        .catch(err => {
            hideLoading();
            showToast("Failed to load sample: " + err.message, "danger");
        });
    };

    // -------------------------------------------------------------
    // Render Results
    // -------------------------------------------------------------
    function renderAnalysis(data) {
        currentAnalysis = data;

        // Show Dashboard, Hide / Collapse Upload Section
        dashboardSection.classList.remove("hidden");
        dashboardSection.scrollIntoView({ behavior: "smooth" });

        // Populate Floating Viewport Badges
        const fi = data.file_info;
        document.getElementById("chip-dimensions").innerHTML = `<i class="fa-solid fa-vector-square"></i> ${fi.resolution}`;
        document.getElementById("chip-format").innerHTML = `<i class="fa-solid fa-file"></i> ${fi.format}`;
        document.getElementById("chip-colormode").innerHTML = `<i class="fa-solid fa-palette"></i> ${fi.color_mode}`;

        // Populate Main Images
        mainDisplayImg.src = data.preview_image;
        splitImgBefore.src = data.preview_image;
        splitImgAfter.src = data.ela.ela_image;

        // Set Default Mode to Original or Split
        setViewportMode("original");

        // Populate Verdict Banner & Score Box
        const verdict = data.verdict;
        const scoreVal = document.getElementById("authenticity-score-val");
        const verdictTitle = document.getElementById("verdict-title");
        const verdictCard = document.getElementById("verdict-card");
        const badgesContainer = document.getElementById("verdict-badges-container");

        scoreVal.textContent = `${verdict.authenticity_score}%`;
        verdictTitle.textContent = verdict.risk_level;

        // Score box border color
        const scoreBox = verdictCard.querySelector(".verdict-score-box");
        if (scoreBox) {
            if (verdict.verdict_color === "danger") {
                scoreBox.style.borderColor = "var(--danger-red)";
                verdictTitle.style.color = "var(--danger-red)";
            } else if (verdict.verdict_color === "warning") {
                scoreBox.style.borderColor = "var(--warning-amber)";
                verdictTitle.style.color = "var(--warning-amber)";
            } else {
                scoreBox.style.borderColor = "var(--success-green)";
                verdictTitle.style.color = "var(--success-green)";
            }
        }

        // Badges
        badgesContainer.innerHTML = "";
        (verdict.badges || []).forEach(b => {
            const span = document.createElement("span");
            const badgeClass = b.color === "danger" ? "badge-danger" : (b.color === "warning" ? "badge-warning" : "badge-success");
            span.className = `badge ${badgeClass}`;
            span.textContent = b.label;
            badgesContainer.appendChild(span);
        });

        // Populate Findings List
        const findingsList = document.getElementById("findings-list-container");
        const countBadge = document.getElementById("findings-count-badge");
        findingsList.innerHTML = "";
        countBadge.textContent = verdict.findings.length;

        verdict.findings.forEach(f => {
            const item = document.createElement("div");
            item.className = `finding-item ${f.type}`;
            const iconClass = f.type === "danger" ? "fa-triangle-exclamation" : (f.type === "warning" ? "fa-circle-exclamation" : "fa-circle-check");
            item.innerHTML = `
                <i class="fa-solid ${iconClass}" style="color: ${f.type === 'danger' ? 'var(--danger-red)' : (f.type === 'warning' ? 'var(--warning-amber)' : 'var(--success-green)')}; margin-top: 2px;"></i>
                <div>
                    <h6>${f.title}</h6>
                    <p>${f.detail}</p>
                </div>
            `;
            findingsList.appendChild(item);
        });

        // Populate Hashes & File Attributes (Tab 1)
        const hashes = data.hashes;
        document.getElementById("hash-md5").textContent = hashes.md5;
        document.getElementById("hash-sha1").textContent = hashes.sha1;
        document.getElementById("hash-sha256").textContent = hashes.sha256;
        document.getElementById("hash-sha512").textContent = hashes.sha512;

        document.getElementById("meta-filesize").textContent = fi.filesize_formatted;
        document.getElementById("meta-bytes").textContent = fi.filesize_bytes.toLocaleString() + " B";
        document.getElementById("meta-aspect").textContent = fi.aspect_ratio;
        document.getElementById("meta-timestamp").textContent = fi.analysis_timestamp;

        // Populate EXIF Hardware (Tab 2)
        const exif = data.exif;
        const cam = exif.camera || {};
        document.getElementById("exif-make").textContent = cam.Make || "Not specified";
        document.getElementById("exif-model").textContent = cam.Model || "Not specified";
        document.getElementById("exif-lens").textContent = cam.LensModel || "Not specified";

        const swEl = document.getElementById("exif-software");
        if (exif.software_detected) {
            swEl.textContent = exif.detected_software_name || exif.software;
            swEl.style.color = "var(--danger-red)";
        } else if (exif.software) {
            swEl.textContent = exif.software;
            swEl.style.color = "var(--warning-amber)";
        } else {
            swEl.textContent = "None detected";
            swEl.style.color = "var(--text-main)";
        }

        const exp = exif.exposure || {};
        document.getElementById("exif-shutter").textContent = exp.ExposureTime || "-";
        document.getElementById("exif-aperture").textContent = exp.FNumber ? `f/${exp.FNumber}` : "-";
        document.getElementById("exif-iso").textContent = exp.ISOSpeedRatings ? `ISO ${exp.ISOSpeedRatings}` : "-";
        document.getElementById("exif-focal").textContent = exp.FocalLength ? `${exp.FocalLength} mm` : "-";
        document.getElementById("exif-flash").textContent = exp.Flash !== undefined ? exp.Flash : "-";
        document.getElementById("exif-datetime").textContent = (exif.timestamps && (exif.timestamps.DateTimeOriginal || exif.timestamps.DateTime)) || "-";

        // Populate GPS Map (Tab 3)
        renderGpsMap(exif.gps);

        // Populate Pixel & ELA Metrics (Tab 4)
        const ela = data.ela;
        document.getElementById("ela-mean-val").textContent = ela.mean_error;
        document.getElementById("ela-max-val").textContent = ela.max_error;
        document.getElementById("ela-variance-val").textContent = ela.variance;
        document.getElementById("ela-quality-tested").textContent = `${ela.quality_tested}%`;
        document.getElementById("clone-matches-val").textContent = `${data.clone_detection.suspicious_matches} matches`;

        // Update Slider Inputs
        elaQualityInput.value = ela.quality_tested;
        elaScaleInput.value = ela.scale_applied;
        elaQualityVal.textContent = `${ela.quality_tested}%`;
        elaScaleVal.textContent = `${ela.scale_applied}x`;

        // Populate Raw Tags Table (Tab 5)
        renderRawTags(exif.all_tags);

        // Configure Export Links
        document.getElementById("btn-export-pdf").href = `/api/download-report/pdf`;
        document.getElementById("btn-export-txt").href = `/api/download-report/txt`;
        document.getElementById("btn-export-json").href = `/api/download-report/json`;
    }

    // -------------------------------------------------------------
    // Viewport Mode Switcher
    // -------------------------------------------------------------
    function setupModeTabs() {
        const modeButtons = document.querySelectorAll(".mode-btn");
        modeButtons.forEach(btn => {
            btn.addEventListener("click", () => {
                modeButtons.forEach(b => b.classList.remove("active"));
                btn.classList.add("active");
                setViewportMode(btn.dataset.mode);
            });
        });
    }

    function setViewportMode(mode) {
        currentMode = mode;
        if (!currentAnalysis) return;

        // Reset display transforms
        resetZoom();

        if (mode === "split") {
            singleViewWrap.classList.add("hidden");
            splitViewWrap.classList.remove("hidden");
            elaControlsBar.style.display = "flex";
            splitImgBefore.src = currentAnalysis.preview_image;
            splitImgAfter.src = currentAnalysis.ela.ela_image;
            guideText.textContent = "Drag the center divider horizontally to contrast the original evidence against Error Level Analysis.";
        } else {
            splitViewWrap.classList.add("hidden");
            singleViewWrap.classList.remove("hidden");

            if (mode === "original") {
                mainDisplayImg.src = currentAnalysis.preview_image;
                elaControlsBar.style.display = "none";
                guideText.textContent = "Original image preview. Use the Loupe tool to inspect subtle compression borders.";
            } else if (mode === "ela") {
                mainDisplayImg.src = currentAnalysis.ela.ela_image;
                elaControlsBar.style.display = "flex";
                guideText.textContent = "Error Level Analysis: Uniform dark areas indicate authentic single-save compression; bright areas indicate re-saved or pasted layers.";
            } else if (mode === "noise") {
                mainDisplayImg.src = currentAnalysis.noise_image || currentAnalysis.preview_image;
                elaControlsBar.style.display = "none";
                guideText.textContent = "Sensor Noise Analysis: High-pass filter revealing inconsistencies in camera sensor pattern and artificial blurring.";
            } else if (mode === "gradient") {
                mainDisplayImg.src = currentAnalysis.gradient_image || currentAnalysis.preview_image;
                elaControlsBar.style.display = "none";
                guideText.textContent = "Luminance Gradient: Highlights edges and lighting vector directionality across the scene.";
            } else if (mode === "clones") {
                const cloneImg = currentAnalysis.clone_detection.clone_image;
                mainDisplayImg.src = cloneImg || currentAnalysis.preview_image;
                elaControlsBar.style.display = "none";
                guideText.textContent = "Copy-Move Detection: Highlights matching feature keypoints between duplicated or cloned image patches.";
            }
        }
    }

    // -------------------------------------------------------------
    // Interactive Split Comparison Slider
    // -------------------------------------------------------------
    function setupSplitSlider() {
        if (!splitContainer) return;

        function updateSlider(clientX) {
            const rect = splitContainer.getBoundingClientRect();
            let offsetX = clientX - rect.left;
            offsetX = Math.max(0, Math.min(offsetX, rect.width));
            const percentage = (offsetX / rect.width) * 100;

            splitAfterBox.style.width = `${percentage}%`;
            splitDivider.style.left = `${percentage}%`;
        }

        splitContainer.addEventListener("mousedown", (e) => {
            isDraggingSplit = true;
            updateSlider(e.clientX);
        });

        window.addEventListener("mousemove", (e) => {
            if (!isDraggingSplit) return;
            updateSlider(e.clientX);
        });

        window.addEventListener("mouseup", () => {
            isDraggingSplit = false;
        });

        // Touch support
        splitContainer.addEventListener("touchstart", (e) => {
            if (e.touches.length > 0) {
                isDraggingSplit = true;
                updateSlider(e.touches[0].clientX);
            }
        });

        window.addEventListener("touchmove", (e) => {
            if (!isDraggingSplit || e.touches.length === 0) return;
            updateSlider(e.touches[0].clientX);
        });

        window.addEventListener("touchend", () => {
            isDraggingSplit = false;
        });
    }

    // -------------------------------------------------------------
    // ELA Slider Parameter Controls
    // -------------------------------------------------------------
    function setupElaSliders() {
        if (!elaQualityInput || !elaScaleInput) return;

        elaQualityInput.addEventListener("input", (e) => {
            elaQualityVal.textContent = `${e.target.value}%`;
        });

        elaScaleInput.addEventListener("input", (e) => {
            elaScaleVal.textContent = `${e.target.value}x`;
        });

        if (btnApplyEla) {
            btnApplyEla.addEventListener("click", () => {
                const quality = parseInt(elaQualityInput.value, 10);
                const scale = parseInt(elaScaleInput.value, 10);
                btnApplyEla.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Processing...`;

                fetch("/api/ela", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ quality, scale })
                })
                .then(res => res.json())
                .then(data => {
                    btnApplyEla.innerHTML = `<i class="fa-solid fa-arrows-rotate"></i> Recalculate ELA`;
                    if (data.error) {
                        showToast(data.error, "danger");
                    } else {
                        currentAnalysis.ela = data;
                        splitImgAfter.src = data.ela_image;
                        if (currentMode === "ela") {
                            mainDisplayImg.src = data.ela_image;
                        }
                        document.getElementById("ela-mean-val").textContent = data.mean_error;
                        document.getElementById("ela-max-val").textContent = data.max_error;
                        document.getElementById("ela-variance-val").textContent = data.variance;
                        document.getElementById("ela-quality-tested").textContent = `${data.quality_tested}%`;
                        showToast(`Recomputed ELA at ${quality}% quality, ${scale}x scale`, "success");
                    }
                })
                .catch(err => {
                    btnApplyEla.innerHTML = `<i class="fa-solid fa-arrows-rotate"></i> Recalculate ELA`;
                    showToast("Failed to compute ELA: " + err.message, "danger");
                });
            });
        }
    }

    // -------------------------------------------------------------
    // Dossier Tabs Navigation
    // -------------------------------------------------------------
    function setupDossierTabs() {
        const tabBtns = document.querySelectorAll(".d-tab-btn");
        const tabPanes = document.querySelectorAll(".d-tab-pane");

        tabBtns.forEach(btn => {
            btn.addEventListener("click", () => {
                tabBtns.forEach(b => b.classList.remove("active"));
                tabPanes.forEach(p => p.classList.remove("active"));

                btn.classList.add("active");
                const targetPane = document.getElementById(btn.dataset.tab);
                if (targetPane) {
                    targetPane.classList.add("active");
                    if (btn.dataset.tab === "tab-gps" && leafletMap) {
                        setTimeout(() => leafletMap.invalidateSize(), 200);
                    }
                }
            });
        });

        // Search Filter for Raw Tags
        if (rawTagSearch) {
            rawTagSearch.addEventListener("input", (e) => {
                const query = e.target.value.toLowerCase();
                const rows = document.querySelectorAll("#raw-tags-tbody tr");
                rows.forEach(r => {
                    const text = r.textContent.toLowerCase();
                    r.style.display = text.includes(query) ? "" : "none";
                });
            });
        }
    }

    // -------------------------------------------------------------
    // GPS Geolocation & Leaflet Map
    // -------------------------------------------------------------
    function renderGpsMap(gpsData) {
        const activeSection = document.getElementById("gps-active-section");
        const inactiveSection = document.getElementById("gps-inactive-section");

        if (!gpsData || !gpsData.latitude || !gpsData.longitude) {
            activeSection.classList.add("hidden");
            inactiveSection.classList.remove("hidden");
            return;
        }

        activeSection.classList.remove("hidden");
        inactiveSection.classList.add("hidden");

        const lat = gpsData.latitude;
        const lon = gpsData.longitude;
        const alt = gpsData.altitude ? `${gpsData.altitude} m` : "N/A";

        document.getElementById("gps-lat-val").textContent = `${lat}° ${gpsData.lat_ref || 'N'}`;
        document.getElementById("gps-lon-val").textContent = `${lon}° ${gpsData.lon_ref || 'E'}`;
        document.getElementById("gps-alt-val").textContent = alt;

        const mapLink = document.getElementById("gps-map-link");
        mapLink.href = `https://www.google.com/maps?q=${lat},${lon}`;

        const mapContainer = document.getElementById("leaflet-map");
        if (!mapContainer) return;

        if (leafletMap) {
            leafletMap.remove();
            leafletMap = null;
        }

        try {
            leafletMap = L.map("leaflet-map").setView([lat, lon], 14);

            L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
                attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
                maxZoom: 19
            }).addTo(leafletMap);

            const marker = L.marker([lat, lon]).addTo(leafletMap);
            marker.bindPopup(`<b>Evidence Geolocation</b><br/>Lat: ${lat}<br/>Lon: ${lon}<br/>Alt: ${alt}`).openPopup();

            setTimeout(() => {
                if (leafletMap) leafletMap.invalidateSize();
            }, 300);
        } catch (e) {
            console.error("Leaflet initialization error:", e);
        }
    }

    // -------------------------------------------------------------
    // Raw EXIF Tags Table
    // -------------------------------------------------------------
    function renderRawTags(tags) {
        const tbody = document.getElementById("raw-tags-tbody");
        tbody.innerHTML = "";

        if (!tags || Object.keys(tags).length === 0) {
            tbody.innerHTML = `<tr><td colspan="2" style="text-align: center; color: var(--text-muted); padding: 1rem;">No EXIF tags discovered.</td></tr>`;
            return;
        }

        const sortedKeys = Object.keys(tags).sort();
        sortedKeys.forEach(tag => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td style="color: #60a5fa; font-weight: 600;">${tag}</td>
                <td>${escapeHtml(String(tags[tag]))}</td>
            `;
            tbody.appendChild(tr);
        });
    }

    function escapeHtml(str) {
        return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }

    // -------------------------------------------------------------
    // Loupe Magnifier & Zoom Tool
    // -------------------------------------------------------------
    function setupLoupeAndZoom() {
        const stage = document.getElementById("viewport-stage");

        if (btnLoupe) {
            btnLoupe.addEventListener("click", () => {
                isLoupeActive = !isLoupeActive;
                btnLoupe.classList.toggle("active", isLoupeActive);
                magnifierGlass.classList.toggle("hidden", !isLoupeActive);
            });
        }

        if (stage && magnifierGlass) {
            stage.addEventListener("mousemove", (e) => {
                if (!isLoupeActive || currentMode === "split") return;

                const targetImg = mainDisplayImg;
                if (!targetImg || !targetImg.src) return;

                const rect = targetImg.getBoundingClientRect();
                const stageRect = stage.getBoundingClientRect();

                const x = e.clientX - rect.left;
                const y = e.clientY - rect.top;

                if (x < 0 || y < 0 || x > rect.width || y > rect.height) {
                    magnifierGlass.classList.add("hidden");
                    return;
                }

                magnifierGlass.classList.remove("hidden");
                const glassRadius = 80;
                magnifierGlass.style.left = `${e.clientX - stageRect.left - glassRadius}px`;
                magnifierGlass.style.top = `${e.clientY - stageRect.top - glassRadius}px`;

                const zoomFactor = 2.5;
                magnifierGlass.style.backgroundImage = `url('${targetImg.src}')`;
                magnifierGlass.style.backgroundSize = `${rect.width * zoomFactor}px ${rect.height * zoomFactor}px`;
                magnifierGlass.style.backgroundPosition = `-${x * zoomFactor - glassRadius}px -${y * zoomFactor - glassRadius}px`;
            });

            stage.addEventListener("mouseleave", () => {
                if (magnifierGlass) magnifierGlass.classList.add("hidden");
            });
        }

        // Zoom In / Out / Reset
        if (btnZoomIn) {
            btnZoomIn.addEventListener("click", () => {
                currentZoom = Math.min(3.0, currentZoom + 0.25);
                applyZoom();
            });
        }

        if (btnZoomOut) {
            btnZoomOut.addEventListener("click", () => {
                currentZoom = Math.max(0.5, currentZoom - 0.25);
                applyZoom();
            });
        }

        if (btnZoomReset) {
            btnZoomReset.addEventListener("click", () => {
                resetZoom();
            });
        }
    }

    function applyZoom() {
        if (mainDisplayImg) {
            mainDisplayImg.style.transform = `scale(${currentZoom})`;
        }
    }

    function resetZoom() {
        currentZoom = 1.0;
        applyZoom();
    }

    // -------------------------------------------------------------
    // Reset Investigation
    // -------------------------------------------------------------
    function resetInvestigation() {
        currentAnalysis = null;
        dashboardSection.classList.add("hidden");
        uploadSection.scrollIntoView({ behavior: "smooth" });
        fileInput.value = "";
        showToast("Investigation workspace reset. Select or drop a new image.", "info");
    }

    // -------------------------------------------------------------
    // Utility: Copy to Clipboard & Toast
    // -------------------------------------------------------------
    window.copyText = function(elementId) {
        const el = document.getElementById(elementId);
        if (el) {
            navigator.clipboard.writeText(el.textContent.trim())
                .then(() => showToast(`Copied ${elementId.replace('hash-', '').toUpperCase()} checksum to clipboard!`, "success"))
                .catch(() => showToast("Failed to copy text", "danger"));
        }
    };

    function showToast(message, type = "info") {
        const container = document.getElementById("toast-container");
        if (!container) return;

        const toast = document.createElement("div");
        toast.className = `toast toast-${type}`;
        const icon = type === "success" ? "fa-circle-check text-success" : (type === "danger" ? "fa-circle-exclamation text-danger" : "fa-circle-info text-info");
        toast.innerHTML = `<i class="fa-solid ${icon}"></i><span>${message}</span>`;
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = "0";
            toast.style.transform = "translateX(100%)";
            toast.style.transition = "all 0.3s ease";
            setTimeout(() => toast.remove(), 300);
        }, 3200);
    }
});
