import os
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ExifTags

from image_utils import calculate_hashes, check_editing_software


def generate_report(selected_file, parent=None):
    """Generate and save the forensic report for the selected image."""
    if not selected_file:
        messagebox.showwarning(
            "No Image", "Please select and analyze an image first.",
            parent=parent
        )
        return

    try:
        image = Image.open(selected_file)
        file_name = os.path.basename(selected_file)
        file_size = os.path.getsize(selected_file)
        file_format = image.format
        width, height = image.width, image.height
        color_mode = image.mode
        md5, sha256 = calculate_hashes(selected_file)
        exif_data = image.getexif()

        report = [
            "============================================",
            "       DIGITAL IMAGE FORENSIC REPORT",
            "============================================",
            "",
            f"Analysis Date: {datetime.now()}",
            "",
            "FILE INFORMATION",
            "--------------------------------------------",
            f"File Name: {file_name}",
            f"File Size: {file_size} bytes",
            f"Format: {file_format}",
            f"Resolution: {width} x {height}",
            f"Color Mode: {color_mode}",
            "",
            "HASH INFORMATION",
            "--------------------------------------------",
            f"MD5: {md5}",
            f"SHA-256: {sha256}",
            "",
            "EXIF METADATA",
            "--------------------------------------------",
        ]

        if exif_data:
            for tag_id, value in exif_data.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)
                report.append(f"{tag}: {value}")
        else:
            report.append("No EXIF metadata found.")

        report.extend(["", "FORENSIC ANALYSIS",
                       "--------------------------------------------"])

        if exif_data:
            detected, software = check_editing_software(exif_data)
            if detected:
                report.extend([
                    "Editing Software: DETECTED",
                    f"Software: {software}",
                    "Note: This is an indicator of image processing, "
                    "not proof of image manipulation."
                ])
            else:
                report.append("Editing Software: No known editor detected")
        else:
            report.append(
                "Editing Software: Cannot determine from EXIF metadata"
            )

        report.extend([
            "",
            "============================================",
            "             END OF REPORT",
            "============================================"
        ])

        save_path = filedialog.asksaveasfilename(
            parent=parent,
            title="Save Forensic Report",
            defaultextension=".txt",
            filetypes=[("Text File", "*.txt")],
            initialfile="forensic_report.txt"
        )

        if save_path:
            with open(save_path, "w", encoding="utf-8") as file:
                file.write("\n".join(report))
            messagebox.showinfo(
                "Report Generated", "Forensic report saved successfully.",
                parent=parent
            )

    except Exception as e:
        messagebox.showerror("Report Error", str(e), parent=parent)
