import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk, ExifTags

from image_utils import calculate_hashes, check_editing_software
from report_generator import generate_report


class ImageForensicsApp:
    def __init__(self, root):
        self.root = root
        self.selected_file = None
        self.preview_image = None
        self._build_ui()

    def select_image(self):
        file_path = filedialog.askopenfilename(
            parent=self.root,
            title="Select Image",
            filetypes=[
                ("Image Files", "*.jpg *.jpeg *.png *.tiff *.bmp"),
                ("All Files", "*.*")
            ]
        )
        if file_path:
            self.selected_file = file_path
            self.show_image_preview(file_path)
            self.file_name_label.config(text=os.path.basename(file_path))
            self.status_label.config(
                text="Image selected. Click ANALYZE IMAGE.",
                foreground="#00d9ff"
            )

    def show_image_preview(self, file_path):
        try:
            image = Image.open(file_path)
            image.thumbnail((300, 220))
            self.preview_image = ImageTk.PhotoImage(image)
            self.image_preview_label.config(image=self.preview_image, text="")
        except Exception:
            self.image_preview_label.config(image="", text="Preview unavailable")

    def analyze_image(self):
        if not self.selected_file:
            messagebox.showwarning(
                "No Image", "Please select an image first.", parent=self.root
            )
            return

        try:
            image = Image.open(self.selected_file)
            file_name = os.path.basename(self.selected_file)
            file_size_kb = os.path.getsize(self.selected_file) / 1024
            file_format = image.format
            width, height = image.width, image.height
            color_mode = image.mode
            md5, sha256 = calculate_hashes(self.selected_file)

            self.file_name_value.config(text=file_name)
            self.file_size_value.config(text=f"{file_size_kb:.2f} KB")
            self.format_value.config(text=file_format)
            self.resolution_value.config(text=f"{width} × {height}")
            self.color_value.config(text=color_mode)
            self.md5_value.config(text=md5)
            self.sha256_value.config(text=sha256)

            exif_data = image.getexif()
            self.metadata_text.delete("1.0", tk.END)
            metadata_found = bool(exif_data)
            software_detected = False
            detected_software = None

            if exif_data:
                for tag_id, value in exif_data.items():
                    tag = ExifTags.TAGS.get(tag_id, tag_id)
                    self.metadata_text.insert(tk.END, f"{tag}: {value}\n")
                software_detected, detected_software = check_editing_software(exif_data)
            else:
                self.metadata_text.insert(tk.END, "No EXIF metadata found.")

            if software_detected:
                self.forensic_status.config(
                    text="⚠ EDITING SOFTWARE DETECTED", foreground="#ff4d6d"
                )
                self.forensic_detail.config(text=f"Software: {detected_software}")
            elif metadata_found:
                self.forensic_status.config(
                    text="✓ NO KNOWN EDITOR DETECTED", foreground="#00e676"
                )
                self.forensic_detail.config(text="EXIF metadata is available.")
            else:
                self.forensic_status.config(
                    text="⚠ NO EXIF METADATA", foreground="#ffaa00"
                )
                self.forensic_detail.config(text="Metadata is unavailable.")

            self.status_label.config(
                text="Analysis completed successfully.", foreground="#00e676"
            )
        except Exception as e:
            messagebox.showerror("Analysis Error", str(e), parent=self.root)

    def make_report(self):
        generate_report(self.selected_file, parent=self.root)

    def clear_data(self):
        self.selected_file = None
        self.preview_image = None
        self.image_preview_label.config(image="", text="IMAGE PREVIEW")
        self.file_name_label.config(text="No image selected")

        for label in (
            self.file_name_value, self.file_size_value, self.format_value,
            self.resolution_value, self.color_value, self.md5_value,
            self.sha256_value
        ):
            label.config(text="-")

        self.metadata_text.delete("1.0", tk.END)
        self.metadata_text.insert(tk.END, "No image analyzed.")
        self.forensic_status.config(
            text="Waiting for analysis", foreground="#aaaaaa"
        )
        self.forensic_detail.config(text="-")
        self.status_label.config(text="Ready", foreground="#00d9ff")

    def _build_ui(self):
        root = self.root
        root.title("Digital Image Forensics Tool")
        root.geometry("1050x750")
        root.configure(bg="#101522")
        root.minsize(900, 650)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", font=("Segoe UI", 11, "bold"), padding=10)
        style.configure(
            "Treeview", background="#171d2b", foreground="white",
            fieldbackground="#171d2b"
        )

        header = tk.Frame(root, bg="#151c2c", height=90)
        header.pack(fill="x")
        tk.Label(
            header, text="🔍 DIGITAL IMAGE FORENSICS TOOL",
            font=("Segoe UI", 24, "bold"), bg="#151c2c", fg="#00d9ff"
        ).pack(pady=(18, 2))
        tk.Label(
            header, text="Image Analysis • Metadata • Hash Verification",
            font=("Segoe UI", 10), bg="#151c2c", fg="#aaaaaa"
        ).pack()

        main_frame = tk.Frame(root, bg="#101522")
        main_frame.pack(fill="both", expand=True, padx=20, pady=15)

        left_panel = tk.Frame(main_frame, bg="#171d2b", width=330)
        left_panel.pack(side="left", fill="y", padx=(0, 10))
        left_panel.pack_propagate(False)

        tk.Label(
            left_panel, text="IMAGE PREVIEW", font=("Segoe UI", 13, "bold"),
            bg="#171d2b", fg="white"
        ).pack(pady=(20, 10))

        self.image_preview_label = tk.Label(
            left_panel, text="IMAGE PREVIEW", font=("Segoe UI", 12),
            bg="#0d111b", fg="#666666", width=30, height=12
        )
        self.image_preview_label.pack(padx=15, pady=10)

        self.file_name_label = tk.Label(
            left_panel, text="No image selected", font=("Segoe UI", 10),
            bg="#171d2b", fg="#aaaaaa", wraplength=280
        )
        self.file_name_label.pack(pady=5)

        buttons = [
            ("📁 SELECT IMAGE", self.select_image, "#0077b6", "#0096c7", 11),
            ("🔎 ANALYZE IMAGE", self.analyze_image, "#00a896", "#02c39a", 11),
            ("📄 GENERATE REPORT", self.make_report, "#6c4ab6", "#805ad5", 11),
            ("↻ CLEAR", self.clear_data, "#343a46", "#495057", 10),
        ]
        for text, command, bg, active_bg, font_size in buttons:
            tk.Button(
                left_panel, text=text, command=command,
                font=("Segoe UI", font_size, "bold" if font_size == 11 else "normal"),
                bg=bg, fg="white", activebackground=active_bg,
                activeforeground="white", relief="flat", cursor="hand2", width=25
            ).pack(pady=12 if text == "📁 SELECT IMAGE" else 5)

        right_panel = tk.Frame(main_frame, bg="#101522")
        right_panel.pack(side="left", fill="both", expand=True)

        file_card = tk.Frame(right_panel, bg="#171d2b")
        file_card.pack(fill="x", pady=(0, 10))
        tk.Label(
            file_card, text="📁 FILE INFORMATION", font=("Segoe UI", 13, "bold"),
            bg="#171d2b", fg="#00d9ff"
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=15, pady=10)

        def create_info_row(parent, row, name):
            tk.Label(
                parent, text=name, font=("Segoe UI", 10),
                bg="#171d2b", fg="#aaaaaa"
            ).grid(row=row, column=0, sticky="w", padx=15, pady=3)
            label = tk.Label(
                parent, text="-", font=("Segoe UI", 10, "bold"),
                bg="#171d2b", fg="white"
            )
            label.grid(row=row, column=1, sticky="w", padx=15, pady=3)
            return label

        self.file_name_value = create_info_row(file_card, 1, "File Name")
        self.file_size_value = create_info_row(file_card, 2, "File Size")
        self.format_value = create_info_row(file_card, 3, "Format")
        self.resolution_value = create_info_row(file_card, 4, "Resolution")
        self.color_value = create_info_row(file_card, 5, "Color Mode")

        hash_card = tk.Frame(right_panel, bg="#171d2b")
        hash_card.pack(fill="x", pady=5)
        tk.Label(
            hash_card, text="🔐 HASH INFORMATION", font=("Segoe UI", 13, "bold"),
            bg="#171d2b", fg="#00d9ff"
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=15, pady=10)
        self.md5_value = create_info_row(hash_card, 1, "MD5")
        self.sha256_value = create_info_row(hash_card, 2, "SHA-256")

        exif_card = tk.Frame(right_panel, bg="#171d2b")
        exif_card.pack(fill="both", expand=True, pady=10)
        tk.Label(
            exif_card, text="📷 EXIF METADATA", font=("Segoe UI", 13, "bold"),
            bg="#171d2b", fg="#00d9ff"
        ).pack(anchor="w", padx=15, pady=(10, 5))
        self.metadata_text = tk.Text(
            exif_card, height=7, bg="#0d111b", fg="#dddddd",
            insertbackground="white", font=("Consolas", 9),
            relief="flat", wrap="word"
        )
        self.metadata_text.pack(fill="both", expand=True, padx=15, pady=5)
        self.metadata_text.insert(tk.END, "No image analyzed.")

        forensic_card = tk.Frame(right_panel, bg="#171d2b")
        forensic_card.pack(fill="x", pady=(0, 5))
        tk.Label(
            forensic_card, text="⚠ FORENSIC ANALYSIS",
            font=("Segoe UI", 13, "bold"), bg="#171d2b", fg="#00d9ff"
        ).pack(anchor="w", padx=15, pady=(10, 2))
        self.forensic_status = tk.Label(
            forensic_card, text="Waiting for analysis",
            font=("Segoe UI", 11, "bold"), bg="#171d2b", fg="#aaaaaa"
        )
        self.forensic_status.pack(anchor="w", padx=15)
        self.forensic_detail = tk.Label(
            forensic_card, text="-", font=("Segoe UI", 9),
            bg="#171d2b", fg="#aaaaaa"
        )
        self.forensic_detail.pack(anchor="w", padx=15, pady=(2, 10))

        self.status_label = tk.Label(
            root, text="Ready", font=("Segoe UI", 9),
            bg="#0b0f18", fg="#00d9ff", anchor="w"
        )
        self.status_label.pack(fill="x", side="bottom", padx=10, pady=5)


def main():
    root = tk.Tk()
    ImageForensicsApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
