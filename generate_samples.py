"""
Generate authentic, tampered, and metadata-stripped sample images for VERITAS lab.
"""
import os
import math
from PIL import Image, ImageDraw, ImageFilter, ExifTags

def create_samples():
    os.makedirs("static/samples", exist_ok=True)

    # 1. Authentic Image: Architectural / Landscape simulation with authentic camera EXIF & GPS
    w, h = 900, 600
    img_auth = Image.new("RGB", (w, h), color=(135, 206, 235))
    draw = ImageDraw.Draw(img_auth)

    # Sky gradient & sun
    for y in range(h // 2):
        r = int(120 + 80 * (y / (h / 2)))
        g = int(180 + 40 * (y / (h / 2)))
        b = int(240 - 20 * (y / (h / 2)))
        draw.line([(0, y), (w, y)], fill=(r, g, b))

    draw.ellipse([w - 180, 50, w - 80, 150], fill=(255, 220, 100))

    # Mountains
    mountain_pts = [(0, 350), (180, 180), (380, 320), (550, 140), (750, 300), (900, 200), (900, 450), (0, 450)]
    draw.polygon(mountain_pts, fill=(70, 90, 120))
    snow_pts = [(550, 140), (520, 180), (580, 180)]
    draw.polygon(snow_pts, fill=(240, 245, 255))

    # Foreground ground
    draw.rectangle([0, 380, w, h], fill=(34, 139, 34))

    # Add realistic gentle camera sensor noise
    auth_noise = Image.effect_noise((w, h), 4).convert("RGB")
    img_auth = Image.blend(img_auth, auth_noise, 0.05)

    # Authentic EXIF
    exif_auth = img_auth.getexif()
    exif_auth[0x010F] = "Nikon Corporation"
    exif_auth[0x0110] = "NIKON D850"
    exif_auth[0x0132] = "2024:06:15 10:30:45"
    
    # Exif IFD
    exif_ifd = exif_auth.get_ifd(ExifTags.IFD.Exif)
    exif_ifd[0x9003] = "2024:06:15 10:30:45" # DateTimeOriginal
    exif_ifd[0x9004] = "2024:06:15 10:30:45" # DateTimeDigitized
    exif_ifd[0x829A] = (1.0, 500.0) # ExposureTime 1/500s
    exif_ifd[0x829D] = 2.8 # FNumber
    exif_ifd[0x8827] = 100 # ISO
    exif_ifd[0x920A] = 50.0 # FocalLength 50mm
    exif_ifd[0xA434] = "AF-S NIKKOR 50mm f/1.8G" # LensModel

    # GPS IFD (Pune Shaniwar Wada)
    gps_ifd = exif_auth.get_ifd(ExifTags.IFD.GPSInfo)
    gps_ifd[1] = "N"
    gps_ifd[2] = (18.0, 31.0, 10.0)
    gps_ifd[3] = "E"
    gps_ifd[4] = (73.0, 51.0, 19.0)
    gps_ifd[6] = 560.0

    img_auth.save("static/samples/sample_authentic.jpg", "JPEG", quality=95, exif=exif_auth)

    # 2. Tampered Image: Splice / Cloning with distinct JPEG re-compression and Photoshop tag
    img_tamp = img_auth.copy()
    draw_tamp = ImageDraw.Draw(img_tamp)

    # Splice a glowing red moon / balloon into the sky, cloned in two positions
    splice_obj = Image.new("RGB", (120, 120), color=(255, 60, 60))
    d_obj = ImageDraw.Draw(splice_obj)
    d_obj.ellipse([10, 10, 110, 110], fill=(255, 80, 80), outline=(255, 255, 0), width=4)
    # Save object with high JPEG compression (quality=40) to introduce distinct ELA signature
    import io
    b = io.BytesIO()
    splice_obj.save(b, "JPEG", quality=35)
    b.seek(0)
    splice_obj = Image.open(b)

    # Paste spliced object at position 1 and position 2 (Copy-Move)
    img_tamp.paste(splice_obj, (120, 80))
    img_tamp.paste(splice_obj, (350, 70))

    # Add text banner overlay typical of edited meme or altered banner
    draw_tamp.rectangle([40, 520, 480, 580], fill=(20, 20, 20))
    draw_tamp.rectangle([45, 525, 475, 575], outline=(255, 50, 80), width=2)

    exif_tamp = img_tamp.getexif()
    exif_tamp[0x010F] = "Canon"
    exif_tamp[0x0110] = "Canon EOS Rebel T7"
    exif_tamp[0x0131] = "Adobe Photoshop 2024 (Windows)"
    exif_tamp[0x0132] = "2024:09:20 23:45:12" # Modified recently

    exif_tamp_ifd = exif_tamp.get_ifd(ExifTags.IFD.Exif)
    exif_tamp_ifd[0x9003] = "2021:04:10 09:12:00" # Original was 3 years prior!
    exif_tamp_ifd[0x0131] = "Adobe Photoshop 2024 (Windows)"

    img_tamp.save("static/samples/sample_tampered.jpg", "JPEG", quality=88, exif=exif_tamp)

    # 3. Metadata Stripped Sample (e.g. Social Media / Web Asset)
    img_strip = Image.new("RGBA", (800, 500), color=(15, 23, 42, 255))
    d_strip = ImageDraw.Draw(img_strip)
    for i in range(0, 800, 40):
        d_strip.line([(i, 0), (i, 500)], fill=(30, 41, 59, 255), width=1)
    for j in range(0, 500, 40):
        d_strip.line([(0, j), (800, j)], fill=(30, 41, 59, 255), width=1)

    d_strip.ellipse([300, 150, 500, 350], fill=(0, 240, 255, 200), outline=(255, 255, 255, 255), width=3)
    img_strip.convert("RGB").save("static/samples/sample_stripped.png", "PNG")

    print("Sample forensic images generated successfully:")
    print(" - static/samples/sample_authentic.jpg")
    print(" - static/samples/sample_tampered.jpg")
    print(" - static/samples/sample_stripped.png")

if __name__ == "__main__":
    create_samples()
