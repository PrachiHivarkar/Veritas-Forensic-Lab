import hashlib
from PIL import ExifTags


def calculate_hashes(file_path):
    """Return MD5 and SHA-256 hashes for a file."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            data = file.read(4096)
            if not data:
                break
            md5.update(data)
            sha256.update(data)

    return md5.hexdigest(), sha256.hexdigest()


def check_editing_software(exif_data):
    """Check EXIF Software metadata for commonly known image editors."""
    editing_software = [
        "Adobe Photoshop", "Photoshop", "GIMP", "Snapseed",
        "Lightroom", "Canva", "PicsArt", "Paint.NET"
    ]

    for tag_id, value in exif_data.items():
        tag = ExifTags.TAGS.get(tag_id, tag_id)
        if tag == "Software":
            software = str(value)
            for editor in editing_software:
                if editor.lower() in software.lower():
                    return True, software

    return False, None
