"""
VERITAS - Digital Image Forensics Platform Entry Point.
Launches the Web Application by default (with auto browser launch),
or the Desktop Tkinter interface if '--desktop' / '--gui' flag is passed.
"""

import sys
import os
import webbrowser
import threading
import time

def open_browser(port):
    time.sleep(1.2)
    url = f"http://127.0.0.1:{port}"
    print(f"[*] Opening browser to {url}...")
    webbrowser.open(url)

def run_web(port=5000, launch_browser=True):
    from app import app
    print("=" * 70)
    print("   VERITAS // DIGITAL IMAGE FORENSICS LAB")
    print(f"   Web Platform running on: http://127.0.0.1:{port}")
    print("   Press Ctrl+C to terminate.")
    print("=" * 70)

    if launch_browser:
        t = threading.Thread(target=open_browser, args=(port,), daemon=True)
        t.start()

    app.run(host="127.0.0.1", port=port, debug=False)

def run_desktop():
    print("[*] Launching Desktop Tkinter Interface...")
    from ui_app import main as desktop_main
    desktop_main()

if __name__ == "__main__":
    if "--desktop" in sys.argv or "--gui" in sys.argv:
        run_desktop()
    else:
        port = int(os.environ.get("PORT", 5000))
        run_web(port=port, launch_browser=True)
