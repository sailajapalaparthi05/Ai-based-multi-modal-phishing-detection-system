import cv2
import requests
import time

# Flask API Endpoint URL
FLASK_API_URL = "http://127.0.0.1:5000/api/check-qr-url"

# Initialize OpenCV built-in QR Code Detector
qr_detector = cv2.QRCodeDetector()


def send_url_to_flask(url):
    """Sends the detected URL to app.py and displays whether it is real or fake."""
    print(f"\n[+] Sending URL to app.py: {url}")
    
    try:
        response = requests.post(FLASK_API_URL, json={"url": url}, timeout=10)
        if response.status_code == 200:
            data = response.json()
            print("==========================================")
            print(f" URL ANALYZED : {data.get('url')}")
            print(f" RESULT       : {data.get('prediction')}")
            print(f" STATUS       : {data.get('status').upper()}")
            print(f" CONFIDENCE   : {data.get('confidence')}%")
            if data.get("risks"):
                print(f" RISKS FOUND  : {', '.join(data.get('risks'))}")
            print("==========================================\n")
        else:
            print(f"[!] Server Error: {response.status_code}")
    except requests.exceptions.ConnectionError:
        print("[!] Error: Could not connect to app.py. Make sure Flask server is running on http://127.0.0.1:5000!")


def start_qr_scanner():
    """Opens camera window and listens for QR codes."""
    cap = cv2.VideoCapture(0)
    
    if not cap.isOpened():
        print("[!] Error: Could not open web camera.")
        return

    # Set lower resolution for fast frame processing
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)

    print("\n[+] QR Scanner Started...")
    print("[+] Point your camera at a QR code. (Press 'q' or 'ESC' to exit)\n")

    last_scanned_url = ""
    last_scan_time = 0

    while True:
        ret, frame = cap.read()
        if not ret:
            continue

        # Detect and decode QR code from frame
        url, bbox, _ = qr_detector.detectAndDecode(frame)

        # Draw box around QR Code if detected
        if bbox is not None and len(bbox) > 0:
            pts = bbox[0].astype(int)
            for i in range(len(pts)):
                cv2.line(frame, tuple(pts[i]), tuple(pts[(i + 1) % len(pts)]), (0, 255, 0), 3)

        # Display camera feed
        cv2.imshow("QR Scanner (Press ESC to Quit)", frame)

        # Send URL if detected & prevent rapid repeated sending (3-second cooldown per unique URL)
        if url and (url != last_scanned_url or time.time() - last_scan_time > 3):
            url = url.strip()
            print(f"[✔] QR Code Detected: {url}")
            send_url_to_flask(url)
            last_scanned_url = url
            last_scan_time = time.time()

        # Exit scanner when pressing ESC or 'q'
        key = cv2.waitKey(1) & 0xFF
        if key in [27, ord("q")]:
            break

    cap.release()
    cv2.destroyAllWindows()


if __name__ == "__main__":
    start_qr_scanner()