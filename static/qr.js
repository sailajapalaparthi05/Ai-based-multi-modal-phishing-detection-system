// QR Scanner JavaScript

document.addEventListener('DOMContentLoaded', function() {
    const fileInput = document.getElementById('qr_image');
    const fileLabel = document.querySelector('.file-label');
    const uploadForm = document.querySelector('.qr-form');

    if (fileInput && fileLabel) {
        fileInput.addEventListener('change', function(e) {
            if (e.target.files.length > 0) {
                const fileName = e.target.files[0].name;
                fileLabel.innerHTML = '<i class="fa-solid fa-file-image"></i> ' + fileName;
            }
        });
    }

    if (uploadForm) {
        uploadForm.addEventListener('submit', function(e) {
            const submitBtn = uploadForm.querySelector('.btn-submit');
            if (submitBtn) {
                submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Scanning...';
                submitBtn.disabled = true;
            }
        });
    }

    initCameraScanner();
});

function switchTab(tabName) {
    const tabs = document.querySelectorAll('.qr-tab');
    const contents = document.querySelectorAll('.qr-tab-content');

    tabs.forEach(function(tab, index) {
        if (tab.getAttribute('onclick') && tab.getAttribute('onclick').includes(tabName)) {
            tab.classList.add('active');
        } else {
            tab.classList.remove('active');
        }
    });

    contents.forEach(function(content) {
        content.classList.remove('active');
    });

    const targetContent = document.getElementById(tabName + '-tab');
    if (targetContent) {
        targetContent.classList.add('active');
    }
}

let cameraStream = null;
let cameraScanInterval = null;

function initCameraScanner() {
    const startBtn = document.getElementById('startCameraBtn');
    const stopBtn = document.getElementById('stopCameraBtn');
    const captureBtn = document.getElementById('captureQrBtn');
    const video = document.getElementById('qrVideo');
    const canvas = document.getElementById('qrCanvas');
    const placeholder = document.getElementById('qrCameraPlaceholder');
    const status = document.getElementById('cameraStatus');

    if (!startBtn || !video) return;

    startBtn.addEventListener('click', async () => {
        try {
            status.textContent = 'Requesting camera access...';
            cameraStream = await navigator.mediaDevices.getUserMedia({
                video: { facingMode: 'environment' }
            });
            video.srcObject = cameraStream;
            video.style.display = 'block';
            if (placeholder) placeholder.style.display = 'none';
            await new Promise((resolve, reject) => {
                video.onloadedmetadata = () => video.play().then(resolve).catch(reject);
                video.onerror = reject;
                setTimeout(reject, 10000);
            });
            if (captureBtn) {
                captureBtn.style.display = 'inline-flex';
                captureBtn.disabled = false;
            }
            startBtn.style.display = 'none';
            stopBtn.style.display = 'inline-flex';
            status.textContent = 'Camera active. Point at a QR code and click Capture QR.';
        } catch (err) {
            console.error('Camera error:', err);
            status.textContent = 'Camera access failed: ' + (err.message || err);
        }
    });

    stopBtn.addEventListener('click', stopCamera);

    captureBtn.addEventListener('click', async () => {
        if (!cameraStream || !video || !canvas) return;
        if (video.readyState < 2) {
            status.textContent = 'Camera is not ready yet. Please wait...';
            return;
        }
        const w = video.videoWidth || 640;
        const h = video.videoHeight || 480;
        const ctx = canvas.getContext('2d');
        canvas.width = w;
        canvas.height = h;
        ctx.drawImage(video, 0, 0, w, h);

        captureBtn.disabled = true;
        captureBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Scanning...';

        try {
            const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/png'));
            if (!blob) {
                throw new Error('Failed to capture image from camera');
            }
            const formData = new FormData();
            formData.append('qr_image', blob, 'camera-capture.png');

            const res = await fetch('/api/scan-qr-frame', {
                method: 'POST',
                body: formData
            });
            const data = await res.json();

            if (data.success && data.url) {
                status.textContent = 'QR detected: ' + data.url;
                window.location.href = '/api/check-qr-url?url=' + encodeURIComponent(data.url);
            } else {
                status.textContent = data.error || 'No QR code detected in this frame.';
            }
        } catch (err) {
            console.error('Capture error:', err);
            status.textContent = 'Scan failed: ' + (err.message || err);
        } finally {
            captureBtn.disabled = false;
            captureBtn.innerHTML = '<i class="fa-solid fa-qrcode"></i> Capture QR';
        }
    });
}

function stopCamera() {
    if (cameraStream) {
        cameraStream.getTracks().forEach(track => track.stop());
        cameraStream = null;
    }
    const video = document.getElementById('qrVideo');
    const placeholder = document.getElementById('qrCameraPlaceholder');
    const startBtn = document.getElementById('startCameraBtn');
    const stopBtn = document.getElementById('stopCameraBtn');
    const captureBtn = document.getElementById('captureQrBtn');
    if (video) video.style.display = 'none';
    if (placeholder) placeholder.style.display = 'flex';
    if (startBtn) startBtn.style.display = 'inline-flex';
    if (stopBtn) stopBtn.style.display = 'none';
    if (captureBtn) {
        captureBtn.style.display = 'none';
        captureBtn.disabled = false;
        captureBtn.innerHTML = '<i class="fa-solid fa-qrcode"></i> Capture QR';
    }
}
