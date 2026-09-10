// Vishing Scanner JavaScript

document.addEventListener('DOMContentLoaded', function() {
    const audioInput = document.getElementById('audio_file');
    const previewContainer = document.getElementById('audioPreviewContainer');
    const preview = document.getElementById('audioPreview');

    if (audioInput) {
        audioInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (! file) return;

            if (file.size > 10 * 1024 * 1024) {
                alert('File size too large. Maximum size is 10MB.');
                audioInput.value = '';
                if (previewContainer) previewContainer.style.display = 'none';
                return;
            }

            const validExtensions = ['wav', 'mp3', 'm4a', 'mpeg', 'mp4', 'aac', 'ogg', 'flac'];
            const fileExtension = file.name.split('.').pop().toLowerCase();
            if (! validExtensions.includes(fileExtension)) {
                alert('Invalid file format. Please upload WAV, MP3, M4A, or other supported audio files.');
                audioInput.value = '';
                if (previewContainer) previewContainer.style.display = 'none';
                return;
            }

            if (preview && previewContainer) {
                preview.src = URL.createObjectURL(file);
                previewContainer.style.display = 'block';
            }
        });
    }

    const percentElement = document.getElementById('percent');
    if (percentElement) {
        const targetValue = parseFloat(percentElement.getAttribute('data-value'));
        let currentValue = 0;
        const increment = Math.max(targetValue / 50, 0.5);

        const counter = setInterval(() => {
            currentValue += increment;
            if (currentValue >= targetValue) {
                currentValue = targetValue;
                clearInterval(counter);
            }
            percentElement.textContent = Math.round(currentValue) + '%';
        }, 30);
    }
});