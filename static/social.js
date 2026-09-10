document.addEventListener("DOMContentLoaded", () => {
    const form = document.querySelector(".social-form");
    const button = form?.querySelector(".btn-submit");
    if (form && button) {
        form.addEventListener("submit", () => {
            button.disabled = true;
            button.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Auto-Extracting Profile Data...';
        });
    }

    const urlInput = document.getElementById("profile_url");
    if (urlInput) {
        urlInput.addEventListener("input", () => {
            const val = urlInput.value.toLowerCase();
            const platforms = {
                instagram: "instagram",
                facebook: "facebook",
                "x.com": "twitter",
                twitter: "twitter",
                linkedin: "linkedin"
            };
            for (const [key, cls] of Object.entries(platforms)) {
                if (val.includes(key)) {
                    urlInput.dataset.platform = cls;
                    break;
                }
            }
        });
    }
});
