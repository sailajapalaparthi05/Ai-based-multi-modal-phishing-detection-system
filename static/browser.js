const FLASK_API = "http://127.0.0.1:5000";

document.addEventListener("DOMContentLoaded", () => {
    const statusEl = document.getElementById("auto-scan-status");
    const resultsEl = document.getElementById("browser-results");
    async function checkLatestScan() {
    try {
        const response = await fetch(
            `${FLASK_API}/api/latest_browser_scan`
        );

        if (!response.ok) return;

        const data = await response.json();

        if (data.available) {
            renderResults(data);
        }

    } catch (error) {
        console.log("Waiting for extension scan...");
    }
}

checkLatestScan();

setInterval(checkLatestScan, 2000);

    // Listen for scan results posted by Chrome Extension
    window.addEventListener("message", (event) => {
        if (event.data?.type === "BROWSER_SCAN_RESULT") {
            renderResults(event.data.result);
        }
    });

    // Poll for latest extension scan stored in localStorage bridge
    const latest = localStorage.getItem("latest_browser_scan");
    if (latest) {
        try {
            renderResults(JSON.parse(latest));
        } catch (e) { /* ignore */ }
    }

    // Manual trigger for testing without extension
    const testBtn = document.getElementById("test-scan-btn");
    if (testBtn) {
        testBtn.addEventListener("click", async () => {
            if (statusEl) {
                statusEl.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i><p>Waiting for Chrome Extension data...</p>';
            }
        });
    }

    function renderResults(data) {
        if (!data || !resultsEl) return;
        localStorage.setItem("latest_browser_scan", JSON.stringify(data));

        const isPhishing = data.verdict === "phishing";
        resultsEl.innerHTML = `
            <div class="result-card">
                <h2>ANALYSIS VERDICT</h2>
                <div class="progress ${data.verdict}" style="--value:${data.confidence}">
                    <div class="inner-circle">
                        <h1>${data.confidence}%</h1>
                        <span class="status ${data.verdict}">
                            <i class="fa-solid fa-${isPhishing ? 'triangle-exclamation' : 'circle-check'}"></i>
                            ${isPhishing ? 'PHISHING' : 'SAFE'}
                        </span>
                    </div>
                </div>
                <p class="website" style="margin-top:20px;">
                    Scanned URL: <strong>${data.current_url || 'N/A'}</strong>
                </p>
                <span class="dl-badge ${isPhishing ? 'threat' : 'safe'}">
                    <i class="fa-solid fa-brain"></i> DL: ${data.dl_prediction} (${data.dl_confidence || 0}%)
                </span>
            </div>
            ${data.screenshot_preview ? `<img class="screenshot-preview" src="${data.screenshot_preview.startsWith('data:') ? data.screenshot_preview : 'data:image/png;base64,' + data.screenshot_preview}" alt="Screenshot">` : ''}
            <h2 class="title">Threat Analysis</h2>
            <div class="metadata-grid">
                <div class="meta-item"><strong>Risk Score</strong>${data.risk_score}/100</div>
                <div class="meta-item"><strong>SSL</strong>${data.ssl_valid ? 'Valid' : 'Invalid'}</div>
                <div class="meta-item"><strong>DNS</strong>${data.dns_valid ? 'Valid' : 'Invalid'}</div>
                <div class="meta-item"><strong>Reputation</strong>${data.reputation || 'Unknown'}</div>
                <div class="meta-item"><strong>Redirects</strong>${data.redirect_len || 0} hops</div>
                <div class="meta-item"><strong>Popups</strong>${data.popup_messages_count || 0}</div>
                <div class="meta-item"><strong>Downloads</strong>${data.auto_downloads_count || 0}</div>
                <div class="meta-item"><strong>Notifications</strong>${data.notification_requests || 0}</div>
            </div>
            ${data.risks?.length ? `<div class="risk-box"><h2>Threat Reasons</h2><ul>${data.risks.map(r => `<li><i class="fa-solid fa-triangle-exclamation"></i>${r}</li>`).join('')}</ul></div>` : ''}
        `;

        if (statusEl) statusEl.style.display = "none";
        resultsEl.style.display = "block";

        const percent = resultsEl.querySelector("#percent");
        if (percent) animatePercent(percent, data.confidence);
    }
});

function animatePercent(el, target) {
    let current = 0;
    const step = target / 40;
    const timer = setInterval(() => {
        current += step;
        if (current >= target) { current = target; clearInterval(timer); }
        el.textContent = Math.round(current) + "%";
    }, 25);
}
