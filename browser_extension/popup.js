document.getElementById("scanNow").addEventListener("click", async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id) {
        chrome.runtime.sendMessage({ type: "TRIGGER_SCAN" });
        document.getElementById("result").innerHTML = '<div class="status safe">Scanning...</div>';
    }
});

document.getElementById("openDashboard").addEventListener("click", () => {
    chrome.tabs.create({ url: "http://127.0.0.1:5000/browser" });
});

chrome.storage.local.get("latest_scan", (data) => {
    if (data.latest_scan) showResult(data.latest_scan);
});

function showResult(r) {
    const cls = r.verdict === "phishing" ? "phishing" : "safe";
    document.getElementById("result").innerHTML = `
        <div class="status ${cls}">
            <strong>${r.verdict === "phishing" ? "⚠️ PHISHING" : "✅ SAFE"}</strong><br>
            Confidence: ${r.confidence}%<br>
            DL: ${r.dl_prediction}<br>
            Risk: ${r.risk_score}/100
        </div>`;
}
