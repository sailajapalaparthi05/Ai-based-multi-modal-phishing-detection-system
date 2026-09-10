const FLASK_API = "http://127.0.0.1:5000";

console.log("background.js loaded");

// Track browser behavior data per tab
let tabData = {}; // { tabId: { redirectChain: [], autoDownloads: [], newTabs: [], timestamp: 0, pageAnalysis: {} } }
let recentDownloads = []; // Track recent downloads across all tabs

// Function to check if URL is internal page
function isInternalPage(url) {
    if (!url) return true;
    return url.startsWith("chrome://") || 
           url.startsWith("chrome-extension://") || 
           url.startsWith("edge://") || 
           url.startsWith("about:") ||
           url.startsWith("moz-extension://") ||
           url.startsWith("http://127.0.0.1:5000") ||
           url.startsWith("http://localhost:5000");
}

// ============================================
// 1. AUTOMATIC DOWNLOAD DETECTION
// ============================================
chrome.downloads.onCreated.addListener((downloadItem) => {
    console.log("Download detected:", downloadItem.filename || downloadItem.url);
    
    // Track download information
    const downloadInfo = {
        filename: downloadItem.filename || downloadItem.url,
        downloadUrl: downloadItem.url || "",
        fileSize: downloadItem.fileSize || 0,
        startTime: downloadItem.startTime || Date.now(),
        byExtensionId: downloadItem.byExtensionId || false,
        danger: downloadItem.danger || ""
    };
    
    // Store in recent downloads
    recentDownloads.push(downloadInfo);
    if (recentDownloads.length > 20) recentDownloads.shift();
    
    // Find which tab triggered this download
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]?.id) {
            const tabId = tabs[0].id;
            if (!tabData[tabId]) {
                tabData[tabId] = { redirectChain: [], autoDownloads: [], newTabs: [], timestamp: Date.now(), pageAnalysis: {} };
            }
            tabData[tabId].autoDownloads.push(downloadInfo);
            console.log(`Download associated with tab ${tabId}:`, downloadInfo);
        }
    });
});

// ============================================
// 2. NEW TAB / POPUP BEHAVIOR DETECTION
// ============================================
chrome.tabs.onCreated.addListener((tab) => {
    console.log("New tab created:", tab.id);
    
    // Try to determine if this was triggered by another tab
    if (tab.openerTabId) {
        console.log(`Tab ${tab.id} opened by tab ${tab.openerTabId} (potential popup)`);
        
        // Record this as popup behavior in the opener tab
        if (tabData[tab.openerTabId]) {
            tabData[tab.openerTabId].newTabs.push({
                tabId: tab.id,
                url: tab.url || "about:blank",
                timestamp: Date.now()
            });
        } else {
            tabData[tab.openerTabId] = { 
                redirectChain: [], 
                autoDownloads: [], 
                newTabs: [{ tabId: tab.id, url: tab.url || "about:blank", timestamp: Date.now() }],
                timestamp: Date.now(),
                pageAnalysis: {}
            };
        }
    }
});

// Track when tabs are closed (cleanup)
chrome.tabs.onRemoved.addListener((tabId) => {
    if (tabData[tabId]) {
        delete tabData[tabId];
    }
});

// ============================================
// 3. REDIRECT / NAVIGATION BEHAVIOR TRACKING
// ============================================
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId !== 0) return; // Only main frame
    
    const tabId = details.tabId;
    if (!tabData[tabId]) {
        tabData[tabId] = { redirectChain: [], autoDownloads: [], newTabs: [], timestamp: Date.now(), pageAnalysis: {} };
    }
    
    // Add to redirect chain if different
    if (details.url && !tabData[tabId].redirectChain.includes(details.url)) {
        tabData[tabId].redirectChain.push(details.url);
        console.log(`Navigation added to chain for tab ${tabId}:`, details.url);
    }
});

chrome.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId !== 0) return;
    
    const tabId = details.tabId;
    if (!tabData[tabId]) {
        tabData[tabId] = { redirectChain: [], autoDownloads: [], newTabs: [], timestamp: Date.now(), pageAnalysis: {} };
    }
    
    // Track navigation transitions
    if (details.transitionType && details.transitionQualifiers) {
        console.log(`Tab ${tabId} navigation: ${details.transitionType}`, details.transitionQualifiers);
    }
});

chrome.webNavigation.onCompleted.addListener((details) => {
    if (details.frameId !== 0) return;
    
    console.log(`Navigation completed for tab ${details.tabId}:`, details.url);
    
    // Trigger scan after navigation completes
    setTimeout(() => scanTab(details.tabId), 2000);
});

// ============================================
// 4. TAB ACTIVATION MONITORING
// ============================================
chrome.tabs.onActivated.addListener(async (activeInfo) => {
    console.log("Tab activated:", activeInfo.tabId);
    
    try {
        const tab = await chrome.tabs.get(activeInfo.tabId);
        console.log("Active tab URL:", tab.url);
        
        if (!isInternalPage(tab.url)) {
            await scanTab(activeInfo.tabId);
        }
    } catch (error) {
        console.error("Error in tab activation:", error);
    }
});

// ============================================
// 5. TAB UPDATE MONITORING
// ============================================
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url) {
        console.log("Tab updated - page loaded:", tab.url);
        
        if (!isInternalPage(tab.url)) {
            await scanTab(tabId);
        }
    }
});

// ============================================
// 6. CONTENT SCRIPT MESSAGE HANDLING
// ============================================
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === "PAGE_ANALYSIS") {
        const tabId = sender.tab?.id;
        if (tabId) {
            console.log("Page analysis received from tab", tabId, msg.data);
            
            // Store content script analysis
            if (!tabData[tabId]) {
                tabData[tabId] = { redirectChain: [], autoDownloads: [], newTabs: [], timestamp: Date.now(), pageAnalysis: {} };
            }
            tabData[tabId].pageAnalysis = msg.data;
            
            chrome.storage.session.set({ [`analysis_${tabId}`]: msg.data });
        }
    }
    
    if (msg.type === "TRIGGER_SCAN" && sender.tab?.id) {
        console.log("Manual scan triggered for tab:", sender.tab.id);
        scanTab(sender.tab.id);
    }
    
    sendResponse({ ok: true });
    return true;
});

// ============================================
// 7. SCREENSHOT CAPTURE (if permissions allow)
// ============================================
async function captureScreenshot(tabId) {
    try {
        // Try to capture screenshot
        const screenshot = await chrome.tabs.captureVisibleTab(null, { format: "png" });
        console.log("Screenshot captured successfully");
        return screenshot;
    } catch (error) {
        console.warn("Screenshot capture failed:", error);
        return "";
    }
}

// ============================================
// 8. MAIN SCAN FUNCTION
// ============================================
async function scanTab(tabId) {
    try {
        const tab = await chrome.tabs.get(tabId);
        if (!tab.url || isInternalPage(tab.url)) {
            console.log("Skipping internal page:", tab.url);
            return;
        }

        console.log("Scanning tab:", tabId, tab.url);

        // Get or initialize tab data
        if (!tabData[tabId]) {
            tabData[tabId] = { redirectChain: [], autoDownloads: [], newTabs: [], timestamp: Date.now(), pageAnalysis: {} };
        }

        // Ensure current URL is in redirect chain
        if (!tabData[tabId].redirectChain.includes(tab.url)) {
            tabData[tabId].redirectChain.push(tab.url);
        }

        // Get content script analysis
        const stored = await chrome.storage.session.get(`analysis_${tabId}`);
        const pageAnalysis = stored[`analysis_${tabId}`] || tabData[tabId].pageAnalysis || {};

        // Capture screenshot (if possible)
        const screenshot_b64 = await captureScreenshot(tabId);

        // Prepare metadata for Flask
        const metadata = {
            current_url: tab.url,
            redirect_chain: tabData[tabId].redirectChain,
            popup_messages: pageAnalysis.popup_messages || [],
            fake_update_detected: pageAnalysis.fake_update_detected || false,
            notification_requests: pageAnalysis.notification_requests || 0,
            auto_downloads: tabData[tabId].autoDownloads.map(d => d.filename || d.downloadUrl),
            ssl_status: tab.url.startsWith("https://"),
            extension_permissions: ["tabs", "storage", "webNavigation", "notifications", "downloads"],
            suspicious_js: pageAnalysis.suspicious_js || [],
            screenshot_b64: screenshot_b64,
            new_tabs_count: tabData[tabId].newTabs.length,
            tab_title: tab.title || "",
            // NEW: Enhanced form analysis data
            login_form_detected: pageAnalysis.login_form_detected || false,
            password_field_count: pageAnalysis.password_field_count || 0,
            username_field_count: pageAnalysis.username_field_count || 0,
            email_field_count: pageAnalysis.email_field_count || 0,
            payment_form_detected: pageAnalysis.payment_form_detected || false,
            sensitive_field_types: pageAnalysis.sensitive_field_types || [],
            form_action_external: pageAnalysis.form_action_external || false,
            external_form_domains: pageAnalysis.external_form_domains || [],
            current_domain: pageAnalysis.current_domain || "",
            is_trusted_domain: pageAnalysis.is_trusted_domain || false,
            // Existing browser behavior fields
            sensitive_forms_detected: pageAnalysis.sensitive_forms_detected || false,
            alert_count: pageAnalysis.alert_count || 0,
            popup_attempts: pageAnalysis.popup_attempts || 0,
            fullscreen_attempts: pageAnalysis.fullscreen_attempts || 0,
        };

        console.log("Sending to Flask:", {
            url: metadata.current_url,
            redirect_length: metadata.redirect_chain.length,
            downloads: metadata.auto_downloads.length,
            new_tabs: metadata.new_tabs_count,
            has_screenshot: !!screenshot_b64
        });

        // Send to Flask API
        const response = await fetch(`${FLASK_API}/api/predict_browser`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(metadata),
        });

        const result = await response.json();
        console.log("Flask response:", result);

        // Store result for popup/dashboard
        await chrome.storage.local.set({ latest_scan: result });

        // Update badge
        chrome.action.setBadgeText({ 
            text: result.verdict === "phishing" ? "!" : "✓", 
            tabId 
        });
        chrome.action.setBadgeBackgroundColor({
            color: result.verdict === "phishing" ? "#ef4444" : "#22c55e",
            tabId,
        });

        // Notify dashboard page if open
        const dashboardTabs = await chrome.tabs.query({ url: `${FLASK_API}/browser*` });
        for (const t of dashboardTabs) {
            chrome.tabs.sendMessage(t.id, { type: "SCAN_COMPLETE", result }).catch(() => {});
        }

    } catch (error) {
        console.error("Scan failed:", error);
    }
}

// ============================================
// 9. PERIODIC ACTIVE TAB SCAN
// ============================================
setInterval(async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id && !isInternalPage(tab.url)) {
        console.log("Periodic scan of active tab:", tab.id);
        scanTab(tab.id);
    }
}, 30000);
