(function () {
    const UPDATE_WORDS = ["update browser", "chrome is outdated", "browser update", "critical update", "flash player", "out of date", "update required", "install now"];
    const URGENCY_WORDS = ["virus detected", "threat found", "infected", "hacked", "compromised", "security warning", "critical threat", "call support", "your computer is at risk", "system infected", "malware detected"];
    const SUSPICIOUS_JS_PATTERNS = ["eval(", "document.write(", "fromCharCode", "unescape(", "atob(", "crypto miner", "coinhive", "keylogger", "iframe", "script src="];
    const SENSITIVE_FIELDS = ["password", "credit", "card", "cvv", "cvc", "otp", "bank", "account", "upi", "payment", "ssn", "secret"];
    const TRUSTED_DOMAINS = ["google.com", "instagram.com", "facebook.com", "microsoft.com", "apple.com", "amazon.com", "github.com", "linkedin.com", "twitter.com", "paypal.com", "ebay.com", "netflix.com", "appleid.apple.com", "accounts.google.com", "login.microsoftonline.com"];
    const LOGIN_KEYWORDS = ["login", "signin", "sign-in", "auth", "authenticate", "session", "credential", "logon"];
    const PAYMENT_KEYWORDS = ["credit", "card", "cvv", "cvc", "expiry", "expire", "bank", "account", "upi", "payment", "wallet", "crypto", "bitcoin", "ether", "financial", "billing"];

    const popup_messages = [];
    let notification_requests = 0;
    let fake_update_detected = false;
    const suspicious_js = [];
    let sensitive_forms_detected = false;
    let popup_attempts = 0;
    let alert_count = 0;
    let fullscreen_attempts = 0;

    // NEW: Enhanced form analysis
    let login_form_detected = false;
    let password_field_count = 0;
    let username_field_count = 0;
    let email_field_count = 0;
    let payment_form_detected = false;
    let sensitive_field_types = [];
    let form_action_external = false;
    let external_form_domains = [];
    let current_domain = location.hostname.toLowerCase();
    let is_trusted_domain = TRUSTED_DOMAINS.some(trusted => current_domain.includes(trusted));

    // Detect fake update pages
    const bodyText = document.body?.innerText?.toLowerCase() || "";
    for (const word of UPDATE_WORDS) {
        if (bodyText.includes(word)) {
            fake_update_detected = true;
            popup_messages.push(`Fake update indicator: ${word}`);
        }
    }
    for (const word of URGENCY_WORDS) {
        if (bodyText.includes(word)) {
            popup_messages.push(`Scareware popup: ${word}`);
        }
    }

    // Detect suspicious JavaScript in page source
    const scripts = document.querySelectorAll("script");
    scripts.forEach((script) => {
        const code = script.textContent || "";
        for (const pattern of SUSPICIOUS_JS_PATTERNS) {
            if (code.includes(pattern) && !suspicious_js.includes(pattern)) {
                suspicious_js.push(pattern);
            }
        }
        // Detect crypto mining patterns
        if (code.includes("miner") || code.includes("coinhive") || code.includes("cryptonight")) {
            suspicious_js.push("crypto miner");
        }
        // Detect keylogger patterns
        if (code.includes("keydown") || code.includes("keypress") || code.includes("addEventListener.*key")) {
            suspicious_js.push("keylogger behavior");
        }
    });

    // Monitor actual notification requests (not just permission check)
    const originalRequest = Notification.requestPermission;
    if (Notification.requestPermission) {
        Notification.requestPermission = function() {
            notification_requests++;
            popup_messages.push("Notification permission requested");
            return originalRequest.apply(this, arguments);
        };
    }

    // Detect alert/confirm/prompt overrides (common in scam pages)
    const originalAlert = window.alert;
    window.alert = function (msg) {
        alert_count++;
        popup_messages.push(`Alert popup: ${String(msg).substring(0, 200)}`);
        return originalAlert.apply(this, arguments);
    };

    const originalConfirm = window.confirm;
    window.confirm = function (msg) {
        alert_count++;
        popup_messages.push(`Confirm dialog: ${String(msg).substring(0, 200)}`);
        return originalConfirm.apply(this, arguments);
    };

    const originalPrompt = window.prompt;
    window.prompt = function (msg) {
        alert_count++;
        popup_messages.push(`Prompt dialog: ${String(msg).substring(0, 200)}`);
        return originalPrompt.apply(this, arguments);
    };

    // Detect popup/window.open abuse
    const originalOpen = window.open;
    window.open = function() {
        popup_attempts++;
        popup_messages.push("Popup window opened");
        return originalOpen.apply(this, arguments);
    };

    // Detect fullscreen abuse
    const originalRequestFullscreen = document.documentElement.requestFullscreen;
    if (originalRequestFullscreen) {
        document.documentElement.requestFullscreen = function() {
            fullscreen_attempts++;
            popup_messages.push("Fullscreen requested");
            return originalRequestFullscreen.apply(this, arguments);
        };
    }

    // NEW: Enhanced form analysis
    const allForms = document.querySelectorAll("form");
    const allInputs = document.querySelectorAll("input");

    // Analyze individual input fields
    allInputs.forEach(input => {
        const inputType = input.type?.toLowerCase() || "";
        const inputName = input.name?.toLowerCase() || "";
        const inputId = input.id?.toLowerCase() || "";
        const inputPlaceholder = input.placeholder?.toLowerCase() || "";
        const fieldText = `${inputType} ${inputName} ${inputId} ${inputPlaceholder}`;

        // Password field detection
        if (inputType === "password" || fieldText.includes("password") || fieldText.includes("passwd") || fieldText.includes("pwd")) {
            password_field_count++;
            if (!sensitive_field_types.includes("password")) {
                sensitive_field_types.push("password");
            }
        }

        // Username/email field detection
        if (inputType === "email" || fieldText.includes("email") || fieldText.includes("mail") || fieldText.includes("username") || fieldText.includes("user") || fieldText.includes("login") || fieldText.includes("userid")) {
            if (inputType === "email" || fieldText.includes("email") || fieldText.includes("mail")) {
                email_field_count++;
            } else {
                username_field_count++;
            }
        }

        // Payment/sensitive field detection
        for (const sensitive of SENSITIVE_FIELDS) {
            if (sensitive in fieldText) {
                sensitive_forms_detected = true;
                if (!sensitive_field_types.includes(sensitive)) {
                    sensitive_field_types.push(sensitive);
                }
            }
        }

        // Payment-specific detection
        for (const payment of PAYMENT_KEYWORDS) {
            if (payment in fieldText) {
                payment_form_detected = true;
                if (!sensitive_field_types.includes(payment)) {
                    sensitive_field_types.push(payment);
                }
            }
        }
    });

    // Analyze forms and their actions
    allForms.forEach(form => {
        const formAction = form.action?.toLowerCase() || "";
        const formId = form.id?.toLowerCase() || "";
        const formClass = form.className?.toLowerCase() || "";
        const formMethod = form.method?.toLowerCase() || "post";

        // Check if form contains login keywords
        const formText = `${formAction} ${formId} ${formClass}`;
        for (const login of LOGIN_KEYWORDS) {
            if (login in formText) {
                login_form_detected = true;
                break;
            }
        }

        // If no action specified, it submits to current domain
        if (!formAction) {
            return; // Same domain by default
        }

        // Parse form action domain
        try {
            const actionUrl = new URL(formAction, location.href);
            const actionDomain = actionUrl.hostname.toLowerCase();

            // Check if form submits to external domain
            if (actionDomain !== current_domain) {
                form_action_external = true;
                if (!external_form_domains.includes(actionDomain)) {
                    external_form_domains.push(actionDomain);
                }
            }
        } catch (e) {
            // Invalid URL, skip
        }
    });

    // Determine if this is a login form
    if (password_field_count > 0 && (username_field_count > 0 || email_field_count > 0)) {
        login_form_detected = true;
    }

    // Legacy sensitive form detection (for backward compatibility)
    const allInputsLegacy = document.querySelectorAll("input");
    allInputsLegacy.forEach(input => {
        const inputType = input.type?.toLowerCase() || "";
        const inputName = input.name?.toLowerCase() || "";
        const inputId = input.id?.toLowerCase() || "";
        const inputPlaceholder = input.placeholder?.toLowerCase() || "";
        
        const fieldText = `${inputType} ${inputName} ${inputId} ${inputPlaceholder}`;
        
        for (const sensitive of SENSITIVE_FIELDS) {
            if (sensitive in fieldText) {
                sensitive_forms_detected = true;
                if (!popup_messages.some(msg => msg.includes(`Sensitive form field detected: ${sensitive}`))) {
                    popup_messages.push(`Sensitive form field detected: ${sensitive}`);
                }
                break;
            }
        }
    });

    // Check for password fields on untrusted domains (legacy logic)
    if (password_field_count > 0 && !is_trusted_domain) {
        popup_messages.push(`Password form on untrusted domain: ${current_domain}`);
    }

    // Add form action warnings
    if (form_action_external) {
        popup_messages.push(`Form submits to external domain: ${external_form_domains.join(", ")}`);
    }

    if (payment_form_detected && !is_trusted_domain) {
        popup_messages.push(`Payment form detected on untrusted domain: ${current_domain}`);
    }

    // Detect excessive popups/alerts
    if (alert_count > 3) {
        popup_messages.push(`Excessive alert dialogs: ${alert_count}`);
    }
    if (popup_attempts > 2) {
        popup_messages.push(`Multiple popup windows: ${popup_attempts}`);
    }
    if (fullscreen_attempts > 1) {
        popup_messages.push(`Fullscreen abuse detected: ${fullscreen_attempts}`);
    }

    // Send analysis to background script
    chrome.runtime.sendMessage({
        type: "PAGE_ANALYSIS",
        data: {
            popup_messages,
            fake_update_detected,
            notification_requests,
            suspicious_js,
            page_title: document.title,
            page_url: location.href,
            sensitive_forms_detected,
            alert_count,
            popup_attempts,
            fullscreen_attempts,
            // NEW: Enhanced form analysis data
            login_form_detected,
            password_field_count,
            username_field_count,
            email_field_count,
            payment_form_detected,
            sensitive_field_types,
            form_action_external,
            external_form_domains,
            current_domain,
            is_trusted_domain,
        },
    });

    // Listen for scan complete messages from background
    chrome.runtime.onMessage.addListener((msg) => {
        if (msg.type === "SCAN_COMPLETE") {
            window.postMessage({ type: "BROWSER_SCAN_RESULT", result: msg.result }, "*");
        }
    });
})();
