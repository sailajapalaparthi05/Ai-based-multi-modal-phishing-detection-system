document.addEventListener("DOMContentLoaded", () => {
    const modal = document.getElementById("url-modal");
    if (!modal) return;

    const overlay = modal.querySelector(".url-modal-overlay");
    const closeBtn = modal.querySelector(".url-modal-close");
    const modalUrl = document.getElementById("modal-url");
    const modalStatus = document.getElementById("modal-status");
    const modalConfidence = document.getElementById("modal-confidence");
    const modalRiskScore = document.getElementById("modal-risk-score");
    const modalRisksList = document.getElementById("modal-risks-list");
    const modalRisksSection = modal.querySelector(".url-modal-risks");

    function openModal(item) {
        const url = item.dataset.url || "";
        const status = (item.dataset.status || "unknown").toLowerCase();
        const confidence = item.dataset.confidence || "0";
        const riskScore = item.dataset.riskScore || "0";
        let risks = [];

        try {
            const raw = item.dataset.risks || "[]";
            const parsed = JSON.parse(raw);
            risks = Array.isArray(parsed) ? parsed : [];
        } catch (e) {
            console.warn("[url-modal] Failed to parse risks JSON:", e);
            risks = [];
        }

        if (modalUrl) modalUrl.textContent = url;
        if (modalStatus) {
            modalStatus.textContent = status.charAt(0).toUpperCase() + status.slice(1);
            modalStatus.className = "url-modal-badge " + status;
        }
        if (modalConfidence) modalConfidence.textContent = "Confidence: " + confidence + "%";
        if (modalRiskScore) modalRiskScore.textContent = "Risk Score: " + riskScore + "/100";

        if (modalRisksList) {
            modalRisksList.innerHTML = "";
            if (risks.length) {
                risks.forEach((risk) => {
                    const li = document.createElement("li");
                    li.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> ' + risk;
                    modalRisksList.appendChild(li);
                });
            } else {
                const li = document.createElement("li");
                li.className = "no-risks";
                li.innerHTML = '<i class="fa-solid fa-circle-check"></i> No risk factors detected';
                modalRisksList.appendChild(li);
            }
        }

        if (modalRisksSection) {
            modalRisksSection.style.display = "block";
            modalRisksSection.style.visibility = "visible";
            modalRisksSection.style.opacity = "1";
        }

        modal.classList.add("active");
        document.body.style.overflow = "hidden";
        console.log("[url-modal] Opened for:", url, "risks:", risks.length);
    }

    function closeModal() {
        modal.classList.remove("active");
        document.body.style.overflow = "";
    }

    const clickables = document.querySelectorAll(".url-item.clickable");
    console.log("[url-modal] clickable items found:", clickables.length);
    clickables.forEach((item) => {
        item.addEventListener("click", () => openModal(item));
    });

    if (overlay) overlay.addEventListener("click", closeModal);
    if (closeBtn) closeBtn.addEventListener("click", closeModal);

    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape" && modal.classList.contains("active")) {
            closeModal();
        }
    });
});
