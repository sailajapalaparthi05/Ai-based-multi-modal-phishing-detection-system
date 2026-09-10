document.addEventListener("DOMContentLoaded", () => {
    const form = document.querySelector(".email-form");
    const button = form?.querySelector(".btn-submit");
    if (form && button) {
        form.addEventListener("submit", () => {
            button.disabled = true;
            button.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Running BiLSTM Analysis...';
        });
    }

    const attachmentInput = document.getElementById("attachments");
    const tagContainer = document.getElementById("attachment-tags");
    if (attachmentInput && tagContainer) {
        attachmentInput.addEventListener("change", () => {
            tagContainer.innerHTML = "";
            Array.from(attachmentInput.files).forEach(file => {
                const tag = document.createElement("span");
                tag.className = "attachment-tag";
                tag.innerHTML = `<i class="fa-solid fa-paperclip"></i> ${file.name}`;
                tagContainer.appendChild(tag);
            });
        });
    }
});
