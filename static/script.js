document.addEventListener("DOMContentLoaded", () => {

    // =========================
    // Percentage Animation
    // =========================

    const percent = document.getElementById("percent");

    if (percent) {

        const target = parseInt(percent.dataset.value) || 0;

        let count = 0;

        const speed = Math.max(10, 1000 / target);

        const timer = setInterval(() => {

            count++;

            percent.innerText = count + "%";

            if (count >= target) {

                clearInterval(timer);

            }

        }, speed);

    }

    // =========================
    // Cards Animation
    // =========================

    const cards = document.querySelectorAll(".card");

    cards.forEach((card, index) => {

        card.style.opacity = "0";

        card.style.transform = "translateY(30px)";

        setTimeout(() => {

            card.style.transition = "0.6s ease";

            card.style.opacity = "1";

            card.style.transform = "translateY(0)";

        }, index * 120);

    });

    // =========================
    // Scan Button Loading
    // =========================

    const form = document.querySelector(".search-box");

    const button = document.querySelector(".search-box button");

    if (form && button) {

        form.addEventListener("submit", () => {

            button.disabled = true;

            button.innerHTML = `
                <i class="fa-solid fa-spinner fa-spin"></i>
                Scanning...
            `;

        });

    }

});