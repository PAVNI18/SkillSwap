document.addEventListener("DOMContentLoaded", () => {
    const cardStack = document.querySelector("#swipe-card-stack");
    const statusMessage = document.querySelector("#swipe-status");
    const undoPassForm = document.querySelector("#undo-pass-form");
    const connectionsLink = document.querySelector("#view-connections-link");
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;

    if (!cardStack) {
        return;
    }

    let startX = 0;
    let currentCard = null;

    function showNextCard(lastAction) {
        const nextCard = cardStack.querySelector(
            "[data-match-card]:not(.is-swiped)"
        );

        if (nextCard) {
            nextCard.classList.add("is-active");
        } else {
            if (statusMessage) {
                statusMessage.textContent = lastAction === "interested"
                    ? "Connection request sent. View it in Connections."
                    : "Match passed. You can undo your last pass below.";
            }

            if (lastAction === "pass" && undoPassForm) {
                undoPassForm.hidden = false;
            }

            if (lastAction === "interested" && connectionsLink) {
                connectionsLink.hidden = false;
            }
        }
    }

    async function swipeCard(direction) {
        const activeCard = cardStack.querySelector(".is-active");

        if (!activeCard) {
            return;
        }

        const action = direction === "left" ? "pass" : "interested";
        const actionButtons = activeCard.querySelectorAll("button");
        actionButtons.forEach((button) => {
            button.disabled = true;
        });

        try {
            const response = await fetch(
                `/matches/${activeCard.dataset.matchId}/action`,
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-CSRF-Token": csrfToken,
                    },
                    body: JSON.stringify({action})
                }
            );
            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error);
            }

            if (statusMessage) {
                statusMessage.textContent = result.message;
            }
        } catch (error) {
            if (statusMessage) {
                statusMessage.textContent = "Could not save your choice. Please try again.";
            }

            actionButtons.forEach((button) => {
                button.disabled = false;
            });

            return;
        }

        activeCard.classList.remove("is-active");
        activeCard.classList.add(
            direction === "left" ? "swipe-left" : "swipe-right"
        );

        window.setTimeout(() => {
            activeCard.classList.add("is-swiped");
            showNextCard(action);
        }, 280);
    }

    // Buttons need their own handlers so a click never starts the drag action
    // on the card behind them.
    cardStack.querySelectorAll("[data-swipe-action]").forEach((button) => {
        button.addEventListener("pointerdown", (event) => {
            event.stopPropagation();
        });

        button.addEventListener("click", (event) => {
            event.preventDefault();
            event.stopPropagation();
            swipeCard(button.dataset.swipeAction);
        });
    });

    cardStack.addEventListener("pointerdown", (event) => {
        currentCard = event.target.closest(".is-active");

        if (!currentCard) {
            return;
        }

        startX = event.clientX;
        currentCard.setPointerCapture(event.pointerId);
    });

    cardStack.addEventListener("pointermove", (event) => {
        if (!currentCard) {
            return;
        }

        const distance = event.clientX - startX;
        currentCard.style.transform = `translateX(${distance}px) rotate(${distance / 18}deg)`;
    });

    cardStack.addEventListener("pointerup", (event) => {
        if (!currentCard) {
            return;
        }

        const distance = event.clientX - startX;
        currentCard.style.transform = "";
        currentCard.releasePointerCapture(event.pointerId);
        currentCard = null;

        if (distance > 100) {
            swipeCard("right");
        } else if (distance < -100) {
            swipeCard("left");
        }
    });
});

document.addEventListener("DOMContentLoaded", () => {
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
    if (csrfToken) {
        document.querySelectorAll('form[method="POST"], form[method="post"]').forEach((form) => {
            if (form.querySelector('input[name="csrf_token"]')) return;
            const tokenInput = document.createElement("input");
            tokenInput.type = "hidden";
            tokenInput.name = "csrf_token";
            tokenInput.value = csrfToken;
            form.append(tokenInput);
        });
    }

    const printCertificateButton = document.querySelector("#print-certificate");

    if (!printCertificateButton) {
        return;
    }

    printCertificateButton.addEventListener("click", () => {
        window.print();
    });
});

document.addEventListener("DOMContentLoaded", () => {
    const chatMessages = document.querySelector("#chat-messages");

    if (chatMessages) {
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }
});

document.addEventListener("DOMContentLoaded", () => {
    const levelSelect = document.querySelector("#skill_level");
    const uploadGroup = document.querySelector("[data-certificate-upload]");
    const certificateInput = document.querySelector("[data-certificate-input]");

    if (!levelSelect || !uploadGroup || !certificateInput) {
        return;
    }

    function updateCertificateRequirement() {
        const needsProof = ["Intermediate", "Advanced"].includes(levelSelect.value);
        const hasCertificate = uploadGroup.dataset.hasCertificate === "true";

        uploadGroup.hidden = !needsProof;
        certificateInput.required = needsProof && !hasCertificate;
    }

    levelSelect.addEventListener("change", updateCertificateRequirement);
    certificateInput.addEventListener("change", () => {
        const selectedFile = certificateInput.files[0];
        if (!selectedFile) return;

        const maxCertificateSize = 10 * 1024 * 1024;
        certificateInput.setCustomValidity(
            selectedFile.size > maxCertificateSize
                ? "Certificate files must be 10 MB or smaller."
                : ""
        );
        certificateInput.reportValidity();
    });
    updateCertificateRequirement();
});

document.addEventListener("DOMContentLoaded", () => {
    const notificationLink = document.querySelector("[data-notification-link]");

    if (!notificationLink) {
        return;
    }

    function showRatingPrompt(prompt) {
        const storageKey = `shown-rating-prompt-${prompt.id}`;
        if (sessionStorage.getItem(storageKey)) return;
        sessionStorage.setItem(storageKey, "true");

        const toast = document.createElement("aside");
        toast.className = "session-rating-toast";
        toast.setAttribute("role", "status");

        const message = document.createElement("p");
        message.textContent = prompt.message;
        const action = document.createElement("a");
        action.href = prompt.link || "/notifications";
        action.textContent = "Share feedback";
        const dismiss = document.createElement("button");
        dismiss.type = "button";
        dismiss.setAttribute("aria-label", "Dismiss notification");
        dismiss.textContent = "×";
        dismiss.addEventListener("click", () => toast.remove());

        toast.append(message, action, dismiss);
        document.body.append(toast);
    }

    async function refreshNotificationCount() {
        try {
            const response = await fetch("/api/session-reminders");
            const data = await response.json();
            const existingBadge = notificationLink.querySelector("span");

            if (!data.unread) {
                if (existingBadge) existingBadge.remove();
                return;
            }

            if (existingBadge) {
                existingBadge.textContent = data.unread;
            } else {
                const badge = document.createElement("span");
                badge.textContent = data.unread;
                notificationLink.append(badge);
            }

            (data.rating_prompts || []).forEach(showRatingPrompt);
        } catch (_error) {
            // The page continues to work normally if the local server is restarting.
        }
    }

    refreshNotificationCount();
    window.setInterval(refreshNotificationCount, 15000);
});

document.addEventListener("DOMContentLoaded", () => {
    const bio = document.querySelector("#bio");
    const count = document.querySelector("[data-bio-count]");

    if (!bio || !count) {
        return;
    }

    function updateBioCount() {
        count.textContent = `${bio.value.length} / 300`;
    }

    bio.addEventListener("input", updateBioCount);
    updateBioCount();
});

document.addEventListener("DOMContentLoaded", () => {
    const pushPreference = document.querySelector("[data-push-preference]");
    if (!pushPreference) return;

    const enableButton = pushPreference.querySelector("[data-enable-push]");
    const disableButton = pushPreference.querySelector("[data-disable-push]");
    const status = pushPreference.querySelector("[data-push-status]");
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
    const vapidPublicKey = pushPreference.dataset.vapidPublicKey;

    function setStatus(message) { status.textContent = message; }

    function base64ToUint8Array(value) {
        const padding = "=".repeat((4 - (value.length % 4)) % 4);
        const base64 = (value + padding).replace(/-/g, "+").replace(/_/g, "/");
        const rawData = window.atob(base64);
        return Uint8Array.from(rawData, (character) => character.charCodeAt(0));
    }

    async function getRegistration() {
        if (!("serviceWorker" in navigator) || !("PushManager" in window)) {
            throw new Error("This browser does not support push notifications.");
        }
        return navigator.serviceWorker.register("/static/service-worker.js");
    }

    enableButton.addEventListener("click", async () => {
        try {
            const permission = await Notification.requestPermission();
            if (permission !== "granted") return setStatus("Browser permission was not granted.");
            const registration = await getRegistration();
            const subscription = await registration.pushManager.getSubscription()
                || await registration.pushManager.subscribe({
                    userVisibleOnly: true,
                    applicationServerKey: base64ToUint8Array(vapidPublicKey),
                });
            const response = await fetch("/api/push-subscription", {
                method: "POST",
                headers: {"Content-Type": "application/json", "X-CSRF-Token": csrfToken},
                body: JSON.stringify(subscription),
            });
            if (!response.ok) throw new Error("SkillSwap could not save this browser.");
            setStatus("Browser push notifications are enabled.");
        } catch (error) {
            setStatus(error.message || "Browser push could not be enabled.");
        }
    });

    disableButton.addEventListener("click", async () => {
        try {
            const registration = await getRegistration();
            const subscription = await registration.pushManager.getSubscription();
            if (!subscription) return setStatus("Browser push is already off.");
            const response = await fetch("/api/push-subscription", {
                method: "DELETE",
                headers: {"Content-Type": "application/json", "X-CSRF-Token": csrfToken},
                body: JSON.stringify(subscription),
            });
            if (!response.ok) throw new Error("SkillSwap could not remove this browser.");
            await subscription.unsubscribe();
            setStatus("Browser push notifications are disabled.");
        } catch (error) {
            setStatus(error.message || "Browser push could not be disabled.");
        }
    });
});

document.addEventListener("DOMContentLoaded", () => {
    const deck = document.querySelector("#onboarding-card-stack");
    if (!deck) return;

    const status = document.querySelector("#onboarding-status");
    const finish = document.querySelector("#onboarding-finish");
    const skipForm = document.querySelector("#onboarding-skip-form");
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
    let startX = 0;
    let currentCard = null;

    function nextCard() {
        const next = deck.querySelector("[data-onboarding-card]:not(.is-swiped)");
        if (next) {
            next.classList.add("is-active");
            return;
        }
        if (status) status.textContent = "You have reviewed every demo card.";
        if (finish) finish.hidden = false;
        if (skipForm) skipForm.hidden = true;
    }

    async function choose(direction) {
        const activeCard = deck.querySelector(".onboarding-skill-card.is-active");
        if (!activeCard) return;

        const buttons = activeCard.querySelectorAll("button");
        buttons.forEach((button) => { button.disabled = true; });
        const action = direction === "right" ? "interested" : "pass";

        try {
            const response = await fetch(deck.dataset.actionUrl, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": csrfToken,
                },
                body: JSON.stringify({card_id: activeCard.dataset.cardId, action}),
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.error);
            if (status) status.textContent = result.message;
        } catch (error) {
            if (status) status.textContent = error.message || "Could not save your choice. Please try again.";
            buttons.forEach((button) => { button.disabled = false; });
            return;
        }

        activeCard.classList.remove("is-active");
        activeCard.classList.add(direction === "right" ? "swipe-right" : "swipe-left");
        window.setTimeout(() => {
            activeCard.classList.add("is-swiped");
            nextCard();
        }, 280);
    }

    deck.querySelectorAll("[data-onboarding-action]").forEach((button) => {
        button.addEventListener("pointerdown", (event) => event.stopPropagation());
        button.addEventListener("click", (event) => {
            event.preventDefault();
            event.stopPropagation();
            choose(button.dataset.onboardingAction);
        });
    });

    deck.addEventListener("pointerdown", (event) => {
        currentCard = event.target.closest(".onboarding-skill-card.is-active");
        if (!currentCard) return;
        startX = event.clientX;
        currentCard.setPointerCapture(event.pointerId);
    });

    deck.addEventListener("pointermove", (event) => {
        if (!currentCard) return;
        const distance = event.clientX - startX;
        currentCard.style.transform = `translateX(${distance}px) rotate(${distance / 18}deg)`;
    });

    deck.addEventListener("pointerup", (event) => {
        if (!currentCard) return;
        const distance = event.clientX - startX;
        currentCard.style.transform = "";
        currentCard.releasePointerCapture(event.pointerId);
        currentCard = null;
        if (distance > 100) choose("right");
        if (distance < -100) choose("left");
    });
});
