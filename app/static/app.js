(() => {
    const modalElement = document.getElementById("confirmationModal");
    const acceptButton = document.getElementById("confirmationModalAccept");
    const message = document.getElementById("confirmationModalMessage");
    const title = document.getElementById("confirmationModalTitle");
    if (!modalElement || !acceptButton || !message || !title || !window.bootstrap) return;

    const modal = new window.bootstrap.Modal(modalElement);
    let pendingForm = null;

    document.addEventListener("submit", (event) => {
        const form = event.target;
        if (!(form instanceof HTMLFormElement) || !form.dataset.confirm || form.dataset.confirmed) return;
        event.preventDefault();
        pendingForm = form;
        title.textContent = form.dataset.confirmTitle || "Confirmar ação";
        message.textContent = form.dataset.confirm;
        acceptButton.className = form.dataset.confirmDanger === "true" ? "btn btn-danger" : "btn btn-primary";
        acceptButton.textContent = form.dataset.confirmButton || "Confirmar";
        modal.show();
    });

    acceptButton.addEventListener("click", () => {
        if (!pendingForm) return;
        pendingForm.dataset.confirmed = "true";
        const form = pendingForm;
        pendingForm = null;
        modal.hide();
        form.requestSubmit();
    });

    document.addEventListener("click", (event) => {
        const button = event.target.closest("[data-copy-target]");
        if (!button) return;
        const input = document.getElementById(button.dataset.copyTarget);
        if (!input) return;
        const complete = () => {
            const original = button.textContent;
            button.textContent = "Copiado";
            window.setTimeout(() => { button.textContent = original; }, 1600);
        };
        if (navigator.clipboard?.writeText) {
            navigator.clipboard.writeText(input.value).then(complete).catch(() => {
                input.select(); document.execCommand("copy"); complete();
            });
        } else {
            input.select(); document.execCommand("copy"); complete();
        }
    });

    const textarea = document.getElementById("body_html");
    const preview = document.getElementById("preview");
    if (textarea && preview) {
        const updatePreview = () => { preview.srcdoc = textarea.value; };
        textarea.addEventListener("input", updatePreview);
        updatePreview();
    }
})();
