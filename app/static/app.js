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

    const richEditor = document.getElementById("rich-editor");
    const textarea = document.getElementById("body_html");
    const preview = document.getElementById("preview");
    const emailForm = document.getElementById("email-form");
    const editorError = document.getElementById("editor-error");
    if (richEditor && textarea) {
        const updatePreview = () => {
            textarea.value = richEditor.innerHTML;
            if (preview) preview.srcdoc = textarea.value;
        };
        richEditor.addEventListener("input", updatePreview);
        document.querySelectorAll("[data-editor-command]").forEach((button) => {
            button.addEventListener("click", () => {
                const command = button.dataset.editorCommand;
                if (command === "createLink") {
                    const url = window.prompt("Endereço do link:");
                    if (url) document.execCommand(command, false, url);
                } else {
                    document.execCommand(command, false);
                }
                richEditor.focus();
                updatePreview();
            });
        });
        emailForm?.addEventListener("submit", (event) => {
            updatePreview();
            if (!richEditor.textContent.trim()) {
                event.preventDefault();
                richEditor.focus();
                richEditor.setAttribute("aria-invalid", "true");
                editorError?.classList.remove("d-none");
            }
        });
        updatePreview();
    }
})();
