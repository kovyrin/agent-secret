(() => {
  const copyButtons = document.querySelectorAll("[data-copy-button]");

  const copyText = async (text) => {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return;
    }

    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    textarea.remove();
  };

  copyButtons.forEach((button) => {
    button.addEventListener("click", async () => {
      const source = button.closest(".copyable")?.querySelector("[data-copy-text]");
      const text = source?.innerText.trim();

      if (!text) return;

      try {
        await copyText(text);
        button.dataset.state = "copied";
        button.setAttribute("aria-label", "Copied");
        window.setTimeout(() => {
          delete button.dataset.state;
          button.setAttribute("aria-label", button.dataset.copyLabel);
        }, 1200);
      } catch {
        button.dataset.state = "failed";
        button.setAttribute("aria-label", "Copy failed");
        window.setTimeout(() => {
          delete button.dataset.state;
          button.setAttribute("aria-label", button.dataset.copyLabel);
        }, 1600);
      }
    });
    button.dataset.copyLabel = button.getAttribute("aria-label") || "Copy";
  });
})();
