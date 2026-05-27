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
        button.textContent = "Copied";
        window.setTimeout(() => {
          button.textContent = "Copy";
        }, 1200);
      } catch {
        button.textContent = "Failed";
        window.setTimeout(() => {
          button.textContent = "Copy";
        }, 1600);
      }
    });
  });
})();
