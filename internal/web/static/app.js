document.addEventListener("click", (event) => {
  const target = event.target instanceof Element ? event.target : null;
  if (!target) return;
  const opener = target.closest("[data-open]");
  if (opener) {
    opener.closest("details")?.removeAttribute("open");
    document.getElementById(opener.getAttribute("data-open"))?.showModal();
    return;
  }
  const closer = target.closest("[data-close]");
  if (closer) {
    closer.closest("dialog")?.close();
    return;
  }
  const copier = target.closest("[data-copy]");
  if (copier) {
    navigator.clipboard.writeText(copier.getAttribute("data-copy")).then(
      () => {
        copier.textContent = "Copied";
        setTimeout(() => {
          copier.textContent = "Copy";
        }, 1500);
      },
      () => {
        copier.textContent = "Copy failed";
      },
    );
  }
});

for (const time of document.querySelectorAll("time[datetime]")) {
  const at = new Date(time.getAttribute("datetime"));
  if (!Number.isNaN(at.getTime())) {
    time.textContent = at.toLocaleString(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    });
  }
}
