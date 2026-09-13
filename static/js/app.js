async function copyPassword(id) {
    const response = await fetch(`/api/entry/${id}`);
    if (!response.ok) return;
    const data = await response.json();
    await navigator.clipboard.writeText(data.password);

    const button = event.target;
    const old = button.textContent;
    button.textContent = "Copied!";
    setTimeout(async () => {
        try { await navigator.clipboard.writeText(""); } catch(e) {}
        button.textContent = old;
    }, 15000);
}

function filterEntries() {
    const q = document.getElementById("search").value.toLowerCase();
    const category = document.getElementById("categoryFilter").value;
    document.querySelectorAll(".entry-card").forEach(card => {
        const matchesText = card.dataset.search.includes(q);
        const matchesCategory = !category || card.dataset.category === category;
        card.style.display = matchesText && matchesCategory ? "grid" : "none";
    });
}

// Inactivity warning/lock is intentionally simple for this educational build.
let idleTimer;
function resetIdleTimer() {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
        window.location.href = "/logout";
    }, 30 * 60 * 1000);
}
["mousemove","keydown","click","scroll","touchstart"].forEach(e => {
    document.addEventListener(e, resetIdleTimer, {passive:true});
});
resetIdleTimer();
