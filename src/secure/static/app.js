/* ============================================================
   8TechBank — Frontend JS
   Balance counter animation, live clock, transfer preview
   ============================================================ */

// ── Live Clock ─────────────────────────────────────────────
function startClock() {
    const el = document.getElementById('liveClock');
    if (!el) return;

    function tick() {
        const now = new Date();
        const hh = String(now.getHours()).padStart(2, '0');
        const mm = String(now.getMinutes()).padStart(2, '0');
        const ss = String(now.getSeconds()).padStart(2, '0');
        el.textContent = `${hh}:${mm}:${ss}`;
    }

    tick();
    setInterval(tick, 1000);
}

// ── Balance Counter Animation ──────────────────────────────
function animateBalance() {
    const el = document.getElementById('balanceCounter');
    if (!el) return;

    const target = parseFloat(el.dataset.balance) || 0;
    const duration = 300; // ms
    const steps = 30;
    const increment = target / steps;
    let current = 0;
    let step = 0;

    const timer = setInterval(() => {
        step++;
        current += increment;
        if (step >= steps) {
            current = target;
            clearInterval(timer);
        }
        el.textContent = '$' + current.toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    }, duration / steps);
}

// ── Transfer Live Preview ──────────────────────────────────
function initTransferPreview(currentBalance) {
    const recipientInput = document.getElementById('recipientInput');
    const amountInput    = document.getElementById('amountInput');
    const memoInput      = document.getElementById('memoInput');

    const previewRecipient = document.getElementById('previewRecipient');
    const previewAmount    = document.getElementById('previewAmount');
    const previewMemo      = document.getElementById('previewMemo');
    const previewBalance   = document.getElementById('previewBalance');

    if (!recipientInput || !amountInput) return;

    function updatePreview() {
        const recipient = recipientInput.value.trim() || '—';
        const amount    = parseFloat(amountInput.value) || 0;
        const memo      = memoInput ? memoInput.value.trim() : '';

        if (previewRecipient) previewRecipient.textContent = recipient;

        if (previewAmount) {
            previewAmount.textContent = '$' + amount.toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
            previewAmount.style.color = amount > 0 ? 'var(--danger)' : 'var(--accent)';
        }

        if (previewMemo) {
            previewMemo.textContent = memo || '—';
        }

        if (previewBalance) {
            const remaining = currentBalance - amount;
            previewBalance.textContent = '$' + remaining.toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
            previewBalance.style.color = remaining < 0 ? 'var(--danger)' : 'var(--text)';
        }
    }

    recipientInput.addEventListener('input', updatePreview);
    amountInput.addEventListener('input', updatePreview);
    if (memoInput) memoInput.addEventListener('input', updatePreview);

    updatePreview();
}

// ── Init ───────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    startClock();
    animateBalance();
});
