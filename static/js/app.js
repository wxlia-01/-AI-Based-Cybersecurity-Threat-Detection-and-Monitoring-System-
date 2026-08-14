/* CyberShield — Frontend Logic */
"use strict";

let selectedType = "auto";

// ── Type selector ──────────────────────────────────────
document.querySelectorAll(".type-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".type-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    selectedType = btn.dataset.type;
  });
});

// ── Load examples on startup ───────────────────────────
async function loadExamples() {
  try {
    const res = await fetch("/api/examples");
    const examples = await res.json();
    const grid = document.getElementById("examplesGrid");
    grid.innerHTML = "";
    examples.forEach(ex => {
      const chip = document.createElement("span");
      chip.className = "example-chip";
      chip.textContent = ex.label;
      chip.title = ex.value;
      chip.onclick = () => {
        document.getElementById("inputArea").value = ex.value;
        // Set matching type button
        document.querySelectorAll(".type-btn").forEach(b => {
          b.classList.toggle("active", b.dataset.type === ex.type);
        });
        selectedType = ex.type;
      };
      grid.appendChild(chip);
    });
  } catch (e) {
    console.error("Failed to load examples", e);
  }
}

// ── Scan ───────────────────────────────────────────────
async function runScan() {
  const input = document.getElementById("inputArea").value.trim();
  if (!input) {
    document.getElementById("inputArea").focus();
    return;
  }

  const btn = document.getElementById("scanBtn");
  const btnText = document.getElementById("scanBtnText");
  btn.disabled = true;
  btnText.innerHTML = '<span class="spinner"></span>Scanning…';

  // Hide placeholder, hide old result
  document.getElementById("placeholderCard").style.display = "none";
  document.getElementById("resultCard").style.display = "none";

  // Remove old error banners
  document.querySelectorAll(".error-banner").forEach(e => e.remove());

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input, type: selectedType }),
    });
    const data = await res.json();

    if (data.error) {
      showError(data.error);
    } else {
      renderResult(data);
      loadHistory();
    }
  } catch (err) {
    showError("Network error — is the server running?");
  } finally {
    btn.disabled = false;
    btnText.textContent = "🔍 Scan";
  }
}

// Allow Enter key (Ctrl+Enter) to trigger scan
document.getElementById("inputArea").addEventListener("keydown", e => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") runScan();
});

// ── Render result ──────────────────────────────────────
function renderResult(data) {
  const card = document.getElementById("resultCard");

  // Verdict
  const icons = { safe: "✅", suspicious: "⚠️", malicious: "🚨" };
  document.getElementById("verdictIcon").textContent  = icons[data.label] || "❓";
  const vl = document.getElementById("verdictLabel");
  vl.textContent  = data.label;
  vl.className = "verdict-label " + data.label;

  // Badges
  document.getElementById("inputTypeBadge").textContent  = data.input_type;
  document.getElementById("confidenceBadge").textContent = `${data.confidence}% confidence`;

  // Probability bars
  const probContainer = document.getElementById("probBars");
  probContainer.innerHTML = "";
  const order = ["safe", "suspicious", "malicious"];
  order.forEach(cls => {
    const pct = data.probabilities[cls] ?? 0;
    const row = document.createElement("div");
    row.className = "prob-row";
    row.innerHTML = `
      <span class="prob-label ${cls}">${cls}</span>
      <div class="prob-track">
        <div class="prob-fill ${cls}" style="width:0%"></div>
      </div>
      <span class="prob-pct">${pct.toFixed(1)}%</span>`;
    probContainer.appendChild(row);
    // Animate fill after render
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        row.querySelector(".prob-fill").style.width = pct + "%";
      });
    });
  });

  // Explanations
  const ul = document.getElementById("explainList");
  ul.innerHTML = "";
  (data.explanations || []).forEach(msg => {
    const li = document.createElement("li");
    li.textContent = msg;
    ul.appendChild(li);
  });

  // Feature grid
  const grid = document.getElementById("featureGrid");
  grid.innerHTML = "";
  Object.entries(data.features || {}).forEach(([k, v]) => {
    const item = document.createElement("div");
    item.className = "feat-item";
    const displayVal = typeof v === "number" ? (Number.isInteger(v) ? v : v.toFixed(4)) : v;
    item.innerHTML = `<div class="feat-name">${k.replace(/_/g, " ")}</div>
                      <div class="feat-value">${displayVal}</div>`;
    grid.appendChild(item);
  });

  card.style.display = "block";
  card.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// ── Error display ──────────────────────────────────────
function showError(msg) {
  const banner = document.createElement("div");
  banner.className = "error-banner";
  banner.textContent = "⚠ " + msg;
  document.querySelector(".results-column").prepend(banner);
  document.getElementById("placeholderCard").style.display = "block";
}

// ── Clear ──────────────────────────────────────────────
function clearAll() {
  document.getElementById("inputArea").value = "";
  document.getElementById("resultCard").style.display = "none";
  document.getElementById("placeholderCard").style.display = "block";
  document.querySelectorAll(".error-banner").forEach(e => e.remove());
}

// ── History ────────────────────────────────────────────
async function loadHistory() {
  try {
    const res = await fetch("/api/history");
    const history = await res.json();
    const list = document.getElementById("historyList");
    if (!history.length) {
      list.innerHTML = '<p class="muted-msg">No scans yet.</p>';
      return;
    }
    list.innerHTML = "";
    history.forEach(h => {
      const item = document.createElement("div");
      item.className = "history-item";
      item.innerHTML = `
        <span class="hist-label ${h.label}">${h.label}</span>
        <span class="hist-input" title="${h.input}">${h.input}</span>
        <span class="hist-time">${h.timestamp}</span>`;
      item.style.cursor = "pointer";
      item.onclick = () => {
        document.getElementById("inputArea").value = h.input;
        runScan();
      };
      list.appendChild(item);
    });
  } catch (e) {
    console.error("History error", e);
  }
}

// ── Init ───────────────────────────────────────────────
loadExamples();
loadHistory();
