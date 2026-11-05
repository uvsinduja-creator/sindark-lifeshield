/**
 * LifeShield Extension Popup Script
 *
 * Checks agent /health status, reads event counters from chrome.storage.local,
 * and allows toggling event collection on/off.
 */

const AGENT_HEALTH_URL = "http://127.0.0.1:8787/health";

const dot = document.getElementById("status-dot");
const statusText = document.getElementById("status-text");
const toggleEl = document.getElementById("toggle");
const sentEl = document.getElementById("sent-count");
const missEl = document.getElementById("miss-count");
const lastEl = document.getElementById("last-event-time");

function formatTime(ts) {
  if (!ts) return "—";
  return new Date(ts).toLocaleTimeString();
}

// Load saved toggle state
chrome.storage.local.get(["collectionEnabled"], (result) => {
  toggleEl.checked = result.collectionEnabled !== false;
});

// Toggle change listener
toggleEl.addEventListener("change", () => {
  chrome.storage.local.set({ collectionEnabled: toggleEl.checked });
});

async function refresh() {
  const { sentCount = 0, missCount = 0, lastEventAt } =
    await chrome.storage.local.get(["sentCount", "missCount", "lastEventAt"]);

  sentEl.textContent = sentCount;
  missEl.textContent = missCount;
  lastEl.textContent = formatTime(lastEventAt);

  try {
    const resp = await fetch(AGENT_HEALTH_URL, { signal: AbortSignal.timeout(2000) });
    if (resp.ok) {
      const data = await resp.json();
      dot.className = "dot online";
      statusText.textContent = `Agent connected — ${data.stored_events ?? 0} events stored`;
      statusText.style.color = "#4ade80";
    } else {
      throw new Error(`HTTP ${resp.status}`);
    }
  } catch {
    dot.className = "dot offline";
    statusText.textContent = "Agent not reachable (is it running?)";
    statusText.style.color = "#f87171";
  }
}

// Initial load
refresh();

// Refresh button
document.getElementById("refresh-btn").addEventListener("click", refresh);
