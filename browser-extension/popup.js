/**
 * LifeShield Extension Popup Script
 *
 * Reads counters from chrome.storage.local (written by background.js)
 * and checks the agent /health endpoint to show live status.
 */

const AGENT_HEALTH = "http://127.0.0.1:8787/health";

const dot        = document.getElementById("status-dot");
const statusText = document.getElementById("status-text");
const sentEl     = document.getElementById("sent-count");
const missEl     = document.getElementById("miss-count");
const lastEl     = document.getElementById("last-event-time");

function formatTime(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  return d.toLocaleTimeString();
}

async function refresh() {
  // 1. Read counters from storage
  const { sentCount = 0, missCount = 0, lastEventAt } =
    await chrome.storage.local.get(["sentCount", "missCount", "lastEventAt"]);

  sentEl.textContent = sentCount;
  missEl.textContent = missCount;
  lastEl.textContent = formatTime(lastEventAt);

  // 2. Probe agent health
  try {
    const resp = await fetch(AGENT_HEALTH, { signal: AbortSignal.timeout(2000) });
    if (resp.ok) {
      const data = await resp.json();
      dot.className = "dot online";
      statusText.textContent = `Agent online — ${data.stored_events ?? "?"} events stored`;
    } else {
      throw new Error(`HTTP ${resp.status}`);
    }
  } catch {
    dot.className = "dot offline";
    statusText.textContent = "Agent offline (is it running?)";
  }
}

// Initial load
refresh();

// Refresh button
document.getElementById("refresh-btn").addEventListener("click", refresh);
