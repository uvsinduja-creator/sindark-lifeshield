/**
 * LifeShield Browser Extension — Background Service Worker
 *
 * Captures browser events and forwards them to the local LifeShield agent
 * running on http://127.0.0.1:8787.
 *
 * Events captured:
 *   - URL_VISIT          (every committed top-level navigation)
 *   - URL_REDIRECT       (server-side redirects during navigation)
 *   - BROWSER_DOWNLOAD   (every file download that starts)
 */

const AGENT_URL = "http://127.0.0.1:8787/events";

// --- Helpers -----------------------------------------------------------

/**
 * Sends a LifeShieldEvent-shaped payload to the local agent.
 * Silently drops the event if the agent is unreachable (extension
 * must never crash the browser).
 */
async function sendEvent(eventType, data) {
  const payload = {
    event_type: eventType,
    source: "browser_extension",
    data: data,
  };

  try {
    const resp = await fetch(AGENT_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!resp.ok) {
      console.warn(`[LifeShield] Agent returned ${resp.status} for ${eventType}`);
    } else {
      console.debug(`[LifeShield] Sent ${eventType}`, data);
      // Increment sent-event counter stored in extension local storage
      const { sentCount = 0 } = await chrome.storage.local.get("sentCount");
      await chrome.storage.local.set({ sentCount: sentCount + 1, lastEventAt: Date.now() });
    }
  } catch (err) {
    // Agent not running — record miss so popup can show "Agent offline"
    console.warn("[LifeShield] Agent unreachable:", err.message);
    const { missCount = 0 } = await chrome.storage.local.get("missCount");
    await chrome.storage.local.set({ missCount: missCount + 1 });
  }
}

/** Returns true for chrome-internal and extension pages we should ignore. */
function isIgnoredUrl(url) {
  if (!url) return true;
  return (
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("edge://") ||
    url.startsWith("about:") ||
    url.startsWith("data:")
  );
}

// --- URL_VISIT ---------------------------------------------------------
// Fires after the user's browser has committed to a new page (after all
// server redirects have resolved), so the final URL is what we capture.

chrome.webNavigation.onCommitted.addListener(
  async (details) => {
    // Only track top-level page loads (frameId 0), not iframes
    if (details.frameId !== 0) return;
    if (isIgnoredUrl(details.url)) return;

    await sendEvent("URL_VISIT", {
      url: details.url,
      tab_id: details.tabId,
      transition_type: details.transitionType,
      transition_qualifiers: details.transitionQualifiers,
    });
  }
);

// --- URL_REDIRECT -------------------------------------------------------
// Fires for every server-side redirect step (301/302/307/308).
// Gives us the FULL redirect chain, not just the final URL.

chrome.webNavigation.onBeforeRedirect.addListener(
  async (details) => {
    if (details.frameId !== 0) return;
    if (isIgnoredUrl(details.url) && isIgnoredUrl(details.redirectUrl)) return;

    await sendEvent("URL_REDIRECT", {
      from_url: details.url,
      to_url: details.redirectUrl,
      tab_id: details.tabId,
    });
  }
);

// --- BROWSER_DOWNLOAD ---------------------------------------------------
// Fires when Chrome/Edge starts a file download.

chrome.downloads.onCreated.addListener(async (downloadItem) => {
  await sendEvent("BROWSER_DOWNLOAD", {
    url: downloadItem.url,
    final_url: downloadItem.finalUrl,
    filename: downloadItem.filename,         // full local path once known
    mime: downloadItem.mime,
    file_size: downloadItem.fileSize,
    danger: downloadItem.danger,             // "safe" | "file" | "url" | "content" | "host" | ...
    download_id: downloadItem.id,
  });
});

// --- Startup log -------------------------------------------------------
console.log("[LifeShield] Background service worker started.");
