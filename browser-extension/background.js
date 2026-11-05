/**
 * LifeShield Browser Extension — Background Service Worker
 *
 * Captures browser events and forwards them to the local LifeShield agent
 * running on http://127.0.0.1:8787.
 *
 * Events captured:
 *   - URL_VISIT          (navigation completed on main frame)
 *   - URL_REDIRECT       (server-side redirects during navigation)
 *   - BROWSER_DOWNLOAD   (file downloads initiated)
 *
 * Respects user opt-out toggle (collectionEnabled in chrome.storage.local).
 */

const AGENT_URL = "http://127.0.0.1:8787/events";

// Simple in-memory + storage-backed toggle so the user can pause
// collection without uninstalling the extension (privacy requirement).
let collectionEnabled = true;

chrome.storage.local.get(["collectionEnabled"], (result) => {
  // Default to enabled on first install if no preference saved yet
  collectionEnabled = result.collectionEnabled !== false;
});

chrome.storage.onChanged.addListener((changes) => {
  if (changes.collectionEnabled) {
    collectionEnabled = changes.collectionEnabled.newValue;
  }
});

/**
 * Builds a LifeShieldEvent-shaped payload and POSTs it to the agent.
 */
async function sendEvent(eventType, data) {
  if (!collectionEnabled) {
    return;
  }

  const payload = {
    event_type: eventType,
    source: "browser_extension",
    device: "browser_extension_device",
    data: data,
    metadata: {
      user_agent: navigator.userAgent,
    },
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
      const { sentCount = 0 } = await chrome.storage.local.get("sentCount");
      await chrome.storage.local.set({ sentCount: sentCount + 1, lastEventAt: Date.now() });
    }
  } catch (err) {
    // Agent is probably not running — fail silently, log only
    console.warn("[LifeShield] Could not reach agent:", err.message);
    const { missCount = 0 } = await chrome.storage.local.get("missCount");
    await chrome.storage.local.set({ missCount: missCount + 1 });
  }
}

/** Returns true for internal and extension pages we should ignore. */
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
chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId !== 0) return; // ignore iframes
  if (!collectionEnabled) return;    // respect user's opt-out
  if (isIgnoredUrl(details.url)) return;
  if (!details.url.startsWith("http")) return;

  await sendEvent("URL_VISIT", {
    url: details.url,
    tab_id: details.tabId,
  });
});

// --- URL_REDIRECT -------------------------------------------------------
chrome.webNavigation.onBeforeRedirect.addListener(async (details) => {
  if (details.frameId !== 0) return;
  if (!collectionEnabled) return;
  if (isIgnoredUrl(details.url) && isIgnoredUrl(details.redirectUrl)) return;

  await sendEvent("URL_REDIRECT", {
    from_url: details.url,
    to_url: details.redirectUrl,
    tab_id: details.tabId,
  });
});

// --- BROWSER_DOWNLOAD ---------------------------------------------------
chrome.downloads.onCreated.addListener(async (downloadItem) => {
  if (!collectionEnabled) return;

  await sendEvent("BROWSER_DOWNLOAD", {
    url: downloadItem.url,
    final_url: downloadItem.finalUrl,
    filename: downloadItem.filename,
    mime: downloadItem.mime,
    file_size: downloadItem.fileSize,
    danger: downloadItem.danger,
    download_id: downloadItem.id,
  });
});

console.log("[LifeShield] Background service worker started.");
