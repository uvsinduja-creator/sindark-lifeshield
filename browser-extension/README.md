# LifeShield Browser Extension

Chrome / Edge **Manifest V3** browser extension that acts as the browser
collector for the LifeShield endpoint security agent.

## What it collects

| Event | Trigger |
|---|---|
| `URL_VISIT` | Every top-level page navigation (committed) |
| `URL_REDIRECT` | Every server-side redirect (301/302/307/308) |
| `BROWSER_DOWNLOAD` | Every file download that starts |

All events are sent as `POST /events` to the local LifeShield agent at
`http://127.0.0.1:8787`.  If the agent is offline the event is silently
dropped and a miss-counter is incremented (visible in the popup).

## Installing (Developer Mode)

1. Make sure the LifeShield agent is running:
   ```bash
   python agent/main.py
   ```
2. Open Chrome/Edge and go to `chrome://extensions/` or `edge://extensions/`
3. Enable **Developer mode** (top-right toggle)
4. Click **Load unpacked**
5. Select the `browser-extension/` folder from this repo
6. Click the LifeShield 🛡️ icon in the toolbar to open the popup

## Files

```
browser-extension/
├── manifest.json      # Manifest V3 config
├── background.js      # Service worker — event capture & forwarding
├── popup.html         # Extension popup UI
├── popup.js           # Popup logic (reads counters, pings /health)
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

## Permissions Used

| Permission | Why |
|---|---|
| `tabs` | Access tab IDs for event correlation |
| `webNavigation` | Capture URL visits and redirects |
| `downloads` | Capture file download events |
| `storage` | Persist sent/miss counters for the popup |
| `host_permissions: http://127.0.0.1:8787/*` | POST events to the local agent |
