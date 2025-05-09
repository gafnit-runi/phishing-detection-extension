# Phishing Detection Chrome Extension

A Chrome extension that detects potential phishing websites using multi-layered analysis.

## Features

- Real-time phishing detection
- Risk score calculation
- Visual indicators for risk levels
- Manual scan option
- Cached results for better performance

## Installation for Developers

1. Clone or download this repository to your local machine

2. Open Chrome and navigate to `chrome://extensions/`

3. Enable "Developer mode" in the top right corner

4. Click "Load unpacked" and select the directory containing the extension files

5. The extension should now be installed and visible in your Chrome toolbar

## Development

### Project Structure

```
phishing-detection-extension/
├── manifest.json      # Extension configuration
├── background.js      # Background service worker
├── content_script.js  # Content script for page analysis
├── popup.html        # Extension popup UI
├── popup.js          # Popup functionality
└── icons/            # Extension icons
    └── icon.png
```

### Key Components

- `manifest.json`: Defines extension permissions and components
- `background.js`: Handles message passing and result storage
- `content_script.js`: Performs phishing detection analysis
- `popup.html/js`: User interface for viewing results

### Testing

1. Make changes to the code
2. Go to `chrome://extensions/`
3. Click the refresh icon on your extension
4. Test the changes in a new tab

### Debugging

- Use Chrome DevTools to debug:
  - Right-click extension icon → Inspect popup
  - Go to `chrome://extensions` → Click "background page" under your extension
  - Use `console.log()` in your code for debugging