// Background script for the extension
chrome.runtime.onInstalled.addListener(() => {
  console.log('Phishing Detection Extension installed');
});

// Store analysis results
const analysisResults = new Map();

// Track navigation events
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  // console.log('Navigation starting:', details.url);
  // Clear stored results for this tab when navigation starts
  analysisResults.delete(details.tabId);
});

// Function to safely send message to a tab
async function sendMessageToTab(tabId, message) {
  try {
    // Check if tab exists

    const tab = await chrome.tabs.get(tabId);
    if (!tab) {
      console.error('Tab not found:', tabId);
      return;
    }

    // Send message to content script
    await chrome.tabs.sendMessage(tabId, message);
    console.log('Message sent successfully');
  } catch (error) {
    console.error('Error sending message to tab:', error);
  }
}

// listener for model purpose
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "check_url") {
    console.log("check_url");
    fetch("http://localhost:5000/check_url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: request.domain })
    })
      .then(res => res.json())
      .then(data => sendResponse({ prediction: data.prediction }))
      .catch(err => sendResponse({ prediction: "error", error: err.message }));
    return true; // keep the message channel open for sendResponse
  }
});

// Listen for messages from content script and popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'SCAN_RESULT') {
    console.log('Received scan result:', request.data);
   
    // Store the result with timestamp
    if (sender.tab) {
      const resultWithTimestamp = {
        ...request.data,
        timestamp: new Date().toISOString()
      };

      analysisResults.set(sender.tab.id, resultWithTimestamp);
      console.log("Stored result for tab", sender.tab.id);
      console.log("Current keys in analysisResults:", Array.from(analysisResults.keys()));
      chrome.runtime.sendMessage({
        type: 'ANALYSIS_RESULT',
        data: analysisResults.get(sender.tab.id)
      });
    } else {
      console.warn(" sender.tab is undefined. Message may be from popup or service worker.");
    }
  } else if (request.type === 'REQUEST_ANALYSIS') {
    // Handle request from popup
      console.log('Received analysis request from popup');
      
      // Check if we have stored results and if force new scan is requested
      const storedResult = analysisResults.get(request.data.tabId);
      const forceNewScan = request.data.forceNewScan;


      if (storedResult && !forceNewScan) {

        // Send stored results to popup
        console.log('Send stored results to popup')
        chrome.runtime.sendMessage({
          type: 'ANALYSIS_RESULT',
          data: storedResult
        });

      } else {

        // If no stored results or force new scan, request new analysis
        sendMessageToTab(request.data.tabId, {
          type: 'REQUEST_ANALYSIS'
        });
      }
  }
}); 
