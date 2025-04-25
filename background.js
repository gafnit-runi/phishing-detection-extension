// Background script for the extension
chrome.runtime.onInstalled.addListener(() => {
  console.log('Phishing Detection Extension installed');
});

// Store analysis results
const analysisResults = new Map();

// Track navigation events
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
console.log('Navigation starting:', details.url);
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
      
      console.log('1');
      // Forward results to popup with timestamp
      chrome.runtime.sendMessage({
        type: 'ANALYSIS_RESULT',
        data: resultWithTimestamp
      });
      console.log('2');
    }
  } else if (request.type === 'REQUEST_ANALYSIS') {
    // Handle request from popup
    console.log('Received analysis request from popup');
    
    // Check if we have stored results and if force new scan is requested
    const storedResult = analysisResults.get(request.data.tabId);
    const forceNewScan = request.data.forceNewScan;
    
    if (storedResult && !forceNewScan) {
      // Send stored results to popup
      chrome.runtime.sendMessage({
        type: 'ANALYSIS_RESULT',
        data: storedResult
      });
    } else {
      console.log('3');
      // If no stored results or force new scan, request new analysis
      sendMessageToTab(request.data.tabId, {
        type: 'REQUEST_ANALYSIS'
      });
      console.log('4');
    }
  }
}); 
