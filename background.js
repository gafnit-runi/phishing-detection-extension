// Background script for the extension
import { extractFullFeatures } from './feature_extraction.js';

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

// Load the model
let model = null;
async function loadModel() {
  try {
    const response = await fetch(chrome.runtime.getURL('phishing_detector.json'));
    model = await response.json();  
    console.log('Model loaded successfully');
    console.log(model);
    return model;
  } catch (error) {
    console.error('Error loading model:', error);
  }
}

function runTree(tree, features) {
  if (tree.leaf) return tree.value;

  return features[tree.feature] <= tree.threshold
    ? runTree(tree.left, features)
    : runTree(tree.right, features);
}

function runModel(model, features) {
  const votes = new Array(model.n_classes).fill(0);
  for (const tree of model.trees) {
    const output = runTree(tree, features);
    const predicted_class = output.indexOf(Math.max(...output));
    votes[predicted_class]++;
  }
  return votes.indexOf(Math.max(...votes));
}


// Call loadModel when the extension starts
loadModel();

// Model-based detection
function detectPhishing(domain) {
  console.log(model);
  if (!model) {
    console.error('Model not loaded');
    return "error";
  }

  const features = extractFullFeatures(domain);
  const prediction = runModel(model, features); // Returns 0 or 1
  return prediction === 1 ? "phishing" : "benign";
}

// Handle messages from content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "check_url") {
    const prediction = detectPhishing(request.domain);
    sendResponse({ prediction });
  }
  return true;
});

// Track scanning status
const scanningTabs = new Set();

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
      scanningTabs.delete(sender.tab.id);  // Mark scan as complete
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
        console.log('Found stored result:', storedResult);
        // Send stored results to popup
        console.log('Send stored results to popup')
        chrome.runtime.sendMessage({
          type: 'ANALYSIS_RESULT',
          data: storedResult
        });

      } else {

        // If no stored results or force new scan, request new analysis
        console.log('Request new analysis')
        sendMessageToTab(request.data.tabId, {
          type: 'REQUEST_ANALYSIS'
        });
      }
  }
}); 
