// Background script for the extension
import { extractFullFeatures } from './feature_extraction.js';

chrome.runtime.onInstalled.addListener(() => {
  console.log('Phishing Detection Extension installed');
});

// Track navigation events
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  // Clear stored results for this tab when navigation starts
  try {
    if (chrome.storage && chrome.storage.local) {
      chrome.storage.local.remove(`analysis_${details.tabId}`, () => {
        console.log('Cleared analysis results for tab:', details.tabId);
      });
    } else {
      console.warn('Chrome storage API not available');
    }
  } catch (error) {
    console.error('Error clearing analysis results:', error);
  }
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

    // Send message to content script and wait for response
    return new Promise((resolve, reject) => {
      chrome.tabs.sendMessage(tabId, message, (response) => {
        if (chrome.runtime.lastError) {
          console.error('Error sending message:', chrome.runtime.lastError);
          reject(chrome.runtime.lastError);
          return;
        }
        resolve(response);
      });
    });
  } catch (error) {
    console.error('Error sending message to tab:', error);
    throw error;
  }
}

// Load model
let model = null;
async function loadModel() {
  try {
    const response = await fetch(chrome.runtime.getURL('random_forest_model_reduced.json'));
    model = await response.json();  
    console.log('Model loaded successfully');
    return model;
  } catch (error) {
    console.error('Error loading model:', error);
  }
}

// Load scaler
let scaler = null;
async function loadScaler() {
  try {
    const response = await fetch(chrome.runtime.getURL('scaler_params.json'));
    scaler = await response.json();
    console.log('Scaler loaded successfully');
  } catch (error) {
    console.error('Error loading scaler:', error);
  }
}

function standardizeFeatures(features, means, scales) {
  const standardized = {};
  Object.keys(features).forEach((key, i) => {
    const val = features[key];
    standardized[key] = (val - means[i]) / scales[i];
  });
  return standardized;
}

function runTree(tree, features) {
  if (tree.leaf) return tree.value;

  return features[tree.feature] <= tree.threshold
    ? runTree(tree.left, features)
    : runTree(tree.right, features);
}

function runModel(model, features) {
  const classTotals = new Array(model.n_classes).fill(0);
  const ordered = model.feature_names.map(f => features[f]);
  for (const tree of model.trees) {
    const output = runTree(tree, ordered); 
    for (let i = 0; i < model.n_classes; i++) {
      classTotals[i] += output[i]; 
    }
  }

  const totalVotes = classTotals.reduce((a, b) => a + b, 0);
  const probabilities = classTotals.map(v => v / totalVotes);

  const predicted_class = classTotals.indexOf(Math.max(...classTotals));
  const confidence = probabilities[predicted_class];

  return { predicted_class, confidence };
}


// Call loadModel when the extension starts
loadModel();

loadScaler();

// Model-based detection
function detectPhishing(url) {
  if (!model || !scaler) {
    console.error('Model or scaler not loaded');
    return "error";
  }

  const rawFeatures = extractFullFeatures(url);
  if (!rawFeatures) {
    return { prediction: "error", confidence: 0 };
  }
  console.log("Extracted features:", rawFeatures);
  const standardized = standardizeFeatures(rawFeatures, scaler.mean, scaler.scale);
  console.log("Standardized features:", standardized);
  const { predicted_class, confidence } = runModel(model, standardized);// Returns 0 or 1
  console.log("Predicted class:", predicted_class," Confidence:", confidence);
  return { prediction: predicted_class, confidence };
}

// Handle messages from content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "check_url") {
    console.log("check_url", request.url);
    const { prediction, confidence } = detectPhishing(request.url);
    sendResponse({ prediction: prediction, confidence: confidence });
    return true;  // Keep the message channel open for async response
  }
});

// Listen for messages from content script and popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.from === 'content' && request.type === 'ANALYSIS_RESULT') {
    console.log('Received scan result:', request.data);
    
    // Store the result with timestamp
    if (sender.tab) {
      const resultWithTimestamp = {
        ...request.data,
        timestamp: new Date().toISOString()
      };

      // Store result using tabId as part of the key
      try {
        if (chrome.storage && chrome.storage.local) {
          chrome.storage.local.set({ [`analysis_${sender.tab.id}`]: resultWithTimestamp }, () => {
            console.log("Stored result for tab", sender.tab.id);
            // Send result to popup
            try {
              chrome.runtime.sendMessage({
                type: 'ANALYSIS_RESULT',
                from: 'background',
                data: resultWithTimestamp
              });
            } catch (error) {
              console.error('Error sending analysis result:', error);
            }
          });
        } else {
          console.warn('Chrome storage API not available');
        }
      } catch (error) {
        console.error('Error storing analysis result:', error);
      }
    } else {
      console.warn("sender.tab is undefined. Message may be from popup or service worker.");
    }
  } else if (request.from === 'popup' && request.type === 'ANALYSIS_REQUEST') {
    // Handle request from popup
    console.log('Received analysis request from popup');
    
    // Check if we have stored results and if force new scan is requested
    try {
      if (chrome.storage && chrome.storage.local) {
        chrome.storage.local.get([`analysis_${request.data.tabId}`], async (result) => {
          const storedResult = result[`analysis_${request.data.tabId}`];
          const forceNewScan = request.data.forceNewScan;

          if (storedResult && !forceNewScan) {
            console.log('Found stored result:', storedResult);
            // Send stored results to popup
            try {
              chrome.runtime.sendMessage({
                type: 'ANALYSIS_RESULT',
                from: 'background',
                data: storedResult
              });
            } catch (error) {
              console.error('Error sending stored result:', error);
            }
          } else {
            // If no stored results or force new scan, request new analysis
            console.log('Request new analysis');
            try {
              await sendMessageToTab(request.data.tabId, {
                type: 'ANALYSIS_REQUEST',
                from: 'background'
              });
              // Send response to keep the message port open
              sendResponse({ received: true });
            } catch (error) {
              console.error('Error requesting new analysis:', error);
              sendResponse({ error: error.message });
            }
          }
        });
      } else {
        console.warn('Chrome storage API not available');
        // If storage is not available, request new analysis
        sendMessageToTab(request.data.tabId, {
          type: 'ANALYSIS_REQUEST',
          from: 'background'
        }).then(() => {
          sendResponse({ received: true });
        }).catch(error => {
          console.error('Error requesting new analysis:', error);
          sendResponse({ error: error.message });
        });
      }
    } catch (error) {
      console.error('Error accessing storage:', error);
      // If there's an error with storage, request new analysis
      sendMessageToTab(request.data.tabId, {
        type: 'ANALYSIS_REQUEST',
        from: 'background'
      }).then(() => {
        sendResponse({ received: true });
      }).catch(error => {
        console.error('Error requesting new analysis:', error);
        sendResponse({ error: error.message });
      });
    }
  }
  // Return true to keep the message port open for async responses
  return true;
}); 
