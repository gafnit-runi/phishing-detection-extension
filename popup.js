// Function to display analysis results
function displayResults(data) {
  console.log('Displaying results:', data);
  const scanStatusElement = document.getElementById('status');
  const resultElement = document.getElementById('result');
  const scanButton = document.getElementById('scanButton');

  // Re-enable scan button if it exists
  if (scanButton) {
    scanButton.disabled = false;
    scanButton.textContent = 'Scan Now';
  }

  const decision = getPhishingDecision(data.isPhishing);
  scanStatusElement.innerHTML = '<div class="scan-status">Last scan results</div>';
  
  resultElement.innerHTML = `
    <h3>Analysis Results</h3>
    <div class="decision ${decision.status}">
      <span class="decision-icon">${decision.icon}</span>
      ${decision.message}
    </div>
    <div class="url-container">
      <strong>URL:</strong><br>
      ${data.url}
    </div>
    <p><strong>Domain:</strong> <span class="domain">${data.domain}</span></p>
    <p class="timestamp">Last Checked: ${formatTimestamp(data.timestamp)}</p>
  `;
}

// Function to show scanning status
function showScanningStatus() {
  const scanStatusElement = document.getElementById('status');
  const resultElement = document.getElementById('result');
  const scanButton = document.getElementById('scanButton');

  scanButton.disabled = true;
  scanButton.textContent = 'Scanning...';
  scanStatusElement.innerHTML = '<div class="scan-status">Scanning in progress...</div>';
  resultElement.innerHTML = '';
}

// Function to request analysis
function requestAnalysis(tabId, url, forceNewScan = false) {
  console.log('Requesting analysis for:', { tabId, url, forceNewScan });
  return new Promise((resolve, reject) => {
    try {
      chrome.runtime.sendMessage({
        type: 'ANALYSIS_REQUEST',
        from: 'popup',
        data: {
          tabId: tabId,
          url: url,
          forceNewScan: forceNewScan
        }
      }, (response) => {
        // Check for runtime error
        if (chrome.runtime.lastError) {
          console.error('Error sending message:', chrome.runtime.lastError);
          reject(chrome.runtime.lastError);
          return;
        }
        
        // If we get a response, resolve with it
        if (response) {
          console.log('Got response:', response);
          resolve(response);
        } else {
          // If no response but no error, this is normal - the background script will send results later
          console.log('No immediate response, waiting for results...');
          resolve();
        }
      });
    } catch (error) {
      console.error('Error in requestAnalysis:', error);
      reject(error);
    }
  });
}

// Get the current active tab
chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
  const currentTab = tabs[0];
  const scanButton = document.getElementById('scanButton');
  console.log('Current tab:', currentTab);

  // Check if we have existing results for this URL first
  try {
    if (chrome.storage && chrome.storage.local) {
      const result = await new Promise((resolve) => {
        chrome.storage.local.get([`analysis_${currentTab.id}`], resolve);
      });
      
      const lastAnalysis = result[`analysis_${currentTab.id}`];
      console.log('Last analysis:', lastAnalysis);
      
      if (lastAnalysis && lastAnalysis.url === currentTab.url) {
        console.log('Found existing results');
        // We have existing results, show them immediately
        displayResults(lastAnalysis);
      } else {
        console.log('No existing results, showing scanning status and starting new scan');
        // No existing results, show scanning status and start new scan
        showScanningStatus();
        // Start new scan and handle any errors
        await startNewScan(currentTab.id, currentTab.url);
      }
    } else {
      console.warn('Chrome storage API not available');
      // If storage is not available, start new scan
      showScanningStatus();
      await startNewScan(currentTab.id, currentTab.url);
    }
  } catch (error) {
    console.error('Error accessing storage:', error);
    // If there's an error with storage, start new scan
    showScanningStatus();
    await startNewScan(currentTab.id, currentTab.url);
  }

  // Add click handler for scan button
  scanButton.addEventListener('click', async () => {
    console.log('Scan button clicked');
    showScanningStatus();
    await startNewScan(currentTab.id, currentTab.url, true);
  });
});

// Function to start a new scan
async function startNewScan(tabId, url, forceNewScan = false) {
  try {
    await requestAnalysis(tabId, url, forceNewScan);
    console.log('Analysis request sent successfully');
  } catch (error) {
    console.error('Error during analysis:', error);
    // Don't show error in UI, just re-enable the button
    const scanButton = document.getElementById('scanButton');
    scanButton.disabled = false;
    scanButton.textContent = 'Scan Now';
  }
}

// Function to determine phishing decision based on boolean result
function getPhishingDecision(isPhishing) {
  console.log('getPhishingDecision:', isPhishing);
  if (isPhishing) {
    return {
      status: 'dangerous',
      message: 'High Risk - Likely Phishing',
      icon: '&#10060;'  // ❌
    };
  } else {
    return {
      status: 'safe',
      message: 'Low Risk - Appears Safe',
      icon: '&#10004;'  // ✔
    };
  }
}

// Function to format timestamp
function formatTimestamp(timestamp) {
  console.log('Formatting timestamp:', timestamp);
  if (!timestamp) {
    console.log('No timestamp provided, returning "Just now"');
    return 'Just now';
  }
  
  const date = new Date(timestamp);
  const now = new Date();
  const diffInMinutes = Math.floor((now - date) / (1000 * 60));
  
  if (diffInMinutes < 1) return 'Just now';
  if (diffInMinutes < 60) return `${diffInMinutes} minutes ago`;
  
  return date.toLocaleString();
}

// Listen for analysis results
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('Received message:', request);
  if (request.from === 'background' && request.type === 'ANALYSIS_RESULT') {
    displayResults(request.data);
    // Send response to keep the message port open
    sendResponse({ received: true });
  }
  // Return true to indicate we will send a response asynchronously
  return true;
}); 