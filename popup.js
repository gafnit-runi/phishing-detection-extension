// Get the current active tab
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const currentTab = tabs[0];
  const statusElement = document.getElementById('status');
  const scanButton = document.getElementById('scanButton');
  
  // Update status with current URL
  statusElement.textContent = `Analyzing: ${currentTab.url}`;
  
  // Request analysis from background script
  chrome.runtime.sendMessage({
    type: 'REQUEST_ANALYSIS',
    data: {
      tabId: currentTab.id,
      url: currentTab.url
    }
  });

  // Add click handler for scan button
  scanButton.addEventListener('click', () => {
    // Disable button while scanning
    scanButton.disabled = true;
    scanButton.textContent = 'Scanning...';
    
    // Clear previous results
    statusElement.textContent = 'Scanning...';
    
    // Request new analysis
    chrome.runtime.sendMessage({
      type: 'REQUEST_ANALYSIS',
      data: {
        tabId: currentTab.id,
        url: currentTab.url,
        forceNewScan: true  // Add flag to force new scan
      }
    });
  });
});

// Function to determine phishing decision based on risk score
function getPhishingDecision(riskScore) {
  if (riskScore >= 7) {
    return {
      status: 'dangerous',
      message: 'High Risk - Likely Phishing',
      icon: '&#10060;'  // ❌
    };
  } else if (riskScore >= 4) {
    return {
      status: 'suspicious',
      message: 'Medium Risk - Exercise Caution',
      icon: '&#9888;'   // ⚠
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
  const statusElement = document.getElementById('status');
  const scanButton = document.getElementById('scanButton');
  
  if (request.type === 'ANALYSIS_RESULT') {
    // Re-enable scan button
    scanButton.disabled = false;
    scanButton.textContent = 'Scan Now';
    
    // Update status with analysis results
    const timestamp = formatTimestamp(request.data.timestamp);
    
    // Get phishing decision
    const decision = getPhishingDecision(request.data.riskScore);
      
    statusElement.innerHTML = `
      <h3>Analysis Results</h3>
      <div class="decision ${decision.status}">
        <span class="decision-icon">${decision.icon}</span>
        ${decision.message}
      </div>
      <div class="url-container">
        <strong>URL:</strong><br>
        ${request.data.url}
      </div>
      <p><strong>Domain:</strong> <span class="domain">${request.data.domain}</span></p>
      <p><strong>Risk Score:</strong> <span class="risk-score">${request.data.riskScore}/10</span></p>
      <p class="timestamp">Last Checked: ${timestamp}</p>
    `;
  } else if (request.type === 'SUSPICIOUS_REDIRECT') {
    // Re-enable scan button
    scanButton.disabled = false;
    scanButton.textContent = 'Scan Now';
    
    // Show warning for suspicious redirects
    statusElement.innerHTML = `
      <h3 class="warning">Suspicious Redirect Detected</h3>
      <div class="decision dangerous">
        <span class="decision-icon">&#10060;</span>
        High Risk - Suspicious Redirect
      </div>
      <div class="url-container">
        <strong>From:</strong><br>
        ${request.data.from}
      </div>
      <div class="url-container">
        <strong>To:</strong><br>
        ${request.data.to}
      </div>
      <p class="warning">This redirect pattern may be suspicious. Please proceed with caution.</p>
    `;
  }
}); 