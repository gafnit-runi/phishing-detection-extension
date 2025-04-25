// Testing entropy branch


// Content script that runs on every page
console.log('Phishing Detection Extension: Content script loaded');

// Basic function to check for potential phishing indicators
function checkForPhishing() {
  const url = window.location.href;
  const domain = window.location.hostname;
  
  // Basic checks (to be expanded)
  const suspiciousPatterns = [
    'login',
    'signin',
    'account',
    'verify',
    'confirm'
  ];
  
  let riskScore = 0;
  
  // Check URL for suspicious patterns
  suspiciousPatterns.forEach(pattern => {
    if (url.toLowerCase().includes(pattern)) {
      riskScore += 1;
    }
  });
  
  // Send results to background script
  chrome.runtime.sendMessage({
    type: 'SCAN_RESULT',
    data: {
      url: url,
      domain: domain,
      riskScore: riskScore
    }
  });
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'REQUEST_ANALYSIS') {
    console.log('Received analysis request from background');
    checkForPhishing();
  }
});

// Wait for page to be fully loaded
window.addEventListener('load', () => {
  // Wait for 3 seconds to catch late-loading content
  setTimeout(() => {
    console.log('Page fully loaded, starting phishing check');
    checkForPhishing();
  }, 3000);
}); 