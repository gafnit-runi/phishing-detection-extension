// Content script that runs on every page
console.log('Phishing Detection Extension: Content script loaded');
// Global scan status flag
let isScanning = false;

const SUSPICIOUS_HOSTING = new Set([
  'godaddysites.com', 'weebly.com', 'webflow.io', 'wixsite.com', 'squarespace.com', 'notion.site', 'github.io',
  'netlify.app', 'vercel.app', 'glitch.me', '000webhostapp.com'
]);


// === Entropy Calculator ===
/**
 * Calculates Shannon entropy - measures the randomness or complexity of a string.
 * - \sum p_i \cdot \log_2(p_i)

 * @param {string} str - The input string (e.g., a URL)
 * @returns {number} entropy - The entropy score (higher means more random)
 */
function calculateEntropy(str) {
  const frequency = {};
  for (let char of str) {
    frequency[char] = (frequency[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (let char in frequency) {
    const p = frequency[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}


// Static URL Analysis
/*
Enhanced Static URL Analysis with model + heuristic fusion
(model, digits, symbols, hyphens, containsAt, isIP, usesHTTP, entropy, keywords)
*/
function isSuspiciousHost(domain) {
  return Array.from(SUSPICIOUS_HOSTING).some(host => domain.endsWith(host));
}

function detectByStaticURL(url, domain, modelScore = null, modelConfidence = null) {
  const reasons = [];
  let score = 0;
  console.log('domain:',domain)
  // === Feature extractors ===
  const digitCount = (url.match(/\d/g) || []).length;
  const symbolCount = (url.match(/[^a-zA-Z0-9]/g) || []).length;
  const hyphenCount = (url.match(/-/g) || []).length;
  const containsAt = url.includes("@");
  const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(domain);
  const usesHTTP = window.location.protocol === 'http:';
  const entropy = calculateEntropy(url);

  if (digitCount > 5) {
    score += 0.1;
    reasons.push('High number of digits in URL');
  }
  if (symbolCount > 10) {
    score += 0.1;
    reasons.push('High number of symbols in URL');
  }
  if (hyphenCount > 3) {
    score += 0.2;
    reasons.push('Multiple hyphens in URL');
  }
  if (containsAt) {
    score += 0.3;
    reasons.push('Contains @ symbol');
  }
  if (isIP) {
    score += 0.5;
    reasons.push('Domain is an IP address');
  }
  if (usesHTTP) {
    score += 0.2;
    reasons.push('Page uses HTTP instead of HTTPS');
  }
  if (entropy > 4.2) {
    score += 0.5;
    reasons.push('High entropy');
  }
  if (isSuspiciousHost(domain)) {
    score += 0.5;
    reasons.push('Hosted on suspicious or free hosting platform');
  }

  // Suspicious sequence patterns ===
  if (/[0-9]{5,}/.test(url)) {
    score += 0.3;
    reasons.push('Suspicious numeric sequence in URL');
  }
  if (/[^a-zA-Z0-9]{3,}/.test(url)) {
    score += 0.3;
    reasons.push('Suspicious symbol sequence in URL');
  }
  if (/(.)\1{2,}/.test(url)) {
    score += 0.3;
    reasons.push('Repeated characters in URL');
  }

  let finalScore = score;

  console.log("Detec By Static URL", { finalScore, score, modelScore, modelConfidence, reasons });
  return {
    score: finalScore,
    reasons
  };
}


// Add this function before detectByStaticContent
function isValidDomain(domain) {
  // Domain pattern: alphanumeric, hyphens, and dots
  // Must start and end with alphanumeric
  // Each part between dots must be 1-63 chars
  const domainPattern = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$/;
  return domainPattern.test(domain);
}

function extractDomainFromText(text) {
  // Remove common prefixes and protocols
  text = text.replace(/^(https?:\/\/)?(www\.)?/i, '');
  
  // Split by common separators and take the first part
  const parts = text.split(/[\s\/\?&#]/);
  const potentialDomain = parts[0];
  
  // Check if it's a valid domain format
  if (isValidDomain(potentialDomain)) {
    return potentialDomain;
  }
  
  return null;
}


// Legitimate page statistics
const LEGIT_STATS = {
  content_length: { mean: 156792.56, std: 258595.3, "25th_percentile": 25515.0, "75th_percentile": 165814.0 },
  num_elements: { mean: 229.17, std: 367.63, "25th_percentile": 53.0, "75th_percentile": 272.5 },
  num_links: { mean: 23.24, std: 51.77, "25th_percentile": 0.0, "75th_percentile": 14.5 },
  num_images: { mean: 5.4, std: 20.71, "25th_percentile": 0.0, "75th_percentile": 2.0 },
  num_scripts: { mean: 21.67, std: 31.13, "25th_percentile": 6.0, "75th_percentile": 25.5 },
  num_styles: { mean: 16.3, std: 18.31, "25th_percentile": 4.0, "75th_percentile": 19.5 },
  num_iframes: { mean: 0.22, std: 0.52, "25th_percentile": 0.0, "75th_percentile": 0.0 }
};

const WEIGHTS = {
  content_length: 1,
  num_elements: 1,
  num_links: 2,
  num_images: 2,
  num_scripts: 2,
  num_styles: 2,
  num_iframes: 3
};

function deviationLevel(value, stat) {
  if (value >= stat["25th_percentile"] && value <= stat["75th_percentile"]) {
    return 0;
  } else if (Math.abs(value - stat.mean) <= stat.std) {
    return 1;
  } else {
    return 2;
  }
}

/*
 * Analyzes the webpage's content and structure for phishing indicators:
 * 1. Content complexity analysis:
 *    - Measures against legitimate page statistics
 *    - Checks for suspicious patterns in page composition
 *    - Uses weighted scoring based on element counts
 * 
 * 2. Link analysis:
 *    - Detects mismatched anchor text vs href
 *    - Identifies suspicious links (IP addresses, encoded chars)
 *    - Uses LinkGuard-style detection
 * 
 * 3. Form analysis:
 *    - Checks for insecure form submissions
 *    - Detects forms submitting to different domains
 *    - Monitors JavaScript-based form submissions
 * 
 * 4. Input field analysis:
 *    - Identifies sensitive input fields
 *    - Checks for multiple sensitive fields
 * 
 * Returns a score and detailed reasons for any suspicious patterns found.
 */
function detectByStaticContent() {
  let score = 0;
  const reasons = [];


  // Content complexity analysis
  /*
   * Analyzes the page's HTML structure and content to detect potential phishing pages:
   * 1. Measures content length and element counts against legitimate page statistics
   * 2. Checks for suspicious patterns in page composition:
   *    - Too few elements (suspiciously simple pages)
   *    - Too many iframes (common in phishing)
   *    - Missing scripts/styles (unusual for legitimate sites)
   *    - Unusually long or short content
   * 
   * Uses statistical analysis:
   * - Compares against known legitimate page metrics (mean, std dev, percentiles)
   * - Weights different features based on their importance
   * - Calculates deviation from normal patterns
   * 
   * Hard override rules for obvious cases:
   * - 3+ iframes (highly suspicious)
   * - Very short content (<5000 chars)
   * - No scripts or styles (extremely unusual)
   */
  let complexityScore = 0;

  const htmlContent = document.documentElement.outerHTML;
  const contentLength = htmlContent.length;
  const numElements = document.getElementsByTagName('*').length;
  const numLinks = document.getElementsByTagName('a').length;
  const numImages = document.getElementsByTagName('img').length;
  const numScripts = document.getElementsByTagName('script').length;
  const numStyles = document.getElementsByTagName('style').length;
  const numIframes = document.getElementsByTagName('iframe').length;
  
  const pageStats = {
    content_length: contentLength,
    num_elements: numElements,
    num_links: numLinks,
    num_images: numImages,
    num_scripts: numScripts,
    num_styles: numStyles,
    num_iframes: numIframes
  };

  for (const [feature, weight] of Object.entries(WEIGHTS)) {
    const val = pageStats[feature] ?? 0;
    const stat = LEGIT_STATS[feature];
    const dev = deviationLevel(val, stat);
    complexityScore += weight * dev;
  }

  // Hard override rules
  if (pageStats.num_iframes >= 3) complexityScore += 5;
  if (pageStats.content_length < 5000) complexityScore += 3;
  if (pageStats.num_scripts === 0 && pageStats.num_styles === 0) complexityScore += 4;

  if (complexityScore > 20) {
    reasons.push('Complex page detected');
    score += 0.3;
  }

  // Link mismatch detection (LinkGuard-style)
  /*
   * Checks for suspicious link behavior that could indicate phishing:
   * 1. Mismatched anchor text vs href (e.g., text says "paypal.com" but links elsewhere)
   * 2. Links to raw IP addresses instead of domain names
   * 3. Links with suspicious patterns in the URL
   * 
   * The detection:
   * - Extracts domains from anchor text
   * - Compares them with the actual link destinations
   * - Ignores links that contain images or other media
   * - Scores suspicious patterns to contribute to overall phishing risk
   */
  let LinkGuard_score = 0;

  document.querySelectorAll('a').forEach(link => {
    const text = link.textContent || "";
    const href = link.href || "";
    
    // Skip if link contains elements with src attribute (like images)
    if (link.querySelector('[src]')) {
      console.log("link contains src attribute")
      return;
    }
    
    if (text.includes('.')) {
      const domainFromText = extractDomainFromText(text.trim());
      if (domainFromText) {
        try {
          const linkUrl = new URL(href);
          if (!linkUrl.hostname.includes(domainFromText)) {
            // Potential phishing link detected
            LinkGuard_score += 0.1;
            reasons.push('Mismatched anchor text vs href');
          }
        } catch (e) {
          console.error('Error parsing URL:', e);
        }
      }
    }

    if (/^\d{1,3}(\.\d{1,3}){3}/.test(href)) {
      LinkGuard_score += 0.2;
      reasons.push('Link to raw IP address');
    }
  });

  if (LinkGuard_score > 0) {
    reasons.push('LinkGuard score');
    score += LinkGuard_score;
  }

  // Form detection for phishing
  /*
   * Checks for suspicious form behavior that could indicate phishing:
   * 1. Insecure form submissions (HTTP instead of HTTPS)
   * 2. Forms with password fields submitting to different domains
   * 3. Suspicious form actions (non-relative paths)
   * 4. JavaScript-based form submissions using fetch/XHR
   * 5. Inline event handlers that might intercept form data
   * 
   * Each suspicious pattern increases the formScore, which contributes
   * to the overall phishing risk score.
   */
  let formScore = 0;
  const currentDomain = window.location.hostname;

  // Check HTML forms
  document.querySelectorAll("form").forEach(form => {
    const action = form.getAttribute("action") || "";
    const hasPasswordField = form.querySelector('input[type="password"]');
    
    // Check for insecure form submission
    if (action.startsWith("http://")) {
      formScore += 0.1;
      reasons.push('Form submits to insecure (HTTP) action');
    }
    
    if (hasPasswordField) {
      try {
        const actionUrl = new URL(action, window.location.href);
        if (actionUrl.hostname !== currentDomain) {
          formScore += 0.1;
          reasons.push('Login form submits to different domain');
        }
      } catch (e) {
        // If action is not a valid URL, check if it's a relative path
        if (!action.startsWith('/') && !action.startsWith('./')) {
          formScore += 0.1;
          reasons.push('Suspicious form action');
        }
      }
    }
  });

  // Check for JavaScript-based form submissions
  const suspiciousSubmitHandlers = [];
  document.querySelectorAll('form, input[type="submit"], button[type="submit"]').forEach(element => {
    const onclick = element.getAttribute('onclick');
    const onsubmit = element.getAttribute('onsubmit');
    
    if (onclick || onsubmit) {
      const handler = onclick || onsubmit;
      if (handler.includes('fetch') || handler.includes('XMLHttpRequest') || handler.includes('ajax')) {
        suspiciousSubmitHandlers.push(handler);
      }
    }
  });

  if (suspiciousSubmitHandlers.length > 0) {
    formScore += 0.1;
    reasons.push('Found suspicious form submission handlers');
  }

  // Check for fetch/XHR event listeners
  const originalFetch = window.fetch;
  const originalXHR = window.XMLHttpRequest.prototype.send;
  let suspiciousSubmissions = false;

  window.fetch = function(...args) {
    const url = args[0];
    if (typeof url === 'string' && url.includes('password')) {
      try {
        const submissionUrl = new URL(url, window.location.href);
        if (submissionUrl.hostname !== currentDomain) {
          suspiciousSubmissions = true;
          reasons.push('Suspicious fetch submission to');
        }
      } catch (e) {
        suspiciousSubmissions = true;
        reasons.push('Suspicious fetch submission to invalid URL');
      }
    }
    return originalFetch.apply(this, args);
  };

  window.XMLHttpRequest.prototype.send = function(data) {
    if (data && typeof data === 'string' && data.includes('password')) {
      const url = this.responseURL || this._url;
      if (url) {
        try {
          const submissionUrl = new URL(url, window.location.href);
          if (submissionUrl.hostname !== currentDomain) {
            suspiciousSubmissions = true;
            reasons.push('Suspicious XHR submission to');
          }
        } catch (e) {
          suspiciousSubmissions = true;
          reasons.push('Suspicious XHR submission to invalid URL');
        }
      }
    }
    return originalXHR.apply(this, arguments);
  };

  if (suspiciousSubmissions) {
    formScore += 0.1;
  }

  if (formScore > 0) {
    score += formScore;
  }

  console.log("Detect By Static Content", { score, reasons });
  return {
    score: score,
    reasons,
    complexityScore
  };
}

////////// Main function to calcualte final score for potential phishing //////////

async function checkForPhishing() {
  // Check if already scanning
  if (isScanning) {
    console.log('Scan already in progress, skipping...');
    return;
  }

  // Set scanning flag
  isScanning = true;
  console.log('Starting phishing scan...');

  try {
    const url = window.location.href;
    const domain = window.location.hostname;

    // Get ML model prediction from background script
    const modelResult = await new Promise((resolve) => {
      chrome.runtime.sendMessage({ action: "check_url", url }, (response) => {
        resolve(response);
      });
    });

    // Run all detection methods in parallel
    const [
      urlAnalysis,
      contentAnalysis, 
      dynamicAnalysis
    ] = await Promise.all([
      detectByStaticURL(url, domain, modelResult.prediction, modelResult.confidence),
      detectByStaticContent(),
      detectByDynamicBehavior()
    ]);

    // Calculate final risk score and combine reasons
    const modelReasons = modelResult.prediction === 1 ? ["ML model predicted phishing domain."] : [];

    const modelScore = modelResult.prediction
    const modelConfidence = modelResult.confidence

    // Check URL for credential-related keywords
    const credentialKeywords = [
      // Login related
      'login', 'log-in', 'log_in', 'signin', 'sign-in', 'sign_in', 'signup', 'sign-up', 'sign_up',
      'register', 'registration', 'signup', 'sign-up', 'sign_up', 'join', 'create-account',
      
      // Account related
      'account', 'profile', 'user', 'member', 'membership', 'my-account', 'myaccount',
      
      // Password related
      'password', 'passwd', 'pwd', 'reset-password', 'resetpassword', 'forgot-password',
      'forgotpassword', 'change-password', 'changepassword', 'recover', 'recovery',
      
      // Authentication related
      'auth', 'authenticate', 'authentication', 'verify', 'verification', 'confirm',
      'confirmation', 'validate', 'validation', 'security', 'secure',
      
      // Payment related
      'payment', 'pay', 'checkout', 'billing', 'invoice', 'order', 'purchase',
      'subscribe', 'subscription', 'upgrade', 'premium',
      
      // Banking related
      'bank', 'banking', 'transfer', 'transaction', 'deposit', 'withdraw',
      'balance', 'statement', 'card', 'credit', 'debit',
      
      // Identity related
      'identity', 'id', 'verify-identity', 'identity-verification', 'kyc',
      'personal-info', 'personal-information'
    ];
    
    // Check for credential input fields
    const hasUsernameField = document.querySelector('input[type="text"][name*="user"], input[type="email"][name*="user"], input[type="text"][name*="login"], input[type="email"][name*="login"]');    const hasUsernameField = document.querySelector('input[type="text"][name*="user"], input[type="email"][name*="user"], input[type="text"][name*="login"], input[type="email"][name*="login"]');
    const hasPasswordField = document.querySelector('input[type="password"]');

    const isCredsPage = hasCredentialKeyword || hasUsernameField || hasPasswordField;
    console.log('isCredsPage:',isCredsPage)
    const isPhishing = (isCredsPage && modelScore == 1 && modelConfidence > 0.6)
                    || (isCredsPage && modelScore == 1 && urlAnalysis.score > 0.1 && contentAnalysis.score > 0.1)
                    || (isCredsPage && modelScore == 1 && urlAnalysis.score > 0.3)
                    || (isCredsPage && modelScore == 1 && contentAnalysis.score > 0.3)
                    || (isCredsPage && modelConfidence < 0.9 && urlAnalysis.score > 0.3 && contentAnalysis.score > 0.3)
                    || (isCredsPage && urlAnalysis.score > 0.4 )
                    | (isCredsPage && contentAnalysis.score > 0.5)
                    || (modelScore == 1 && modelConfidence > 0.6 && urlAnalysis.score > 0.2)
                    || (modelScore == 1 && modelConfidence > 0.6 && contentAnalysis.score > 0.2)
                    || (modelScore == 1 && urlAnalysis.score > 0.3 && contentAnalysis.score > 0.3)
                    || (urlAnalysis.score > 0.4 || contentAnalysis.score > 0.5);

    // Combine all reasons
    const allReasons = [...urlAnalysis.reasons, ...contentAnalysis.reasons, ...modelReasons];
    // Expose to window (for Selenium or testing)
    window.isPhishing = isPhishing;
    window.modelScore = modelResult.prediction;
    window.modelconfidence = modelResult.confidence;
    window.riskReasons = allReasons;
    window.isCredsPage = isCredsPage;
    console.log('riskReasons:',riskReasons)
    // For testing: Save to localStorage

    localStorage.setItem('isPhishing', Number(isPhishing));
    localStorage.setItem('modelScore', modelResult.prediction);
    localStorage.setItem('modelconfidence', modelResult.confidence);
    localStorage.setItem('riskReasons', JSON.stringify(allReasons));
    localStorage.setItem('urlAnalysis_score', urlAnalysis.score);
    localStorage.setItem('contentAnalysis_score', contentAnalysis.score);

    localStorage.setItem('isCredsPage', Number(isCredsPage));
    console.log('localStorage.isPhishing:',Number(localStorage.isPhishing))
    console.log('localStorage.modelScore:',localStorage.modelScore)
    console.log('localStorage.modelconfidence:',localStorage.modelconfidence)
    console.log('localStorage.urlAnalysis_score:',localStorage.urlAnalysis_score)
    console.log('localStorage.contentAnalysis_score:',localStorage.contentAnalysis_score)
    
    console.log('localStorage.riskReasons:',localStorage.riskReasons)
    // for memory usage testing
    if (window.performance && window.performance.memory) {
      console.log("📦 JS Heap Used (bytes):", window.performance.memory.usedJSHeapSize);
    }
    // For testing close ////////////////////////////////

    // Send results to background script
    chrome.runtime.sendMessage({
      type: 'ANALYSIS_RESULT',
      from: 'content',
      data: {
        url,
        domain,
        isPhishing,
        urlScore: urlAnalysis.score,
        contentScore: contentAnalysis.score,
        modelScore: modelScore,
        reasons: allReasons
      }
    });
  } catch (error) {
    console.error('Error during phishing scan:', error);
  } finally {
    // Reset scanning flag
    isScanning = false;
    console.log('Phishing scan completed');
  }

// Listen for messages from background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('Content script received message:', request);
  if (request.from === 'background' && request.type === 'ANALYSIS_REQUEST') {
    console.log('Received analysis request from background');
    if (!isScanning) {
      // Start the scan and wait for it to complete
      checkForPhishing()
        .then(() => {
          console.log('Analysis complete');
          sendResponse({ success: true });
        })
        .catch(error => {
          console.error('Error during analysis:', error);
          sendResponse({ error: error.message });
        });
    } else {
      console.log('Scan already in progress');
      sendResponse({ error: 'Scan already in progress' });
    }
  }
  // Return true to keep the message port open for async response
  return true;
});

// Wait for page to be fully loaded
window.addEventListener('load', () => {
  // Wait for 3 seconds to catch late-loading content
  setTimeout(async () => {
    console.log('Page fully loaded, starting phishing check');
    if (!isScanning) {
      await checkForPhishing();
    } else {
      console.log('Scan already in progress, skipping initial check');
    }
  }, 3000);
});