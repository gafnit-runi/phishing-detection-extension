// Content script that runs on every page
console.log('Phishing Detection Extension: Content script loaded');

// === Entropy Calculator ===
/**
 * Calculates Shannon entropy - measures the randomness or complexity of a string.
 * - \sum p_i \cdot \log_2(p_i)

 * @param {string} str - The input string (e.g., a URL)
 * @returns {number} entropy - The entropy score (higher means more random)
 */
function calculateEntropy(str) {
  console.log('calculateEntropy');
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

/**
 * Detects suspicious dynamic behavior on the page,
 * 1. redirects after the initial load.
 * 2.Dynamically added <script> or <iframe> elements (common in phishing attacks)
 */

function detectByDynamicBehavior() {
  return new Promise((resolve) => {
    let score = 0;
    const reasons = [];

    // Detect redirect using Navigation Timing API
    const navEntry = performance.getEntriesByType("navigation")[0];
    const currentUrl = window.location.href;
    if (navEntry && navEntry.type === "reload" && navEntry.redirectCount > 0) {
    if (navEntry?.name) {
      try {
        const originalUrl = new URL(navEntry.name);
        const currentParsed = new URL(currentUrl);
        const samePath = originalUrl.origin + originalUrl.pathname === currentParsed.origin + currentParsed.pathname;
        const sameQuery = originalUrl.search === currentParsed.search;
        if (!samePath || !sameQuery) {
          score += 1;
      score += 1;
          reasons.push(`Redirect detected: ${originalUrl.href} → ${currentParsed.href}`);
        }
      } catch (err) {
        reasons.push("Redirect detection failed (malformed URL).");
      reasons.push("Suspicious redirect detected after page load.");
      }
    }

    // Monitor for dynamic script or iframe injections
    const observer = new MutationObserver(mutations => {
      mutations.forEach(mutation => {
        mutation.addedNodes.forEach(node => {
          if (node.tagName === "SCRIPT" || node.tagName === "IFRAME") {
            score += 1;
            reasons.push(`Dynamically injected <${node.tagName.toLowerCase()}> detected.`);
          }
        });
      });
    });

    // Delay observation start to avoid false positives
    setTimeout(() => {
      const body = document.body;
      if (body) {
        observer.observe(body, {
          childList: true,
          subtree: true
        });

        // Stop observing after 5s and resolve the result
        setTimeout(() => {
          observer.disconnect();
          console.log("Dynamic Behavior Check Done", { score, reasons });
          resolve({
            score: score >= 1 ? 1 : 0,
            reasons
          });
        }, 5000);
      } else {
        resolve({ score: 0, reasons: ["Document body not available"] });
      }
    }, 2000); 
  });
}


// Static URL Analysis
/*
checks the website’s URL and domain
  1.  Fake or spoofed brand names in the domain (e.g., paypa1.com)
	2.	High entropy 
	3.	Suspicious keywords
	4.	Unusual characteristics (long URLs) or numeric IP addresses
	5.	Obfuscated brand names (g00gle)
*/
function detectByStaticURL(url, domain) {
  const urlLower = url.toLowerCase();

  const reasons = [];
  let score = 0;

  const fakeBrands = ['paypal', 'google', 'apple', 'bank'];


  fakeBrands.forEach(brand => {
    if (domain.includes(brand) && !domain.endsWith(`${brand}.com`)) {
      score += 1;
      reasons.push(`Suspicious use of brand name: "${brand}" in ${domain}`);
    }
  });

  // Entropy-based scoring
  const entropy = calculateEntropy(url);
  if (entropy > 4.5) {
    score += 1;
    reasons.push(`High entropy: ${entropy.toFixed(2)}`);
  } else if (entropy > 4.0) {
    score += 0.5;
    reasons.push(`Moderate entropy: ${entropy.toFixed(2)}`);
  }

  // Suspicious keyword matches
  const suspiciousKeywords = ['login', 'verify', 'account', 'signin', 'update', 'confirm'];
  suspiciousKeywords.forEach(word => {
    if (urlLower.includes(word)) {
      score += 0.5;
      reasons.push(`Suspicious keyword found in URL: "${word}"`);
    }
  });

  // Long URL
  if (url.length > 100) {
    score += 0.5;
    reasons.push("URL is very long (>100 characters)");
  }

  // IP address usage
  if (/^\d{1,3}(\.\d{1,3}){3}/.test(domain)) {
    score += 1;
    reasons.push(`Domain is an IP address: ${domain}`);
  }

  // Obfuscated brand pattern detection
  if (/(paypa1|g00gle|secure-\w+)/.test(domain)) {
    score += 1;
    reasons.push(`Obfuscated brand pattern in domain: ${domain}`);
  }

  // Return binary result (1 if any risk found)
  const isSuspicious = score >= 1;

  console.log("Detect By Static URL", { score, reasons });
  return {
    score: isSuspicious ? 1 : 0,
    reasons
  }
}

/*
structure and elements of the webpage’s HTML
	1.	Link mismatches (link says “paypal.com” but leads elsewhere)
	2.	Suspicious links (links to IP addresses or with encoded characters)
	3.	Insecure forms 
	4.	Sensitive input fields
	5.	The page isn’t using a secure protocol- Missing HTTPS
*/
function detectByStaticContent() {
  let score = 0;
  const reasons = [];

  // Link mismatch detection (LinkGuard-style)
  document.querySelectorAll('a').forEach(link => {
    const text = link.textContent || "";
    const href = link.href || "";

    if (text.includes('.') && !href.includes(text)) {
      score += 1;
      reasons.push(`Mismatched anchor text vs href: "${text}" → "${href}"`);
    }

    if (/^\d{1,3}(\.\d{1,3}){3}/.test(href)) {
      score += 1;
      reasons.push(`Link to raw IP address: ${href}`);
    }

    if (/%[0-9a-f]{2}/i.test(href) || href.length > 100) {
      score += 1;
      reasons.push(`Encoded or overly long link: ${href}`);
    }
  });

  // Insecure form detection
  document.querySelectorAll("form").forEach(form => {
    const action = form.getAttribute("action") || "";
    if (action.startsWith("http://")) {
      score += 1;
      reasons.push(`Form submits to insecure (HTTP) action: ${action}`);
    }
  });

  // Sensitive input field detection
  const sensitiveInputs = document.querySelectorAll("input[type='password'], input[name*='card'], input[name*='ssn']");
  if (sensitiveInputs.length >= 2) {
    score += 1;
    reasons.push("Multiple sensitive input fields detected (password, card, SSN)");
  }

  // Add SSL/HTTPS Check
  if (window.location.protocol !== 'https:') {
    score += 0.5;
    reasons.push("Page is not using HTTPS.");
  }
  console.log("Detec By Static Content", { score, reasons });
  return {
    score: score >= 1 ? 1 : 0,
    reasons
  };
}



////////// Main function to calcualte final score for potential phishing //////////

function checkForPhishing() {
  console.log('checkForPhishing');
  const url = window.location.href;
  const domain = window.location.hostname;
  
  const { score: urlScore, reasons: urlReasons } = detectByStaticURL(url, domain);
  const { score: contentScore, reasons: contentReasons } = detectByStaticContent();
  const { score: dynamicScore, reasons: dynamicReasons } = detectByDynamicBehavior();
  console.log('urlScore:',urlScore)
  console.log('contentScore:',contentScore)
  console.log('dynamicScore:',dynamicScore)
  const riskScore = urlScore + contentScore + dynamicScore;

  // Combine all reasons
  const allReasons = [...urlReasons, ...contentReasons, ...dynamicReasons];
  // Expose to window (for Selenium or testing)
  window.riskScore = riskScore;
  window.riskReasons = allReasons;
  console.log("✅ riskScore exposed to window:", window.riskScore);
  console.log('riskScore:',riskScore)
  // Send results to background script
  chrome.runtime.sendMessage({
    type: 'SCAN_RESULT',
    data: {
      url,
      domain,
      riskScore,
      reasons: allReasons
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