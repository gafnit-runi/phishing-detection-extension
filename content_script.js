// Content script that runs on every page
console.log('Phishing Detection Extension: Content script loaded');

// === Entropy Calculator ===
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

// // === LinkGuard Heuristic Function ===
// function runLinkGuardHeuristics() {
//   const links = document.querySelectorAll('a');
//   let score = 0;
//   const reasons = [];

//   links.forEach(link => {
//     const text = (link.textContent || "").trim();
//     const href = (link.href || "").trim();

//     if (!href || href.startsWith('javascript')) return;

//     try {
//       const linkDomain = new URL(href).hostname.toLowerCase();

//       // IP Address Detection
//       if (/^\d{1,3}(\.\d{1,3}){3}/.test(linkDomain)) {
//         score += 1;
//         reasons.push(`Link to IP address: ${href}`);
//       }

//       // Mismatch between anchor text and link target
//       if (text && text.includes('.') && !href.includes(text)) {
//         score += 1;
//         reasons.push(`Mismatched text vs href: text="${text}" → href="${href}"`);
//       }

//       if (href.length > 100 || /%[0-9a-f]{2}/i.test(href)) {
//         score += 0.5;
//         reasons.push(`Suspicious long or encoded link: ${href}`);
//       }
//     } catch (e) {
//       // Invalid URL — skip
//     }
//   });

//   const finalScore = Math.min(score, 3);
//   return { score: finalScore, reasons };
// }

function detectByDynamicBehavior() {
  let score = 0;
  const reasons = [];

  // Detect redirect (example — adjust as needed)
  const navEntry = performance.getEntriesByType("navigation")[0];
  if (navEntry && navEntry.type === "reload" && navEntry.redirectCount > 0) {
    score += 1;
    reasons.push("Suspicious redirect detected after page load.");
  }

  // Monitor for dynamic script or iframe injections
  const observer = new MutationObserver(mutations => {
    mutations.forEach(mutation => {
      mutation.addedNodes.forEach(node => {
        if (
          node.tagName === "SCRIPT" ||
          node.tagName === "IFRAME"
        ) {
          score += 1;
          reasons.push(`Dynamically injected <${node.tagName.toLowerCase()}> detected.`);
        }
      });
    });
  });

  // Observe body for changes
  setTimeout(() => {
    const body = document.body;
    if (body) {
      observer.observe(body, {
        childList: true,
        subtree: true
      });

      // Stop observing after 5 seconds (clean up)
      setTimeout(() => observer.disconnect(), 5000);
    }
  }, 2000); // wait 2s before starting observation

  // Return immediately with initial values;
  // you’ll update risk after observer catches changes

  console.log("Detec By Dynamic Behavior", { score, reasons });
  return {
    score: score >= 1 ? 1 : 0,
    reasons
  };
}


// Static URL Analysis
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

// Detects redirect after load
window.addEventListener("load", () => {
  setTimeout(() => {
    const navEntry = performance.getEntriesByType("navigation")[0];
    const original = navEntry?.name;
    const current = window.location.href;

    if (!original) return; // no redirect info available

    try {
      const originalUrl = new URL(original);
      const currentUrl = new URL(current);

      const samePath = originalUrl.origin + originalUrl.pathname === currentUrl.origin + currentUrl.pathname;
      const sameQuery = originalUrl.search === currentUrl.search;

      if (!samePath || !sameQuery) {
        dynamicFlag = 1;
        console.warn("Redirect detected:", original, "→", current);
      }
    } catch (err) {
      console.warn(" Redirect detection failed due to malformed URL:", err);
    }
  }, 2000);
});


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