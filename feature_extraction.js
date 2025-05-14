// External sets to be imported or defined globally
// const TOP_DOMAINS = new Set();
const SUSPICIOUS_TLDS = new Set([
  "tk", "ml", "ga", "cf", "gq", "xyz", "top", "pw", "cc", "country", "download",
  "racing", "icu", "work", "casa", "link", "click", "space", "fun", "science",
  "fit", "buzz", "club", "online", "site", "live", "stream", "review", "bid",
  "trade", "date", "party", "loan", "accountant", "win", "faith", "cricket",
  "monster", "ren", "wang", "world", "tech", "rest", "bar", "best", "cam",
  "cyou", "surf", "mom", "dad", "kids", "hair", "pics", "photo", "cloud"
]);
const KNOWN_BRANDS = new Set([
  // Financial Services & Payment
  "paypal", "stripe", "square", "visa", "mastercard", "amex", "chase", "wellsfargo",
  "bankofamerica", "citibank", "hsbc", "barclays", "capitalone", "discover", "venmo",
  "cashapp", "westernunion", "transferwise", "revolut", "klarna", "affirm",
  
  // Tech Giants & Social Media
  "google", "facebook", "apple", "amazon", "microsoft", "meta", "twitter", "linkedin",
  "instagram", "tiktok", "snapchat", "pinterest", "reddit", "youtube", "whatsapp",
  "telegram", "wechat", "line", "kakao", "viber",
  
  // Email & Cloud Services
  "outlook", "yahoo", "gmail", "protonmail", "icloud", "zoho", "dropbox", "box",
  "onedrive", "googledrive", "evernote", "notion", "airtable", "office365",
  
  // E-commerce & Retail
  "ebay", "walmart", "target", "bestbuy", "costco", "aliexpress", "shopify", "etsy",
  "wayfair", "homedepot", "lowes", "ikea", "nike", "adidas", "macys", "nordstrom",
  
  // Entertainment & Streaming
  "netflix", "spotify", "disney", "hulu", "amazonprime", "hbomax", "peacock",
  "paramount", "twitch", "steam", "epicgames", "nintendo", "playstation", "xbox",
  
  // Business & Productivity
  "zoom", "teams", "slack", "asana", "trello", "github", "gitlab", "bitbucket",
  "atlassian", "salesforce", "hubspot", "zendesk", "freshworks", "quickbooks", "xero",
  
  // Travel & Transportation
  "uber", "lyft", "airbnb", "booking", "expedia", "tripadvisor", "marriott",
  "hilton", "delta", "united", "southwest", "americanairlines", "britishairways",
  
  // Food Delivery
  "doordash", "ubereats", "grubhub", "postmates", "instacart", "gopuff"
]);

const URL_SHORTENERS = new Set([
  "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "buff.ly", "cutt.ly",
  "tiny.cc", "is.gd", "cli.gs", "soo.gd", "s2r.co", "tny.im", "snip.ly",
  "short.io", "bl.ink", "rebrand.ly", "shorturl.at", "rb.gy",
  "fb.me", "youtu.be", "amzn.to", "lnkd.in", "spoti.fi", "wa.me", "pin.it",
  "adf.ly", "po.st", "bc.vc", "j.mp", "su.pr", "dlvr.it", "ift.tt"
]);

// Helper functions
function shannonEntropy(s) {
  if (!s) return 0;
  const freq = {};
  for (let char of s) {
    freq[char] = (freq[char] || 0) + 1;
  }
  const probs = Object.values(freq).map(n => n / s.length);
  return -probs.reduce((sum, p) => sum + p * Math.log2(p), 0);
}

function charContinuityRate(s) {
  if (!s) return 0;
  let lastType = null;
  let count = 0;
  const segments = [];
  
  for (let c of s) {
    let t;
    if (/[a-zA-Z]/.test(c)) t = 'a';
    else if (/[0-9]/.test(c)) t = 'd';
    else t = 's';
    
    if (t === lastType) {
      count++;
    } else {
      if (count > 0) segments.push(count);
      count = 1;
      lastType = t;
    }
  }
  segments.push(count);
  return Math.max(...segments) / s.length;
}

function getDomainParts(domain) {
  const parts = domain.split('.');
  let sub, dom, suf;
  
  if (parts.length > 2) {
    sub = parts.slice(0, -2).join('.');
    dom = parts[parts.length - 2];
    suf = parts[parts.length - 1];
  } else if (parts.length === 2) {
    sub = '';
    dom = parts[0];
    suf = parts[1];
  } else {
    sub = dom = suf = '';
  }
  
  return [sub, dom, suf];
}

function hasKeyword(s, keywords) {
  return keywords.some(k => s.includes(k)) ? 1 : 0;
}

function minLevenshteinDistance(domain, brandList) {
  const core = domain.replace(/^www\./, '').split(".").slice(-2, -1)[0] || domain;
  return Math.min(...Array.from(brandList).map(brand => levenshtein(core, brand)));
}

// Dummy Levenshtein implementation placeholder
function levenshtein(a, b) {
  const matrix = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      matrix[i][j] = Math.min(
        matrix[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
        matrix[i][j - 1] + 1,
        matrix[i - 1][j] + 1
      );
    }
  }
  return matrix[a.length][b.length];
}

function extractFullFeatures(url) {
  console.log("extractFullFeatures", url);
  try {
    const parsedUrl = new URL(url.startsWith("http") ? url : `http://${url}`);
    const domain = parsedUrl.hostname.toLowerCase();
    const path = parsedUrl.pathname.toLowerCase();
    const query = parsedUrl.search.toLowerCase();

    const [sub, dom, suf] = getDomainParts(domain);
    const entropies = [sub, dom, suf].map(shannonEntropy);
    const entropyMean = entropies.reduce((a, b) => a + b, 0) / entropies.length;
    const entropyStd = Math.sqrt(entropies.reduce((a, b) => a + Math.pow(b - entropyMean, 2), 0) / entropies.length);

    return {
      entropy_std: entropyStd,
      entropy_mean: entropyMean,
      unique_chars_sub: new Set(sub).size,
      char_continuity_sub: charContinuityRate(sub),
      char_continuity_url: charContinuityRate(url),
      entropy_dom: shannonEntropy(dom),
      num_subdomains: domain.split('.').length - 1,
      path_depth: path.split('/').length - 1,
      unique_chars_url: new Set(url).size,
      unique_chars_dom: new Set(dom).size,
      levenshtein_to_brand: minLevenshteinDistance(domain, KNOWN_BRANDS),
      is_shortened: URL_SHORTENERS.has(domain),
      is_suspicious_tld: SUSPICIOUS_TLDS.has(suf)
    };
  } catch (err) {
    console.error("Failed to extract features", err);
    return null;
  }
}

// Export the main function
export { extractFullFeatures }; 