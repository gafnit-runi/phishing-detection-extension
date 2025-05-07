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

function extractFullFeatures(domain) {
  const [sub, dom, suf] = getDomainParts(domain);
  const full = domain;
  
  // Calculate entropies for mean and std
  const entropies = [sub, dom, suf].map(part => shannonEntropy(part));
  const entropyMean = entropies.reduce((a, b) => a + b, 0) / entropies.length;
  const entropyStd = Math.sqrt(
    entropies.reduce((a, b) => a + Math.pow(b - entropyMean, 2), 0) / entropies.length
  );

  return {
    length_full: full.length,
    length_sub: sub.length,
    length_dom: dom.length,
    length_suf: suf.length,
    unique_chars_full: new Set(full).size,
    unique_chars_sub: new Set(sub).size,
    unique_chars_dom: new Set(dom).size,
    unique_chars_suf: new Set(suf).size,
    num_digits_full: (full.match(/\d/g) || []).length,
    num_symbols_full: (full.match(/[!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~]/g) || []).length,
    entropy_full: shannonEntropy(full),
    entropy_sub: shannonEntropy(sub),
    entropy_dom: shannonEntropy(dom),
    entropy_suf: shannonEntropy(suf),
    entropy_mean: entropyMean,
    entropy_std: entropyStd,
    char_continuity_full: charContinuityRate(full),
    char_continuity_dom: charContinuityRate(dom)
  };
}

// Export the main function
export { extractFullFeatures }; 