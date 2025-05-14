

import math
import string
from collections import Counter
import numpy as np

TOP_DOMAINS = set()

def shannon_entropy(s):
    if not s: return 0
    probs = [n / len(s) for n in Counter(s).values()]
    return -sum(p * math.log2(p) for p in probs)

def char_continuity_rate(s):
    if not s: return 0
    last_type = None
    count = 0
    segments = []
    for c in s:
        if c.isalpha(): t = 'a'
        elif c.isdigit(): t = 'd'
        else: t = 's'
        if t == last_type:
            count += 1
        else:
            if count > 0: segments.append(count)
            count = 1
            last_type = t
    segments.append(count)
    return max(segments) / len(s)

def get_domain_parts(domain):
    parts = domain.split('.')
    if len(parts) > 2:
        sub = '.'.join(parts[:-2])
        dom = parts[-2]
        suf = parts[-1]
    elif len(parts) == 2:
        sub = ''
        dom = parts[0]
        suf = parts[1]
    else:
        sub = dom = suf = ''
    return sub, dom, suf

def extract_full_features(domain):
    sub, dom, suf = get_domain_parts(domain)
    full = domain
    features = {
        'length_full': len(full),
        'length_sub': len(sub),
        'length_dom': len(dom),
        'length_suf': len(suf),
        'unique_chars_full': len(set(full)),
        'unique_chars_sub': len(set(sub)),
        'unique_chars_dom': len(set(dom)),
        'unique_chars_suf': len(set(suf)),
        'num_digits_full': sum(c.isdigit() for c in full),
        'num_symbols_full': sum(c in string.punctuation for c in full),
        'entropy_full': shannon_entropy(full),
        'entropy_sub': shannon_entropy(sub),
        'entropy_dom': shannon_entropy(dom),
        'entropy_suf': shannon_entropy(suf),
        'entropy_mean': np.mean([shannon_entropy(p) for p in [sub, dom, suf]]),
        'entropy_std': np.std([shannon_entropy(p) for p in [sub, dom, suf]]),
        'char_continuity_full': char_continuity_rate(full),
        'char_continuity_dom': char_continuity_rate(dom)
    }

    # # ✅ Add custom feature after the dict is built
    # features["is_top_1m"] = int(domain.lower().lstrip("www.") in TOP_DOMAINS)
    # print(domain.lower().lstrip("www.") in TOP_DOMAINS)

    return features