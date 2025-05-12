import math
import string
import re
from collections import Counter
import numpy as np
import Levenshtein
from urllib.parse import urlparse

TOP_DOMAINS = set()
KNOWN_BRANDS = [
    # Financial Services & Payment
    "paypal", "stripe", "square", "visa", "mastercard", "amex", "chase", "wellsfargo",
    "bankofamerica", "citibank", "hsbc", "barclays", "capitalone", "discover", "venmo",
    "cashapp", "westernunion", "transferwise", "revolut", "klarna", "affirm",
    
    # Tech Giants & Social Media
    "google", "facebook", "apple", "amazon", "microsoft", "meta", "twitter", "linkedin",
    "instagram", "tiktok", "snapchat", "pinterest", "reddit", "youtube", "whatsapp",
    "telegram", "wechat", "line", "kakao", "viber",
    
    # Email & Cloud Services
    "outlook", "yahoo", "gmail", "protonmail", "icloud", "zoho", "dropbox", "box",
    "onedrive", "googledrive", "evernote", "notion", "airtable", "office365",
    
    # E-commerce & Retail
    "ebay", "walmart", "target", "bestbuy", "costco", "aliexpress", "shopify", "etsy",
    "wayfair", "homedepot", "lowes", "ikea", "nike", "adidas", "macys", "nordstrom",
    
    # Entertainment & Streaming
    "netflix", "spotify", "disney", "hulu", "amazonprime", "hbomax", "peacock",
    "paramount", "twitch", "steam", "epicgames", "nintendo", "playstation", "xbox",
    
    # Business & Productivity
    "zoom", "teams", "slack", "asana", "trello", "github", "gitlab", "bitbucket",
    "atlassian", "salesforce", "hubspot", "zendesk", "freshworks", "quickbooks", "xero",
    
    # Travel & Transportation
    "uber", "lyft", "airbnb", "booking", "expedia", "tripadvisor", "marriott",
    "hilton", "delta", "united", "southwest", "americanairlines", "britishairways",
    
    # Food Delivery
    "doordash", "ubereats", "grubhub", "postmates", "instacart", "gopuff"
]

SUSPICIOUS_TLDS = {
    # Known Abuse TLDs
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "pw", "cc", "country", "download",
    "racing", "icu", "work", "casa", "link", "click", "space", "fun", "science",
    "fit", "buzz", "club", "online", "site", "live", "stream", "review", "bid",
    "trade", "date", "party", "loan", "accountant", "win", "faith", "cricket",
    
    # Recently Abused New gTLDs
    "monster", "ren", "wang", "world", "tech", "rest", "bar", "best", "cam",
    "cyou", "surf", "mom", "dad", "kids", "hair", "pics", "photo", "cloud"
}

URL_SHORTENERS = {
    # Popular URL Shorteners
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "buff.ly", "cutt.ly",
    "tiny.cc", "is.gd", "cli.gs", "soo.gd", "s2r.co", "tny.im", "snip.ly",
    "short.io", "bl.ink", "rebrand.ly", "buff.ly", "shorturl.at", "rb.gy",
    
    # Social Media Shorteners
    "fb.me", "youtu.be", "amzn.to", "lnkd.in", "spoti.fi", "wa.me", "pin.it",
    
    # Custom Enterprise Shorteners
    "adf.ly", "po.st", "bc.vc", "j.mp", "su.pr", "dlvr.it", "ift.tt"
}


def shannon_entropy(s):
    if not s: return 0
    probs = [n / len(s) for n in Counter(s).values()]
    return -sum(p * math.log2(p) for p in probs)

def has_keyword(domain, keywords):
    return int(any(kw in domain.lower() for kw in keywords))

def min_lev_distance(domain, brand_list):
    # Clean domain: remove www, extract only the second-level domain
    domain = domain.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    parts = domain.split(".")
    if len(parts) >= 2:
        core = parts[-2]  # Get second-level domain
    else:
        core = domain
    return min(Levenshtein.distance(core, brand) for brand in brand_list)

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

def extract_full_features(url):

    parsed = urlparse(url if url.startswith("http") else f"http://{url}")
    domain = parsed.netloc.lower() or parsed.path.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()


    sub, dom, suf = get_domain_parts(domain)
 
    features = {
        'entropy_std': np.std([shannon_entropy(p) for p in [sub, dom, suf]]), #2 strong KDE
        'entropy_mean': np.mean([shannon_entropy(p) for p in [sub, dom, suf]]), #2 strong KDE
        'unique_chars_sub': len(set(sub)), #1
        'char_continuity_sub': char_continuity_rate(sub), #1 mid KDE
        'char_continuity_url': char_continuity_rate(url), #2'
        'entropy_dom': shannon_entropy(dom), #?
        'num_subdomains': domain.count('.') - 1, #1
        'path_depth': path.count('/'), #2 ?
        'unique_chars_url': len(set(url)),
        'unique_chars_dom': len(set(dom)),
        'levenshtein_to_brand': min_lev_distance(domain, TOP_DOMAINS), 
        'is_shortened': int(domain.lower() in URL_SHORTENERS), #1        
        'is_suspicious_tld': int(suf in SUSPICIOUS_TLDS), #1 

        # 'length_sub': len(sub), #1
        # 'path_length': len(path), #2 weak KDE

        # 'unique_chars_suf': len(set(suf)), #2 weak KDE
        # 'entropy_sub': shannon_entropy(sub), #1 weak KDE
        
        
        

        
        # 'length_url': len(url), #2
        # 'num_symbols_url': sum(c in string.punctuation for c in url), #2
        # 'is_short_brand': (min_lev_distance(domain, TOP_DOMAINS) <= 2) & (len(url) < 15)

        # maybe add char_continuity_url mid KDE
    }

    return features


#all features:
# 'length_url': len(url), #2
#         'length_sub': len(sub), #1
#         'length_dom': len(dom),
#         'length_suf': len(suf),
#         'path_length': len(path), #2


#         'unique_chars_url': len(set(url)),
#         'unique_chars_sub': len(set(sub)), #1
#         'unique_chars_dom': len(set(dom)),
#         'unique_chars_suf': len(set(suf)), #2
#         'num_digits_url': sum(c.isdigit() for c in url),
#         'num_symbols_url': sum(c in string.punctuation for c in url), #2
#         'num_hyphens': domain.count('-'), #1
#         'num_subdomains': domain.count('.') - 1, #1

#         'entropy_url': shannon_entropy(url),
#         'entropy_sub': shannon_entropy(sub), #1
#         'entropy_dom': shannon_entropy(dom),
#         'entropy_suf': shannon_entropy(suf), #2
#         'entropy_mean': np.mean([shannon_entropy(p) for p in [sub, dom, suf]]), #2
#         'entropy_std': np.std([shannon_entropy(p) for p in [sub, dom, suf]]), #2

#         'char_continuity_url': char_continuity_rate(url), #2
#         'char_continuity_sub': char_continuity_rate(sub), #1
#         'char_continuity_dom': char_continuity_rate(dom),
        
        
#         'has_https_keyword': has_keyword(domain, ["https"]), #1
#         'levenshtein_to_brand': min_lev_distance(domain, TOP_DOMAINS),
#         'has_login_in_path': int(any(word in path for word in ["login", "signin", "verify", "secure", "account"])), #1

#         'has_at_symbol': int('@' in domain), #1
#         'is_ip_address': int(bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', dom))),
#         'is_suspicious_tld': int(suf in SUSPICIOUS_TLDS), #1
#         'is_shortened': int(domain.lower() in URL_SHORTENERS), #1
        
#         'path_depth': path.count('/'), #2
#         'num_query_parameters': query.count('&') + query.count('='),
#         'query_length': len(query),
#         'is_short_brand': (min_lev_distance(domain, KNOWN_BRANDS) <= 2) & (len(url) < 15)

# Option A:
        # 'length_url': len(url),
        # 'length_sub': len(sub),
        # 'length_dom': len(dom),
        # 'unique_chars_url': len(set(url)),
        # 'unique_chars_sub': len(set(sub)),
        # 'num_digits_url': sum(c.isdigit() for c in url),
        # 'num_symbols_url': sum(c in string.punctuation for c in url),
        # 'entropy_url': shannon_entropy(url),
        # 'entropy_sub': shannon_entropy(sub),
        # 'entropy_dom': shannon_entropy(dom),
        # 'entropy_mean': np.mean([shannon_entropy(p) for p in [sub, dom, suf]]),
        # 'entropy_std': np.std([shannon_entropy(p) for p in [sub, dom, suf]]),
        # 'char_continuity_url': char_continuity_rate(url),
        # 'char_continuity_sub': char_continuity_rate(sub),

        # 'num_subdomains': domain.count('.') - 1,

        # 'levenshtein_to_brand': min_lev_distance(domain, KNOWN_BRANDS),
        # 'is_shortened': int(domain.lower() in URL_SHORTENERS),
        # 'path_length': len(path),
        # 'path_depth': path.count('/'),
        # 'has_login_in_path': int(any(word in path for word in ["login", "signin", "verify", "secure", "account"])),

# Option B:
        # 'length_url': len(url),
        # 'length_sub': len(sub),
        # 'length_dom': len(dom),
        # 'length_suf': len(suf),
        # 'unique_chars_url': len(set(url)),
        # 'unique_chars_sub': len(set(sub)),
        # 'unique_chars_dom': len(set(dom)),
        # 'unique_chars_suf': len(set(suf)),
        # 'num_symbols_url': sum(c in string.punctuation for c in url),
        # 'entropy_url': shannon_entropy(url),
        # 'entropy_sub': shannon_entropy(sub),
        # 'entropy_dom': shannon_entropy(dom),
        # 'entropy_suf': shannon_entropy(suf),
        # 'entropy_mean': np.mean([shannon_entropy(p) for p in [sub, dom, suf]]),
        # 'entropy_std': np.std([shannon_entropy(p) for p in [sub, dom, suf]]),
        # 'char_continuity_url': char_continuity_rate(url),
        # 'char_continuity_sub': char_continuity_rate(sub),
        # 'num_hyphens': domain.count('-'),
        # 'num_subdomains': domain.count('.') - 1,
        # 'levenshtein_to_brand': min_lev_distance(domain, KNOWN_BRANDS),
        # 'path_length': len(path),
        # 'path_depth': path.count('/')