import requests
from bs4 import BeautifulSoup
import pandas as pd
import numpy as np
from urllib.parse import urlparse, urlunparse
import time
from concurrent.futures import ThreadPoolExecutor
import json
from typing import Dict, List, Tuple
import logging
import socket
import urllib3
import warnings
import ssl
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

# Suppress only the specific InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# List of top 100 websites (you can replace this with a more comprehensive list)
TOP_SITES = [
    "google.com", "youtube.com", "facebook.com", "wikipedia.org", "instagram.com",
    "bing.com", "reddit.com", "x.com", "yandex.ru",
    "whatsapp.com", "amazon.com", "yahoo.com", "yahoo.co.jp", "weather.com",
    "duckduckgo.com", "baidu.com", "tiktok.com", "pornhub.com", "linkedin.com",
    "netflix.com", "live.com", "office.com", "bilibili.com",
    "twitch.tv", "news.yahoo.co.jp", "microsoft.com", "vk.com", "mail.ru",
    "samsung.com", "xhamster.com", "pinterest.com", "fandom.com", "quora.com",
    "globo.com", "sharepoint.com", "roblox.com", "lazada.com", "kwai.com",
    "telegram.org", "xnxx.com", "cnn.com", "bbc.co.uk", "discord.com",
    "zoom.us", "qq.com", "msn.com", "ebay.com", "nytimes.com", "aajtak.in", "spotify.com", "turbopages.org", "openai.com",
    "play.google.com", "espncricinfo.com", "cricbuzz.com", "apple.com", "naver.com",
    "dzen.ru", "microsoftstore.com", "adobe.com", "imdb.com", "stackoverflow.com",
    "github.com", "wordpress.com", "tripadvisor.com", "booking.com", "indeed.com",
    "etsy.com", "aliexpress.com", "paypal.com", "tumblr.com", "ok.ru",
    "weibo.com", "dropbox.com", "archive.org", "bbc.com", "forbes.com",
    "huffpost.com", "businessinsider.com", "buzzfeed.com", "medium.com", "theguardian.com",
    "washingtonpost.com", "usatoday.com", "cnbc.com", "foxnews.com", "nbcnews.com",
    "reuters.com", "bloomberg.com", "time.com", "npr.org", "theverge.com",
    "engadget.com", "techcrunch.com", "wired.com", "gizmodo.com", "lifehacker.com", "asos.com"
]

# Domain-specific configurations
DOMAIN_CONFIGS = {
    'sharepoint.com': {'use_www': False},  # Microsoft domains typically don't use www
    'office.com': {'use_www': False},
    'live.com': {'use_www': False},
    'microsoft.com': {'use_www': False},
    'microsoftstore.com': {'use_www': False},
}

# Custom SSL adapter that supports modern TLS versions and legacy protocols
class ModernHTTPAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context(
            ssl_version=ssl.PROTOCOL_TLS,
            ciphers='DEFAULT@SECLEVEL=1',  # Allow more ciphers for compatibility
            cert_reqs=ssl.CERT_NONE  # Don't verify certificates
        )
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)

def resolve_domain(url: str) -> str:
    """Resolve domain name and return the correct URL format."""
    domain = url.split('.')[-2] + '.' + url.split('.')[-1]
    
    # Check domain-specific configuration
    if domain in DOMAIN_CONFIGS:
        config = DOMAIN_CONFIGS[domain]
        if not config.get('use_www', True):
            return url.replace('www.', '')
    
    # Try to resolve the domain
    try:
        socket.gethostbyname(url)
        return url
    except socket.gaierror:
        # If www. version fails, try without www.
        if url.startswith('www.'):
            try:
                socket.gethostbyname(url[4:])
                return url[4:]
            except socket.gaierror:
                pass
        # If non-www. version fails, try with www.
        elif '.' in url and url.count('.') == 1:
            try:
                socket.gethostbyname('www.' + url)
                return 'www.' + url
            except socket.gaierror:
                pass
    return url

def get_site_content(url: str) -> Dict:
    """Fetch and analyze website content."""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'DNT': '1',
            'Sec-Ch-Ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"macOS"'
        }
        
        # Parse the URL to handle both domain-only and full URLs
        parsed_url = urlparse(url)
        if not parsed_url.netloc:
            # If it's a domain-only URL, resolve it
            resolved_url = resolve_domain(url)
            logging.info(f"Attempting to fetch domain: {resolved_url}")
            target_url = resolved_url
        else:
            # If it's a full URL, use it as is
            logging.info(f"Attempting to fetch full URL: {url}")
            target_url = url
            
        # Create a session with custom SSL configuration
        session = requests.Session()
        
        # Use modern SSL adapter
        adapter = ModernHTTPAdapter()
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        
        # Configure the session with retry strategy
        retry_strategy = requests.adapters.Retry(
            total=3,
            backoff_factor=2,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD", "OPTIONS"]
        )
        session.mount("https://", requests.adapters.HTTPAdapter(max_retries=retry_strategy))
        
        # Try different protocols and configurations
        for protocol in ['https://', 'http://']:
            try:
                # For domain-only URLs, prepend protocol
                # For full URLs, use as is
                request_url = f"{protocol}{target_url}" if not parsed_url.netloc else target_url
                
                response = session.get(
                    request_url,
                    headers=headers,
                    timeout=(10, 50),
                    allow_redirects=True,
                    verify=False
                )
                
                # Check if we got a successful response
                if response.status_code >= 400:
                    if response.status_code == 403:
                        # Try with different headers for 403
                        headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
                        response = session.get(
                            request_url,
                            headers=headers,
                            timeout=(10, 50),
                            allow_redirects=True,
                            verify=False
                        )
                        if response.status_code >= 400:
                            logging.warning(f"Received status code {response.status_code} for {target_url}")
                            continue
                    else:
                        logging.warning(f"Received status code {response.status_code} for {target_url}")
                        continue
                
                # Read the response content with a timeout
                try:
                    content = response.content
                    if not content:
                        logging.warning(f"Empty response received for {target_url}")
                        continue
                    
                    # Parse the content
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    # Count elements more thoroughly
                    all_elements = soup.find_all()
                    links = soup.find_all('a')
                    images = soup.find_all('img')
                    scripts = soup.find_all('script')
                    styles = soup.find_all(['style', 'link', 'link[rel="stylesheet"]'])
                    iframes = soup.find_all('iframe')
                    
                    # Log the counts for debugging
                    logging.info(f"Element counts for {target_url}:")
                    logging.info(f"Total elements: {len(all_elements)}")
                    logging.info(f"Links: {len(links)}")
                    logging.info(f"Images: {len(images)}")
                    logging.info(f"Scripts: {len(scripts)}")
                    logging.info(f"Styles: {len(styles)}")
                    logging.info(f"IFrames: {len(iframes)}")
                    
                    # Collect metrics
                    metrics = {
                        'url': target_url,
                        'content_length': len(content),
                        'num_elements': len(all_elements),
                        'num_links': len(links),
                        'num_images': len(images),
                        'num_scripts': len(scripts),
                        'num_styles': len(styles),
                        'num_iframes': len(iframes),
                        'status_code': response.status_code,
                        'final_url': response.url,
                        'protocol': protocol.rstrip('://') if not parsed_url.netloc else parsed_url.scheme,
                        'ssl_verified': False
                    }
                    
                    # Check if all metrics are zero or empty
                    if all(value == 0 or value == '' for value in metrics.values() if isinstance(value, (int, str))):
                        logging.warning(f"All metrics are empty for {target_url}")
                        continue
                        
                    return metrics
                    
                except Exception as e:
                    logging.warning(f"Error reading response for {target_url}: {str(e)}")
                    continue
                
            except requests.exceptions.ConnectTimeout:
                logging.warning(f"Connection timeout for {request_url}")
                continue
            except requests.exceptions.ReadTimeout:
                logging.warning(f"Read timeout for {request_url}")
                continue
            except requests.exceptions.ConnectionError as e:
                logging.warning(f"Connection error for {request_url}: {str(e)}")
                continue
            except Exception as e:
                logging.warning(f"Failed to fetch {request_url}: {str(e)}")
                continue
        
        # If we get here, all attempts failed
        return {'url': target_url, 'error': "All access attempts failed"}
            
    except Exception as e:
        logging.error(f"Error processing {url}: {str(e)}")
        return {'url': url, 'error': str(e)}

def analyze_sites(sites: List[str], max_workers: int = 2) -> List[Dict]:
    """Analyze multiple sites in parallel."""
    results = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(get_site_content, site): site for site in sites}
        
        for future in future_to_url:
            try:
                metrics = future.result()
                if 'error' not in metrics:
                    results.append(metrics)
            except Exception as e:
                logging.error(f"Error in thread: {str(e)}")
    
    return results

def calculate_statistics(results: List[Dict]) -> Dict:
    """Calculate statistics from the collected data."""
    df = pd.DataFrame(results)
    
    # Calculate statistics for each metric
    stats = {}
    for column in ['content_length', 'num_elements', 'num_links', 'num_images', 
                  'num_scripts', 'num_styles', 'num_iframes']:
        stats[column] = {
            'mean': df[column].mean(),
            'median': df[column].median(),
            'std': df[column].std(),
            'min': df[column].min(),
            'max': df[column].max(),
            '25th_percentile': df[column].quantile(0.25),
            '75th_percentile': df[column].quantile(0.75)
        }
    
    return stats

def suggest_normalization_values(stats: Dict) -> Dict:
    """Suggest normalization values based on statistics."""
    return {
        'elements': int(stats['num_elements']['median']),  # Use median for elements
        'links': int(stats['num_links']['75th_percentile']),  # Use 75th percentile for links
        'images': int(stats['num_images']['75th_percentile']),  # Use 75th percentile for images
        'scripts': int(stats['num_scripts']['75th_percentile']),  # Use 75th percentile for scripts
        'styles': int(stats['num_styles']['75th_percentile']),  # Use 75th percentile for styles
        'iframes_weight': 5,  # Keep iframe weight as is since they're rare
        'min_content_length': int(stats['content_length']['25th_percentile'])  # Use 25th percentile for min content length
    }

def convert_numpy_types(obj):
    """Convert NumPy types to Python native types for JSON serialization."""
    if isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {key: convert_numpy_types(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy_types(item) for item in obj]
    return obj

def analyze_login_sites(login_sites_file: str) -> List[Dict]:
    """Analyze login pages from a file containing site:login-url pairs."""
    results = []
    
    try:
        with open(login_sites_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                    
                try:
                    site, login_url = line.split(':', 1)
                    site = site.strip()
                    login_url = login_url.strip()
                    
                    # Parse URL components
                    if not login_url.startswith(('http://', 'https://')):
                        login_url = f"https://{login_url}"
                    
                    parsed_url = urlparse(login_url)
                    if not parsed_url.netloc:
                        logging.warning(f"Invalid URL format for {site}: {login_url}")
                        continue
                    
                    # Reconstruct URL without scheme and remove double slash
                    full_url = urlunparse((
                        parsed_url.scheme or 'https',  # Use https as default if no scheme
                        parsed_url.netloc,
                        parsed_url.path or "",
                        parsed_url.params,
                        parsed_url.query,
                        parsed_url.fragment
                    ))
                    
                    logging.info(f"Analyzing login page for {site}: {full_url}")
                    logging.info(f"URL components: scheme={parsed_url.scheme}, netloc={parsed_url.netloc}, path={parsed_url.path}, query={parsed_url.query}, fragment={parsed_url.fragment}")
                    
                    metrics = get_site_content(full_url)
                    
                    if 'error' not in metrics:
                        results.append(metrics)
                    else:
                        logging.warning(f"Failed to analyze login page for {site}: {metrics['error']}")
                        
                except ValueError:
                    logging.warning(f"Invalid line format in {login_sites_file}: {line}")
                    continue
                    
    except FileNotFoundError:
        logging.error(f"Login sites file not found: {login_sites_file}")
        return []
    except Exception as e:
        logging.error(f"Error reading login sites file: {str(e)}")
        return []
        
    return results

def main():
    # logging.info("Starting website analysis...")
    
    # # Analyze main sites
    # results = analyze_sites(TOP_SITES)
    
    # if not results:
    #     logging.error("No results collected for main sites!")
    # else:
    #     # Calculate statistics for main sites
    #     stats = calculate_statistics(results)
        
    #     # Suggest normalization values
    #     normalization = suggest_normalization_values(stats)
        
    #     # Convert NumPy types to Python native types
    #     output = {
    #         'statistics': convert_numpy_types(stats),
    #         'suggested_normalization': convert_numpy_types(normalization),
    #         'sample_size': len(results)
    #     }
        
    #     with open('website_stats.json', 'w') as f:
    #         json.dump(output, f, indent=2)
        
    #     # Print summary for main sites
    #     logging.info(f"\nMain sites analysis complete! Processed {len(results)} sites.")
    #     logging.info("\nSuggested normalization values:")
    #     for key, value in normalization.items():
    #         logging.info(f"{key}: {value}")
        
    #     logging.info("\nDetailed statistics saved to website_stats.json")
    
    # Analyze login pages
    logging.info("\nStarting login pages analysis...")
    login_results = analyze_login_sites('top_sites_login.txt')
    
    if not login_results:
        logging.error("No results collected for login pages!")
    else:
        # Calculate statistics for login pages
        login_stats = calculate_statistics(login_results)

        # Suggest normalization values
        login_normalization = suggest_normalization_values(login_stats)
        
        # Convert NumPy types to Python native types
        login_output = {
            'statistics': convert_numpy_types(login_stats),
            'suggested_normalization': convert_numpy_types(login_normalization),
            'sample_size': len(login_results)
        }
        
        with open('login_pages_stats.json', 'w') as f:
            json.dump(login_output, f, indent=2)
        
        # Print summary for login pages
        logging.info(f"\nLogin pages analysis complete! Processed {len(login_results)} pages.")
        logging.info("\nDetailed statistics saved to login_pages_stats.json")

if __name__ == "__main__":
    main() 