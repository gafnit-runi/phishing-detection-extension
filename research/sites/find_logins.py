import requests
from urllib.parse import urljoin

TOP_SITES = [
    "google.com", "youtube.com", "facebook.com", "wikipedia.org", "instagram.com",
    "bing.com", "reddit.com", "x.com", "chatgpt.com", "yandex.ru",
    "whatsapp.com", "amazon.com", "yahoo.com", "yahoo.co.jp", "weather.com",
    "duckduckgo.com", "baidu.com", "tiktok.com", "pornhub.com", "linkedin.com",
    "netflix.com", "live.com", "office.com", "microsoftonline.com", "bilibili.com",
    "twitch.tv", "news.yahoo.co.jp", "microsoft.com", "vk.com", "mail.ru",
    "samsung.com", "xhamster.com", "pinterest.com", "fandom.com", "quora.com",
    "globo.com", "sharepoint.com", "roblox.com", "lazada.com", "kwai.com",
    "telegram.org", "xnxx.com", "cnn.com", "bbc.co.uk", "discord.com",
    "zoom.us", "qq.com", "msn.com", "ebay.com", "nytimes.com",
    "realsrv.com", "aajtak.in", "spotify.com", "turbopages.org", "openai.com",
    "play.google.com", "espncricinfo.com", "cricbuzz.com", "apple.com", "naver.com",
    "dzen.ru", "microsoftstore.com", "adobe.com", "imdb.com", "stackoverflow.com",
    "github.com", "wordpress.com", "tripadvisor.com", "booking.com", "indeed.com",
    "etsy.com", "aliexpress.com", "paypal.com", "tumblr.com", "ok.ru",
    "weibo.com", "dropbox.com", "archive.org", "bbc.com", "forbes.com",
    "huffpost.com", "businessinsider.com", "buzzfeed.com", "medium.com", "theguardian.com",
    "washingtonpost.com", "usatoday.com", "cnbc.com", "foxnews.com", "nbcnews.com",
    "reuters.com", "bloomberg.com", "time.com", "npr.org", "theverge.com",
    "engadget.com", "techcrunch.com", "wired.com", "gizmodo.com", "lifehacker.com"
]

COMMON_LOGIN_PATHS = [
    "/login", "/signin", "/account/login", "/accounts/login", "/auth/login",
    "/users/login", "/log-in", "/sign-in", "/account/signin", "/session/new"
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; GPT-Login-Finder/1.0)"
}

def find_login_url(domain):
    for path in COMMON_LOGIN_PATHS:
        url = f"https://{domain.strip('/')}{path}"
        try:
            response = requests.get(url, headers=HEADERS, timeout=5)
            if response.status_code == 200 and "login" in response.url.lower():
                return response.url
        except requests.RequestException:
            continue
    return None

if __name__ == "__main__":
    top_sites_login = {}
    for site in TOP_SITES:
        print(f"Checking {site}...")
        login_url = find_login_url(site)
        top_sites_login[site] = login_url or "Not Found"
        print(f" → Login URL: {top_sites_login[site]}")

    # Optionally save to file
    with open("top_sites_login.txt", "w") as f:
        for site, login in top_sites_login.items():
            f.write(f"{site}: {login}\n")
