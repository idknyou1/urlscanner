import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import os

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def banner():
    print("\033[91m")  
    print(r"""
   __  ______  __       _____ _________    _   __
  / / / / __ \/ /      / ___// ____/   |  / | / /
 / / / / /_/ / /       \__ \/ /   / /| | /  |/ /
/ /_/ / _, _/ /___    ___/ / /___/ ___ |/ /|  /
\____/_/ |_/_____/   /____/\____/_/  |_/_/ |_/
""")
    print("\033[0m")  
    print("       MALICIOUS URL SCANNER by Idknyou_\n")

def domain_from_url(url):
    try:
        return urlparse(url).netloc.lower()
    except:
        return ""

def is_external_link(base_domain, link_url):
    link_domain = domain_from_url(link_url)
    return link_domain and (link_domain != base_domain)

def scan_url(url):
    suspicious_domains = [
        "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "rgttpnts.xyz", "malicious.com"
    ]

    try:
        response = requests.get(url, timeout=10)
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        base_domain = domain_from_url(url)

        title = soup.title.string if soup.title else ""
        lower_html = html.lower()

        protection_indicators = [
            "just a moment", "checking your browser", "attention required", "please enable javascript",
            "cloudflare", "ddos protection", "security check"
        ]

        protection_flag = any(ind in title.lower() or ind in lower_html for ind in protection_indicators)
        if protection_flag:
            print("\033[93m[!] Page looks like a protection or anti-bot interstitial.\033[0m")

        scripts = soup.find_all("script")
        suspicious_script_domains = []
        for s in scripts:
            src = s.get("src")
            if src and any(sd in src for sd in suspicious_domains):
                suspicious_script_domains.append(src)

        forms = soup.find_all("form")
        sensitive_forms = []
        sensitive_fields = ["password", "pass", "login", "user", "email", "card", "cc-number", "credit", "iban"]

        for f in forms:
            inputs = f.find_all(["input", "textarea", "select"])
            fields = []
            for inp in inputs:
                attrs = " ".join([str(inp.get(a, "")).lower() for a in ["type", "name", "id", "placeholder"]])
                if any(sf in attrs for sf in sensitive_fields):
                    fields.append(attrs)
            if fields:
                sensitive_forms.append({"form": str(f)[:200], "fields": fields})

        iframes = soup.find_all("iframe")
        hidden_iframes = []
        for iframe in iframes:
            style = iframe.get("style", "").replace(" ", "").lower()
            width = iframe.get("width")
            height = iframe.get("height")
            if "display:none" in style or width == "0" or height == "0":
                hidden_iframes.append(str(iframe)[:200])

        links = soup.find_all("a", href=True)
        external_links = [l["href"] for l in links if is_external_link(base_domain, l["href"])]

        score = 0
        score += len(suspicious_script_domains) * 3
        score += len(sensitive_forms) * 4
        score += len(hidden_iframes) * 3
        if len(external_links) > 20:
            score += 2
        if protection_flag:
            score += 3  

        
        print(f"\n[+] Page title: {title if title else 'N/A'}")

        print(f"[+] Found {len(suspicious_script_domains)} suspicious external script(s):")
        for s in suspicious_script_domains:
            print(f"    - {s}")

        print(f"[+] Found {len(sensitive_forms)} form(s) with sensitive fields:")
        for f in sensitive_forms:
            print(f"    - Fields: {f['fields']}")

        print(f"[+] Found {len(hidden_iframes)} hidden iframe(s).")

        print(f"[+] Found {len(external_links)} external links.")

        print(f"\nHeuristic suspicion score: {score}")
        if score >= 6:
            print("\033[91m[!] This link may be suspicious.\033[0m")
        elif score >= 3:
            print("\033[93m[!] This link is somewhat suspicious, caution advised.\033[0m")
        else:
            print("\033[92m[+] This link appears clean.\033[0m")

    except Exception as e:
        print(f"\033[91m[-] Error while scanning: {e}\033[0m")


def main():
    while True:
        clear()
        banner()
        print("1. Scan a URL")
        print("2. Exit")
        choice = input("\nSelect an option > ")

        if choice == "1":
            url = input("\nEnter URL to scan: ")
            if not url.startswith("http"):
                url = "http://" + url
            scan_url(url)
            input("\nPress ENTER to continue...")
        elif choice == "2":
            print("\nExiting... Stay safe out there!")
            break
        else:
            print("Invalid choice.")
            input("\nPress ENTER to try again...")

if __name__ == "__main__":
    main()
