# core/web_crawler.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import time

class WebCrawler:
    """
    Generic web crawler that auto-discovers forms,
    URL parameters and links on any website.
    """

    def __init__(self, base_url, session=None, max_pages=15):
        self.base_url = base_url.rstrip("/")
        self.base_domain = urlparse(base_url).netloc
        self.session = session or requests.Session()
        self.max_pages = max_pages
        self.visited = set()
        self.forms_found = []
        self.url_params_found = []   # NEW: URLs with GET parameters
        self.pages_crawled = []

        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Security Scanner - Authorized Testing)"
        })

    def _is_same_domain(self, url):
        return urlparse(url).netloc == self.base_domain

    def _normalize_url(self, url, parent_url):
        return urljoin(parent_url, url)

    def _extract_url_params(self, url):
        """Extract URLs that have GET parameters — these are injection points"""
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            if params:
                return {
                    "url": url,
                    "base_url": f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                    "params": {k: v[0] for k, v in params.items()}
                }
        return None

    def _extract_form_details(self, form, page_url):
        action = form.attrs.get("action", "")
        method = form.attrs.get("method", "get").lower()

        if not action or action == "#":
            action_url = page_url
        elif action.startswith("http"):
            action_url = action
        else:
            action_url = urljoin(page_url, action)

        inputs = []
        for tag in form.find_all(["input", "textarea", "select"]):
            input_type = tag.attrs.get("type", "text").lower()
            input_name = tag.attrs.get("name", "")
            input_value = tag.attrs.get("value", "")
            if not input_name:
                continue
            inputs.append({
                "type": input_type,
                "name": input_name,
                "value": input_value
            })

        return {
            "action_url": action_url,
            "method": method,
            "inputs": inputs,
            "page_url": page_url
        }

    def get_links(self, url, soup):
        links = set()
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            full_url = self._normalize_url(href, url)
            if self._is_same_domain(full_url):
                clean = full_url.split("#")[0]
                if clean and clean not in self.visited:
                    links.add(clean)
        return links

    def crawl(self):
        """
        Crawl website and discover:
        1. All forms (POST + GET)
        2. All URLs with GET parameters
        """
        print(f"[CRAWLER] 🕷️ Starting crawl on: {self.base_url}")
        print(f"[CRAWLER] Max pages: {self.max_pages}")

        to_visit = {self.base_url}
        seen_param_bases = set()

        while to_visit and len(self.visited) < self.max_pages:
            url = to_visit.pop()
            if url in self.visited:
                continue

            # Check if this URL has parameters — save it as injection point
            url_param = self._extract_url_params(url)
            if url_param:
                base = url_param["base_url"]
                if base not in seen_param_bases:
                    seen_param_bases.add(base)
                    self.url_params_found.append(url_param)
                    print(f"[CRAWLER] 📌 URL param found: {url} → params: {list(url_param['params'].keys())}")

            print(f"[CRAWLER] Visiting: {url}")
            self.visited.add(url)

            try:
                response = self.session.get(url, timeout=10)
                soup = BeautifulSoup(response.text, "html.parser")

                # Extract forms
                for form in soup.find_all("form"):
                    details = self._extract_form_details(form, url)
                    if details["inputs"]:
                        self.forms_found.append(details)
                        print(f"[CRAWLER] 📋 Form found: {details['action_url']} ({len(details['inputs'])} inputs)")

                self.pages_crawled.append(url)

                # Get more links — including ones with parameters
                new_links = self.get_links(url, soup)
                to_visit.update(new_links - self.visited)

                time.sleep(0.2)

            except Exception as e:
                print(f"[CRAWLER] Error on {url}: {e}")
                continue

        print(f"[CRAWLER] ✅ Done: {len(self.pages_crawled)} pages, "
              f"{len(self.forms_found)} forms, "
              f"{len(self.url_params_found)} URL param endpoints")
        return self.forms_found

    def submit_form(self, form_details, payload, target_param=None):
        """Submit a form with payload"""
        data = {}
        for inp in form_details["inputs"]:
            name = inp["name"]
            itype = inp["type"]
            if itype in ["hidden", "submit", "button", "image"]:
                data[name] = inp["value"] or ""
            elif itype in ["text", "search", "email", "url",
                           "textarea", "password", "tel", "number"]:
                if target_param:
                    data[name] = payload if name == target_param else inp["value"] or "test"
                else:
                    data[name] = payload
            else:
                data[name] = inp["value"] or "test"

        try:
            if form_details["method"] == "post":
                return self.session.post(
                    form_details["action_url"], data=data, timeout=10
                )
            else:
                return self.session.get(
                    form_details["action_url"], params=data, timeout=10
                )
        except Exception as e:
            print(f"[CRAWLER] Submit error: {e}")
            return None

    def test_url_param(self, url_param_info, payload, param_name):
        """Test a URL parameter with a payload"""
        try:
            params = dict(url_param_info["params"])
            params[param_name] = payload
            return self.session.get(
                url_param_info["base_url"], params=params, timeout=10
            )
        except Exception as e:
            print(f"[CRAWLER] URL param test error: {e}")
            return None
