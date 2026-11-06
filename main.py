import re
import json
import http.client
import urllib.request
from datetime import datetime, timezone
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin

from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel

app = FastAPI()


class Message(BaseModel):
    text: str


# ------------------------------------------------------------------
# SETTINGS
# ------------------------------------------------------------------
ONLINE_CHECKS = True   # False = skip short-link expanding and domain-age lookups
ONLINE_TIMEOUT = 3     # seconds to wait for each internet request
RDAP_URL = "https://rdap.org/domain/"   # free public "who registered this domain" service


# ------------------------------------------------------------------
# PART 1: the models from your teammates.
#   sms_model.py -> def check_sms(text)  -> number 0 to 100
#   url_model.py -> def check_url(link)  -> number 0 to 100
# (0 = totally safe, 100 = surely phishing)
# ------------------------------------------------------------------
try:
    from sms_model import check_sms
    print("Using real SMS model")
except Exception as e:
    print("!!! SMS MODEL FAILED TO LOAD, using a placeholder. Reason:", repr(e))
    def check_sms(text):
        return 10  # fake answer for now

try:
    from url_model import check_url
    print("Using real URL model")
except Exception as e:
    print("!!! URL MODEL FAILED TO LOAD, using a placeholder. Reason:", repr(e))
    def check_url(link):
        return 10  # fake answer for now


# ------------------------------------------------------------------
# PART 2: simple rules that also explain WHY something looks bad.
# ------------------------------------------------------------------
URGENT_WORDS = ["urgent", "immediately", "within 24", "blocked", "suspended",
                "expire", "last warning", "act now", "verify now", "final notice"]
MONEY_WORDS = ["kyc", "otp", "bank", "upi", "refund", "prize", "lottery",
               "reward", "customs", "fastag", "electricity", "disconnected", "pan card"]
BAD_ENDINGS = [".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf", ".gq", ".icu", ".buzz"]
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "rb.gy", "is.gd"]
BRANDS = ["sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "gpay", "amazon",
          "flipkart", "netflix", "airtel", "jio", "irctc", "uidai", "aadhaar"]
SAFE_DOMAINS = ["hdfcbank.com", "icicibank.com", "axisbank.com", "sbi.co.in",
                "onlinesbi.sbi", "paytm.com", "phonepe.com", "amazon.in",
                "amazon.com", "flipkart.com", "netflix.com", "airtel.in",
                "jio.com", "irctc.co.in", "uidai.gov.in", "google.com"]


def is_trusted(domain):
    return any(domain == s or domain.endswith("." + s) for s in SAFE_DOMAINS)


def is_shortener(domain):
    return any(domain == s or domain.endswith("." + s) for s in SHORTENERS)


def find_links(text):
    # strip punctuation that sticks to the end of a link in a sentence
    return [l.rstrip(".,;)!\"'") for l in re.findall(r"(?:https?://|www\.)\S+", text, flags=re.I)]


def clean_domain(link):
    """Gets just the website name from a link (removes http://, www., path, port)."""
    d = re.sub(r"^https?://", "", link.lower()).split("/")[0].split("?")[0]
    d = d.split(":")[0].rstrip(".,;)")
    if d.startswith("www."):
        d = d[4:]
    return d


def is_ip(domain):
    return bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", domain))


# ---- Feature: short-link expander ---------------------------------
@lru_cache(maxsize=256)
def expand_short_link(url, max_hops=5):
    """Finds where a short link (bit.ly etc.) really points.
    Safety: we only send a HEAD request to the shortener service itself and read
    its 'Location' header. We NEVER open the final (possibly dangerous) website.
    Returns the final URL, or None if it could not be expanded."""
    cur = url if "://" in url else "http://" + url
    changed = False
    for _ in range(max_hops):
        p = urlparse(cur)
        host = (p.hostname or "").lower()
        if not is_shortener(host):
            break
        try:
            conn_class = http.client.HTTPSConnection if p.scheme == "https" else http.client.HTTPConnection
            conn = conn_class(host, p.port, timeout=ONLINE_TIMEOUT)
            path = (p.path or "/") + ("?" + p.query if p.query else "")
            conn.request("HEAD", path, headers={"User-Agent": "Mozilla/5.0 PhishGuard"})
            resp = conn.getresponse()
            location = resp.getheader("Location")
            conn.close()
        except Exception:
            return cur if changed else None
        if resp.status in (301, 302, 303, 307, 308) and location:
            cur = urljoin(cur, location)
            changed = True
        else:
            break
    return cur if changed else None


# ---- Feature: domain age check ------------------------------------
def registrable_domain(domain):
    """'login.secure-sbi.xyz' -> 'secure-sbi.xyz'; 'mail.abc.co.in' -> 'abc.co.in'"""
    parts = domain.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "ac", "gov", "org", "net", "com", "edu", "nic"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


@lru_cache(maxsize=256)
def domain_age_days(domain):
    """How many days ago the website name was registered (RDAP lookup).
    Brand-new websites are a classic phishing sign. Returns None if unknown."""
    try:
        req = urllib.request.Request(
            RDAP_URL + registrable_domain(domain),
            headers={"User-Agent": "Mozilla/5.0 PhishGuard", "Accept": "application/rdap+json"})
        with urllib.request.urlopen(req, timeout=ONLINE_TIMEOUT) as r:
            data = json.loads(r.read().decode("utf-8", "ignore"))
        for ev in data.get("events", []):
            if ev.get("eventAction") == "registration":
                d = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                if d.tzinfo is None:
                    d = d.replace(tzinfo=timezone.utc)
                return max(0, (datetime.now(timezone.utc) - d).days)
    except Exception:
        return None
    return None


def run_online_checks(links):
    """Runs the internet checks in parallel, with a time limit, and never raises.
    Returns (expanded, ages): expanded[short_link] = final url, ages[domain] = days."""
    expanded, ages = {}, {}
    if not ONLINE_CHECKS or not links:
        return expanded, ages
    ex = ThreadPoolExecutor(max_workers=8)
    try:
        # 1) expand short links
        futs = {l: ex.submit(expand_short_link, l) for l in links if is_shortener(clean_domain(l))}
        for l, f in futs.items():
            try:
                final = f.result(timeout=ONLINE_TIMEOUT * 3)
                if final:
                    expanded[l] = final
            except Exception:
                pass
        # 2) domain age for every real (non-short, non-trusted, non-IP) website
        domains = set()
        for l in list(links) + list(expanded.values()):
            d = clean_domain(l)
            if d and not is_shortener(d) and not is_trusted(d) and not is_ip(d):
                domains.add(d)
        dfuts = {d: ex.submit(domain_age_days, d) for d in domains}
        for d, f in dfuts.items():
            try:
                age = f.result(timeout=ONLINE_TIMEOUT * 2)
                if age is not None:
                    ages[d] = age
            except Exception:
                pass
    except Exception:
        pass
    finally:
        ex.shutdown(wait=False)
    return expanded, ages


PRIVATE_THINGS = r"(aadhaar|aadhar|\bpan\b|cvv|card number|card details|account number|bank details|password|\bpin\b)"
ASK_VERBS = r"(shar\w*|send\w*|reply|provide|enter|give|bhej\w*|bata\w*)"


def asks_private_details(text):
    """True if the message asks you to send/share Aadhaar, PAN, card, PIN, etc.
    Warnings like 'Do not share your PIN' are ignored."""
    low = re.sub(r"\b(do not|don't|dont|never|not to)\s+(share|disclose|give|send|reveal)\b", " ", text.lower())
    low = re.sub(r"(?:https?://|www\.)\S+", " ", low)
    return bool(re.search(ASK_VERBS + r".{0,50}" + PRIVATE_THINGS, low) or
                re.search(PRIVATE_THINGS + r".{0,60}" + ASK_VERBS, low))


def rule_reasons(text, links=None, ages=None):
    """Returns (extra_points, list_of_reasons)."""
    if links is None:
        links = find_links(text)
    ages = ages or {}
    # Look for scam words in the message text only (not inside the links)
    low = re.sub(r"(?:https?://|www\.)\S+", " ", text.lower())
    points = 0
    reasons = []

    hit = [w for w in URGENT_WORDS if w in low]
    if hit:
        points += 30
        reasons.append("Pressure words used: " + ", ".join(hit[:3]))

    hit = [w for w in MONEY_WORDS if w in low]
    if hit:
        points += 15
        reasons.append("Money / account words: " + ", ".join(hit[:3]))

    if asks_private_details(text):
        points += 25
        reasons.append("Asks you to send or share private details (Aadhaar, PAN, card, PIN)")

    seen = set()
    for link in links:
        if link in seen:
            continue
        seen.add(link)
        l = link.lower()
        domain = clean_domain(link)

        # Real, well-known websites are not flagged by the link rules
        if is_trusted(domain):
            continue

        if is_shortener(domain):
            points += 20
            reasons.append(f"Shortened link hides the real site: {domain}")
        if any(domain.endswith(e) for e in BAD_ENDINGS):
            points += 25
            reasons.append(f"Risky link ending: {domain}")
        if "@" in l:
            points += 20
            reasons.append("Link contains '@' (a common trick)")
        if is_ip(domain):
            points += 25
            reasons.append("Link uses a raw IP address instead of a name")
        if domain.count("-") >= 2:
            points += 10
            reasons.append(f"Many hyphens in domain: {domain}")
        for b in BRANDS:
            if b in domain:
                points += 25
                reasons.append(f"Looks like it copies the brand '{b}': {domain}")
                break

        age = ages.get(domain)
        if age is not None:
            if age < 30:
                points += 30
                reasons.append(f"Website {domain} was registered only {age} days ago (brand new)")
            elif age < 90:
                points += 15
                reasons.append(f"Website {domain} is very young: registered {age} days ago")

    return points, reasons


# ------------------------------------------------------------------
# PART 3: the endpoint the website calls
# ------------------------------------------------------------------
@app.post("/analyze")
def analyze(msg: Message):
    text = msg.text.strip()
    if not text:
        return {"score": 0, "verdict": "Empty", "reasons": ["Please type or paste something."]}

    links = find_links(text)

    # Internet checks: where do short links really go? how old is each website?
    expanded, ages = run_online_checks(links)
    # Judge the REAL destination when we know it (a short link that expands
    # is replaced by the site it leads to); keep the short link if we could not expand it.
    all_links = [expanded.get(l, l) for l in links]

    sms_score = check_sms(text)                                       # from teammate 1
    url_score = max([check_url(l) for l in all_links]) if all_links else 0   # from teammate 2
    extra, reasons = rule_reasons(text, all_links, ages)

    for short, final in expanded.items():
        reasons.insert(0, f"Short link really goes to: {final[:80]}")

    # If every link goes to a known, trusted website and there are no pressure
    # words, trust the text model less (it often over-reacts to messages with links)
    low = text.lower()
    has_pressure = any(w in low for w in URGENT_WORDS)
    if all_links and all(is_trusted(clean_domain(l)) for l in all_links) and not has_pressure:
        sms_score = int(sms_score * 0.3)
        url_score = 0
        reasons.append("All links go to known, trusted websites")
    elif not all_links and not has_pressure and not asks_private_details(text) and not re.search(r"(?<!\d)(?:\+?91[\s-]?)?\d{10}(?!\d)", text):
        # A plain notice: nothing to click, no number to call, no pressure.
        # Scammers almost always want you to click, call or hurry.
        sms_score = int(sms_score * 0.6)
        extra = extra * 0.5
        reasons.append("No link, no phone number and no pressure words")

    # Combine everything into one score from 0 to 100
    score = max(sms_score, url_score) * 0.7 + extra * 1.0
    score = int(min(100, max(0, score)))

    if score >= 60:
        verdict = "Phishing"
    elif score >= 35:
        verdict = "Suspicious"
    else:
        verdict = "Safe"
        if not reasons:
            reasons.append("No warning signs found.")

    link_details = []
    for l in links:
        final = expanded.get(l)
        d = clean_domain(final or l)
        link_details.append({"link": l, "goes_to": final, "domain": d, "age_days": ages.get(d)})

    return {"score": score, "verdict": verdict, "reasons": reasons,
            "link_details": link_details,
            "details": {"sms_score": sms_score, "url_score": url_score, "links_found": links}}


@app.get("/")
def home():
    return FileResponse("index.html")
