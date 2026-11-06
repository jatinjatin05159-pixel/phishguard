import os
import re
import json
import time
import threading
import http.client
import urllib.request
from datetime import datetime, timezone
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin, urlencode

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
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/host/"   # list of known malware / phishing sites (abuse.ch)
URLHAUS_KEY = os.environ.get("URLHAUS_KEY", "")         # free key from auth.abuse.ch; no key = this check is skipped
TRANCO_URL = "https://tranco-list.eu/api/ranks/domain/" # rank of a website among the world's top 1,000,000


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


# ---- Feature: known-bad list (URLhaus) ----------------------------
# URLhaus (abuse.ch) keeps a daily-updated list of websites that spread malware or phishing.
# We only ASK the list about the website name. We never visit the website.
_urlhaus_cache = {}


def urlhaus_check(host):
    """None = could not check (no key / no internet), False = not listed,
    dict = listed: {'urls': how many bad pages, 'online': how many still live, 'threat': type}."""
    if not URLHAUS_KEY:
        return None
    if host in _urlhaus_cache:
        return _urlhaus_cache[host]
    try:
        req = urllib.request.Request(
            URLHAUS_URL, data=urlencode({"host": host}).encode(),
            headers={"Auth-Key": URLHAUS_KEY, "User-Agent": "Mozilla/5.0 PhishGuard"})
        with urllib.request.urlopen(req, timeout=ONLINE_TIMEOUT) as r:
            data = json.loads(r.read().decode("utf-8", "ignore"))
    except Exception:
        return None
    status = data.get("query_status")
    if status == "ok":
        urls = data.get("urls") or []
        n = int(data.get("url_count") or len(urls) or 0)
        result = ({"urls": n,
                   "online": sum(1 for u in urls if u.get("url_status") == "online"),
                   "threat": next((u.get("threat") for u in urls if u.get("threat")), "malicious")}
                  if n > 0 else False)
    elif status in ("no_results", "invalid_host"):
        result = False
    else:
        return None
    _urlhaus_cache[host] = result
    return result


# ---- Feature: top-sites rank (Tranco) ------------------------------
# Tranco is a research list of the 1,000,000 most visited websites. Famous sites are
# rarely scam sites, so a high rank LOWERS the risk. It never makes a message "safe" by itself.
_tranco_cache = {}
_tranco_lock = threading.Lock()
_tranco_last = [0.0]
FREE_HOSTS = {  # popular, but anyone can make a page there, so rank proves nothing
    "blogspot.com", "weebly.com", "wixsite.com", "github.io", "web.app", "firebaseapp.com",
    "pages.dev", "netlify.app", "vercel.app", "herokuapp.com", "000webhostapp.com",
    "sites.google.com", "forms.gle", "glitch.me", "repl.co", "workers.dev", "carrd.co",
    "wordpress.com", "medium.com", "notion.site", "godaddysites.com", "myshopify.com"}


def tranco_rank(domain):
    """None = unknown, 0 = not in the top million, otherwise the rank (1 = most popular)."""
    rd = registrable_domain(domain)
    if rd in _tranco_cache:
        return _tranco_cache[rd]
    with _tranco_lock:                       # Tranco allows 1 request per second
        wait = 1.05 - (time.time() - _tranco_last[0])
        if wait > 0:
            time.sleep(wait)
        _tranco_last[0] = time.time()
        try:
            req = urllib.request.Request(TRANCO_URL + rd, headers={"User-Agent": "Mozilla/5.0 PhishGuard"})
            with urllib.request.urlopen(req, timeout=ONLINE_TIMEOUT) as r:
                data = json.loads(r.read().decode("utf-8", "ignore"))
        except Exception:
            return None
    ranks = [x.get("rank") for x in (data.get("ranks") or []) if x.get("rank")]
    result = min(ranks) if ranks else 0
    _tranco_cache[rd] = result
    return result


def is_popular(domain, ranks):
    r = ranks.get(domain)
    return bool(r) and r <= 1_000_000 and registrable_domain(domain) not in FREE_HOSTS and not is_shortener(domain)


def run_online_checks(links):
    """Runs the internet checks in parallel, with a time limit, and never raises.
    Returns (expanded, ages, listed, ranks):
      expanded[short_link] = final url, ages[domain] = days old,
      listed[domain] = URLhaus info, ranks[domain] = top-million rank (0 = not ranked)."""
    expanded, ages, listed, ranks = {}, {}, {}, {}
    if not ONLINE_CHECKS or not links:
        return expanded, ages, listed, ranks
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
        # 2) for every real (non-short, non-trusted, non-IP) website: age, known-bad list, rank
        domains = []
        for l in list(links) + list(expanded.values()):
            d = clean_domain(l)
            if d and not is_shortener(d) and not is_trusted(d) and not is_ip(d) and d not in domains:
                domains.append(d)
        domains = domains[:5]
        afuts = {d: ex.submit(domain_age_days, d) for d in domains}
        ufuts = {d: ex.submit(urlhaus_check, d) for d in domains}
        rfuts = {d: ex.submit(tranco_rank, d) for d in domains}
        for store, futs2, wait in ((ages, afuts, ONLINE_TIMEOUT * 2), (listed, ufuts, ONLINE_TIMEOUT * 2),
                                   (ranks, rfuts, ONLINE_TIMEOUT * 2 + 5)):
            for d, f in futs2.items():
                try:
                    v = f.result(timeout=wait)
                    if v is not None:
                        store[d] = v
                except Exception:
                    pass
    except Exception:
        pass
    finally:
        ex.shutdown(wait=False)
    return expanded, ages, listed, ranks


PRIVATE_THINGS = r"(aadhaar|aadhar|\bpan\b|cvv|card number|card details|account number|bank details|password|\bpin\b)"
ASK_VERBS = r"(shar\w*|send\w*|reply|provide|enter|give|bhej\w*|bata\w*)"


def asks_private_details(text):
    """True if the message asks you to send/share Aadhaar, PAN, card, PIN, etc.
    Warnings like 'Do not share your PIN' are ignored."""
    low = re.sub(r"\b(do not|don't|dont|never|not to)\s+(share|disclose|give|send|reveal)\b", " ", text.lower())
    low = re.sub(r"(?:https?://|www\.)\S+", " ", low)
    return bool(re.search(ASK_VERBS + r".{0,50}" + PRIVATE_THINGS, low) or
                re.search(PRIVATE_THINGS + r".{0,60}" + ASK_VERBS, low))


OTP_WORDS = r"(\botp\b|one[- ]time (password|pin|code)|verification code)"
OTP_VERBS = r"(shar\w*|send\w*|reply|provide|give|bhej\w*|bata\w*|tell|read out|forward)"


def asks_otp(text):
    """True if the message asks you to hand over an OTP. 'Do not share your OTP' warnings are ignored,
    and so are delivery OTPs ('share the OTP with the delivery agent')."""
    low = re.sub(r"(?:https?://|www\.)\S+", " ", text.lower())
    low = re.sub(r"\b(do not|don't|dont|never|not to)\s+(share|disclose|give|send|reveal|tell)\b", " ", low)
    if re.search(r"deliver\w*|at the time of", low):
        return False
    return bool(re.search(OTP_VERBS + r".{0,40}" + OTP_WORDS, low) or re.search(OTP_WORDS + r".{0,40}" + OTP_VERBS, low))


# ------------------------------------------------------------------
# PART 2b: the two scam families named in the problem statement:
#   "digital arrest" scams and malicious (fake / remote-access) apps.
# ------------------------------------------------------------------
# Warnings written to HELP people ("Beware of digital arrest scams...") must not be flagged.
AWARENESS = (r"\b(beware|advisory|awareness|be alert|stay alert|stay safe|safety (tip|message)|cyber safety|"
             r"scam alert|fraud alert|cautions?( the)? public|warns?|will never|never (ask|call|arrest|install|share|send|allow)|"
             r"do not fall for|don'?t fall for|is a (scam|fraud)|it is a (scam|fraud)|fraudsters|frauds)\b")

# 4 signals of a digital-arrest scam (each alone is weak, together they are a strong sign)
DA_AUTHORITY = (r"(\bcbi\b|enforcement directorate|\bed officer\b|cyber ?(crime|police|cell)|crime branch|narcotics|\bncb\b|"
                r"\btrai\b|supreme court|high court|police|inspector|\bdcp\b|customs|income tax (department|officer)|"
                r"\bjudge\b|telecom (department|authority)|court (order|summons|notice)|giraftari)")
DA_THREAT = (r"(arrest|warrant|\bfir\b|money laundering|hawala|illegal|\bdrugs?\b|mdma|narcotics|seized|caught at customs|"
             r"legal action|prosecution|\bjail\b|custody|suspicious (transfer|activit)|under investigation|criminal|"
             r"case (is |has been )?(registered|filed)|complaints?|terror|trafficking|blacklisted|"
             r"number will be (blocked|disconnected|deactivated)|giraftar)")
DA_CONTROL = (r"(digital arrest|digital custody|video call|skype|\bzoom\b|whatsapp video|do not disconnect|don'?t disconnect|"
              r"do not hang up|stay on (the |this )?(call|line|video)|remain on (the |this )?(video )?call|"
              r"(leave|keep) (your |the )?camera|don'?t tell|do not tell|tell no one|do not inform|kisi ko na bata|"
              r"keep (this )?(matter |call )?(confidential|secret)|do not discuss|don'?t discuss)")
DA_PAY = (r"(safe account|rbi (protected |safe |verification )?account|verification account|government account|"
          r"security deposit|\bbail\b|settlement|settle the case|clearance (fee|charge)|"
          r"transfer (your |all )?(savings|balance|funds|money)|deposit all|pay (the )?(fine|penalty)|fine of rs|"
          r"penalty of rs|share your (bank|account))")

REMOTE_TOOLS = r"(anydesk|any desk|teamviewer|team viewer|quick ?support|rustdesk|airdroid|aweray|ammyy|alpemix)"
APP_BAIT = (r"\b(reward|claim|kyc|update|verify|challan|kisan|yojana|bill|cashback|loan|offer|refund|subsidy|"
            r"aadhaar|pan|free|lucky|earn|win|gold|invest|tracking|parcel)\b")
OFFER_BAIT = (r"((earn|income|make)\W+(rs\.?|inr)?\W*\d[\d,]*.{0,40}(per day|daily|a day|per week|weekly)|"
              r"work from home|part.?time job|liking .{0,20}videos|like .{0,20}videos|"
              r"telegram (channel|group)|registration fee|refundable (registration|security|fee)|"
              r"guaranteed (profit|return)|(double|triple) your money)")
APP_STORES = ("play.google.com", "apps.apple.com", "play store", "app store")


def special_rules(text, links):
    """Looks for digital-arrest scams and malicious-app tricks.
    Returns (points, reasons, flags) where flags = {'digital_arrest': bool, 'malicious_app': bool}."""
    full = text.lower()
    low = re.sub(r"(?:https?://|www\.)\S+", " ", full)
    untrusted_link = any(not is_trusted(clean_domain(l)) for l in links)
    aware = bool(re.search(AWARENESS, low)) and not untrusted_link and not asks_private_details(text)
    points, reasons, flags = 0, [], {"digital_arrest": False, "malicious_app": False, "aware": False}
    if aware:
        flags["aware"] = True
        return 0, ["This looks like a safety warning, not a scam message"], flags

    # ---- digital arrest ----
    a, t = bool(re.search(DA_AUTHORITY, low)), bool(re.search(DA_THREAT, low))
    c, p = bool(re.search(DA_CONTROL, low)), bool(re.search(DA_PAY, low))
    literal = "digital arrest" in low or "digital custody" in low
    da = 70 if literal else 0
    if (c or (a and t)) and (a + t + c + p) >= 2:
        da = max(da, 15 * a + 20 * t + 25 * c + 25 * p)
    if da:
        parts = []
        if a:
            parts.append("claims to be police, CBI, customs, TRAI or a court")
        if t:
            parts.append("threatens arrest, a case or blocking")
        if c:
            parts.append("tells you to stay on a video call or keep it secret")
        if p:
            parts.append("asks you to move money for 'verification', a 'safe account' or a fine")
        reasons.append("Digital-arrest scam pattern: " + ("; ".join(parts) if parts else "mentions 'digital arrest'"))
        reasons.append("Real police, CBI or courts never arrest anyone over a video call, and never ask for money to close a case")
        points += da
        flags["digital_arrest"] = True

    # ---- malicious apps ----
    ma_reasons = []
    ma = 0
    if re.search(r"\bapk\b", full):
        ma += 45
        ma_reasons.append("Asks you to install an .apk file: an Android app from outside the Play Store, a common way to steal OTPs and money")
    if re.search(REMOTE_TOOLS, full):
        ma += 45
        ma_reasons.append("Asks you to install a remote-control app (AnyDesk, TeamViewer, etc.): this lets a stranger see and control your phone")
    store_link = any(s in full for s in APP_STORES)
    if (not store_link and re.search(r"\b(install|download)\w*\b.{0,60}\b(app|application)\b", low)
            and re.search(APP_BAIT, low)):
        ma += 25
        ma_reasons.append("Pushes you to install an app to claim, update or verify something")
    if re.search(r"\b(allow|grant|enable|give)\b.{0,40}\b(accessibility|screen overlay|overlay|contacts|gallery|sms|screen shar\w*|all permissions)", low):
        ma += 20
        ma_reasons.append("Asks for risky app permissions (contacts, SMS, screen access)")
    if ma:
        reasons.extend(ma_reasons)
        points += ma
        flags["malicious_app"] = True

    # ---- too-good-to-be-true money offers (fake jobs, tasks, investments) ----
    if re.search(OFFER_BAIT, low):
        points += 30
        reasons.append("Too-good-to-be-true money offer (easy daily income, fees for a job, or guaranteed returns)")
    return points, reasons, flags


# ------------------------------------------------------------------
# PART 2c: scam type + plain-words advice ("what to do next")
# ------------------------------------------------------------------
SCAM_TYPES = {
    "digital_arrest": ("Digital arrest scam",
        "Fraudsters pose as police, CBI, customs or TRAI, say you are linked to a crime, and keep you on a video call until you transfer money.",
        ["Hang up. Do not stay on the call and do not switch on your camera.",
         "Do not send any money. Real police, CBI or courts never ask for money to close a case.",
         "India has no 'digital arrest'. Nobody can arrest you over a video call.",
         "Tell a family member or friend right now. Scammers need you to keep it secret."]),
    "malicious_app": ("Fake app / remote-access scam",
        "You are pushed to install an app (an .apk file, or AnyDesk / TeamViewer) that reads your OTPs or controls your phone.",
        ["Do not install it. Install apps only from the official Play Store or App Store.",
         "Never install screen-sharing apps like AnyDesk or TeamViewer for someone who called you.",
         "If you already installed it: uninstall it, turn on airplane mode, call your bank and change your passwords."]),
    "upi_collect": ("UPI collect-request scam",
        "Scammers say you will RECEIVE money, but the request actually makes you PAY. Entering a UPI PIN only ever sends money out.",
        ["Never enter your UPI PIN to receive money.",
         "Read every request carefully: it must say you will receive, not pay."]),
    "electricity": ("Fake electricity-bill scam",
        "A message says your power will be cut tonight unless you pay or call. Electricity boards do not threaten cuts by SMS from random numbers.",
        ["Do not call the number or tap the link.",
         "Check your bill in your electricity board's official app or website."]),
    "fastag": ("Fake FASTag / KYC scam",
        "A message says your FASTag or wallet is blocked and sends you to a fake page.",
        ["Do not tap the link. Check your balance in the official bank or FASTag app."]),
    "courier": ("Fake courier / customs scam",
        "A message says a parcel is stuck and asks for a small fee, which gives the scammer your card details.",
        ["Do not pay. Track your parcel on the official courier app or website.",
         "Customs and courier firms do not collect fees through random links."]),
    "job": ("Fake job or investment scam",
        "Easy money for liking videos, or a job that needs a fee first. You pay and the money never comes back.",
        ["Never pay a fee to get a job or a task.",
         "No honest investment guarantees fast, huge returns."]),
    "prize": ("Fake lottery / prize scam",
        "You are told you won something you never entered. The catch is a fee or your bank details.",
        ["You cannot win a lottery you did not enter. Do not pay any fee."]),
    "refund": ("Fake refund / cashback scam",
        "A refund or cashback is offered, and you are asked to click or enter details to 'receive' it.",
        ["Real refunds go to your account without you entering a PIN or OTP.",
         "Check refund status only on the official website or app."]),
    "bank_kyc": ("Fake bank / KYC scam",
        "A message says your account or card will be blocked unless you update KYC, PAN or details on a fake page.",
        ["Banks do not ask you to update KYC through SMS links.",
         "Open your bank's official app yourself, or call the number printed on your card."]),
    "generic": ("Phishing message",
        "Phishing messages try to rush you into clicking a link or sharing private details.",
        ["Do not tap the link or reply.",
         "Contact the company using its official app or the number on your card."]),
}

TYPE_PATTERNS = [
    ("upi_collect", r"(collect request|upi pin|scan this qr|scan the qr)"),
    ("electricity", r"(electricity|bijli|power (will be )?(cut|disconnect)|bescom|connection (will be )?(cut|disconnect)|kat jayega)"),
    ("fastag", r"fastag"),
    ("courier", r"(parcel|courier|customs (fee|duty)|redelivery|delivery fee|indiapost|india post|fedex|\bdhl\b|blue ?dart|address (is )?incomplete)"),
    ("job", r"(part.?time|work from home|earn rs|per day|telegram|registration fee|security fee|offer letter|invest|guaranteed|returns)"),
    ("prize", r"(lottery|lucky draw|prize|you have won|you won|inaam|\bkbc\b|winner)"),
    ("refund", r"(refund|cashback|subsidy)"),
    ("bank_kyc", r"(kyc|\bpan\b|net ?banking|aadhaar|account.{0,20}(blocked|suspended|restricted)|card.{0,20}blocked|bank account|\bsim\b)"),
]


def classify_scam(text, flags):
    if flags["digital_arrest"]:
        return "digital_arrest"
    if flags["malicious_app"]:
        return "malicious_app"
    low = re.sub(r"(?:https?://|www\.)\S+", " ", text.lower())
    for key, pat in TYPE_PATTERNS:
        if re.search(pat, low):
            return key
    return "generic"


TXN_ALERT = (r"(debited|credited|spent on|a/c|\bxx\d{3,4}\b|ending \d{4}|card ending|upi ref|txn|avl\.? bal|available balance)")
COMMON_STEPS = ["Never share your OTP, PIN, CVV or Aadhaar with anyone, even someone who says they are from your bank."]
REPORT = {"helpline": "1930", "portal": "cybercrime.gov.in",
          "text": "Lost money or been threatened? Call 1930 (National Cyber Crime Helpline) right away, or report at cybercrime.gov.in. The sooner you report, the better the chance of freezing the money."}


def build_advice(verdict, type_key):
    """Returns (scam_type dict or None, list of what-to-do steps, report dict or None)."""
    if verdict == "Safe":
        return (None,
                ["Nothing alarming found, but no tool is perfect. If something still feels wrong, trust that feeling.",
                 "If unsure, open the official app yourself or call the number printed on your card.",
                 COMMON_STEPS[0]],
                None)
    name, what, steps = SCAM_TYPES[type_key]
    lead = ["Do not tap any link, reply or call back."] if verdict == "Phishing" else \
           ["Do not tap links or call numbers in this message until you have checked it another way."]
    if type_key in ("digital_arrest", "malicious_app"):
        lead = []
    return ({"key": type_key, "name": name, "what": what}, lead + steps + COMMON_STEPS, REPORT)


def rule_reasons(text, links=None, ages=None, listed=None, ranks=None):
    """Returns (extra_points, list_of_reasons)."""
    if links is None:
        links = find_links(text)
    ages, listed, ranks = ages or {}, listed or {}, ranks or {}
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
    elif asks_otp(text):
        points += 25
        reasons.append("Asks you to share your OTP")

    seen = set()
    said_popular = False
    for link in links:
        if link in seen:
            continue
        seen.add(link)
        l = link.lower()
        domain = clean_domain(link)

        # Known-bad list: strongest evidence we have
        info = listed.get(domain)
        if info:
            points += 60
            reasons.append(f"{domain} is on the URLhaus list of known {str(info.get('threat', 'malicious')).replace('_', ' ')} sites"
                           + (" (still live)" if info.get("online") else ""))

        # Real, well-known websites are not flagged by the link rules
        if is_trusted(domain):
            continue
        if not info and is_popular(domain, ranks):
            if not said_popular:
                reasons.append(f"{domain} is a very popular website (top {ranks[domain]:,} in the world), which lowers the risk")
                said_popular = True
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
# PART 2d: evidence for the website. Every warning sign comes with the exact words in the
# message that caused it (so the page can underline them), a plain explanation,
# a per-link tick-list, and six numbers for the radar chart.
# ------------------------------------------------------------------
LINK_RE = r"(?:https?://|www\.)\S+"
BRAND_INFO = {
    "sbi": ("SBI", "onlinesbi.sbi or sbi.co.in"), "hdfc": ("HDFC Bank", "hdfcbank.com"),
    "icici": ("ICICI Bank", "icicibank.com"), "axis": ("Axis Bank", "axisbank.com"),
    "paytm": ("Paytm", "paytm.com"), "phonepe": ("PhonePe", "phonepe.com"),
    "gpay": ("Google Pay", "pay.google.com"), "amazon": ("Amazon", "amazon.in"),
    "flipkart": ("Flipkart", "flipkart.com"), "netflix": ("Netflix", "netflix.com"),
    "airtel": ("Airtel", "airtel.in"), "jio": ("Jio", "jio.com"), "irctc": ("IRCTC", "irctc.co.in"),
    "uidai": ("UIDAI (Aadhaar)", "uidai.gov.in"), "aadhaar": ("UIDAI (Aadhaar)", "uidai.gov.in"),
}
AXES = ["wording", "links", "pressure", "impersonation", "asks", "online"]


def link_spans(text):
    """[(start, end, link)] for every link, matching find_links() (trailing punctuation removed)."""
    out = []
    for m in re.finditer(LINK_RE, text, flags=re.I):
        raw = m.group()
        link = raw.rstrip(".,;)!\"'")
        out.append((m.start(), m.start() + len(link), link))
    return out


def _spans(pattern, s, limit=6):
    return [[m.start(), m.end()] for m in re.finditer(pattern, s, flags=re.I) if m.end() > m.start()][:limit]


def _sig(sid, axis, severity, label, detail, spans=None, weight=0):
    return {"id": sid, "axis": axis, "severity": severity, "label": label, "detail": detail,
            "spans": spans or [], "weight": weight}


def collect_signals(text, links, all_links, expanded, ages, listed, ranks, flags, final_sms, final_url, txn_ok):
    """Builds the list of warning signs (and good signs) shown on the website."""
    sigs = []
    masked = re.sub(LINK_RE, lambda m: " " * len(m.group()), text)       # same length, links blanked out
    low = masked.lower()

    if flags.get("aware"):
        sigs.append(_sig("aware", "wording", "good", "Looks like a safety warning",
                         "It warns people about scams instead of trying to trick them.", _spans(AWARENESS, masked)))
    elif txn_ok:
        sigs.append(_sig("txn", "wording", "good", "Looks like a normal bank or payment alert",
                         "No link and no mobile number to call, only the usual details of a transaction."))

    # --- pressure, money words ---
    hit = [w for w in URGENT_WORDS if w in low]
    if hit:
        sigs.append(_sig("pressure", "pressure", "medium", "Pressure and deadline words",
                         "Scammers rush you so you do not think. Words used: " + ", ".join(hit[:4]) + ".",
                         _spans("|".join(re.escape(w) for w in hit), masked), 30))
    hit = [w for w in MONEY_WORDS if w in low]
    if hit and not flags.get("aware"):
        sigs.append(_sig("money", "asks", "low", "Money or account words",
                         "Mentions " + ", ".join(hit[:4]) + ". Common in real messages too, so this is a small clue.",
                         _spans("|".join(r"\b" + re.escape(w) + r"\b" for w in hit), masked), 15))

    # --- private details / OTP ---
    if asks_private_details(text):
        neutral = re.sub(r"\b(do not|don't|dont|never|not to)\s+(share|disclose|give|send|reveal)\b",
                         lambda m: " " * len(m.group()), masked, flags=re.I)
        sp = []
        for pat in (ASK_VERBS + r".{0,50}" + PRIVATE_THINGS, PRIVATE_THINGS + r".{0,60}" + ASK_VERBS):
            for m in re.finditer(pat, neutral, flags=re.I):
                sp += [[x.start() + m.start(), x.end() + m.start()] for x in re.finditer(PRIVATE_THINGS, m.group(), flags=re.I)]
        sigs.append(_sig("private", "asks", "high", "Asks for your private details",
                         "No bank or government office asks you to send Aadhaar, PAN, card numbers or PINs by message.", sp[:6], 25))
    elif asks_otp(text):
        sigs.append(_sig("otp", "asks", "high", "Asks you to share your OTP",
                         "An OTP is a key to your money. Real banks say it again and again: never share it, not even with their staff.",
                         _spans(OTP_WORDS, masked), 25))

    # --- digital arrest ---
    if flags.get("digital_arrest"):
        a, t = re.search(DA_AUTHORITY, low), re.search(DA_THREAT, low)
        c, p = re.search(DA_CONTROL, low), re.search(DA_PAY, low)
        if "digital arrest" in low or "digital custody" in low:
            sigs.append(_sig("da_literal", "impersonation", "high", "Says 'digital arrest'",
                             "There is no such thing in Indian law. Nobody can arrest you through a phone or video call.",
                             _spans(r"digital (arrest|custody)", masked), 70))
        if a:
            sigs.append(_sig("da_auth", "impersonation", "high", "Claims to be police, CBI, customs, TRAI or a court",
                             "Real agencies send written notices to your address. They do not scare you over WhatsApp, Skype or a call.",
                             _spans(DA_AUTHORITY, masked), 15))
        if t:
            sigs.append(_sig("da_threat", "pressure", "high", "Threatens arrest, a case or blocking",
                             "Fear is the scammer's main tool. It is meant to make you panic and obey.",
                             _spans(DA_THREAT, masked), 20))
        if c:
            sigs.append(_sig("da_control", "pressure", "high", "Tells you to stay on the call or keep it secret",
                             "Scammers cut you off from family so nobody can tell you it is a scam.",
                             _spans(DA_CONTROL, masked), 25))
        if p:
            sigs.append(_sig("da_pay", "asks", "high", "Asks you to move money or pay a fine",
                             "No police, CBI or court asks you to transfer money to a 'safe account' or to close a case.",
                             _spans(DA_PAY, masked), 25))

    # --- malicious apps (links count here, so use the original text) ---
    if flags.get("malicious_app"):
        full = text
        if re.search(r"\bapk\b", full, flags=re.I):
            sigs.append(_sig("apk", "asks", "high", "Asks you to install an .apk file",
                             "An .apk from a link is an Android app from outside the Play Store. These steal OTPs and empty bank accounts.",
                             _spans(r"\S*\bapk\b\S*", full), 45))
        if re.search(REMOTE_TOOLS, full, flags=re.I):
            sigs.append(_sig("remote", "asks", "high", "Asks you to install a remote-control app",
                             "Apps like AnyDesk and TeamViewer let a stranger see and control your phone, including your banking apps.",
                             _spans(REMOTE_TOOLS, full), 45))
        if re.search(r"\b(install|download)\w*\b.{0,60}\b(app|application)\b", low, flags=re.I) and not any(s in text.lower() for s in APP_STORES) and re.search(APP_BAIT, low):
            sigs.append(_sig("appbait", "asks", "medium", "Pushes you to install an app to claim or update something",
                             "Real banks and offices do not send you an app to install through a message.",
                             _spans(r"\b(install|download)\w*\b.{0,60}\b(app|application)\b", masked), 25))
        if re.search(r"\b(allow|grant|enable|give)\b.{0,40}\b(accessibility|screen overlay|overlay|contacts|gallery|sms|screen shar\w*|all permissions)", low):
            sigs.append(_sig("perm", "asks", "medium", "Asks for risky app permissions",
                             "Access to your SMS, contacts or screen lets a bad app read OTPs and spy on you.",
                             _spans(r"\b(allow|grant|enable|give)\b.{0,40}\b(accessibility|screen overlay|overlay|contacts|gallery|sms|screen shar\w*|all permissions)", masked), 20))

    # --- too good to be true ---
    if re.search(OFFER_BAIT, low) and not flags.get("aware"):
        sigs.append(_sig("offer", "asks", "medium", "Too-good-to-be-true money offer",
                         "Easy daily income, fees for a job, or guaranteed returns are classic scam hooks.",
                         _spans(OFFER_BAIT, masked), 30))

    # --- links ---
    ls = link_spans(text)
    for i, orig in enumerate(links):
        span = [[ls[i][0], ls[i][1]]] if i < len(ls) else []
        final = all_links[i] if i < len(all_links) else orig
        d = clean_domain(final)
        l = final.lower()
        info = listed.get(d)
        if info:
            sigs.append(_sig(f"l{i}_bad", "online", "high", "Website is on a known-bad list",
                             f"{d} is on the URLhaus list of {str(info.get('threat', 'malicious')).replace('_', ' ')} sites"
                             + (" and is still live." if info.get("online") else "."), span, 60))
        if is_trusted(d):
            sigs.append(_sig(f"l{i}_ok", "links", "good", "Link goes to a known, official website", d, span))
            continue
        if not info and is_popular(d, ranks):
            sigs.append(_sig(f"l{i}_pop", "links", "good", "Very popular website",
                             f"{d} is in the world's top {ranks[d]:,} most visited sites, which lowers the risk.", span))
            continue
        if is_shortener(d):
            sigs.append(_sig(f"l{i}_short", "links", "medium", "Short link hides the real website",
                             "Scammers use short links so you cannot see where they lead.", span, 20))
        if any(d.endswith(e) for e in BAD_ENDINGS):
            end = next(e for e in BAD_ENDINGS if d.endswith(e))
            sigs.append(_sig(f"l{i}_tld", "links", "medium", f"Cheap '{end}' website ending",
                             "Endings like this cost almost nothing and are very common in scam links.", span, 25))
        if "@" in l:
            sigs.append(_sig(f"l{i}_at", "links", "medium", "Link contains '@'",
                             "Everything before the @ is ignored by the browser. It is a trick to hide the real site.", span, 20))
        if is_ip(d):
            sigs.append(_sig(f"l{i}_ip", "links", "medium", "Link uses a number instead of a name",
                             "Real companies use their name, not a raw IP address.", span, 25))
        if d.count("-") >= 2:
            sigs.append(_sig(f"l{i}_hy", "links", "low", "Many hyphens in the website name",
                             "Long hyphenated names like bank-kyc-update are a common trick.", span, 10))
        for b in BRANDS:
            if b in d:
                name, real = BRAND_INFO.get(b, (b.upper(), "its official website"))
                sigs.append(_sig(f"l{i}_brand", "impersonation", "high", f"Link pretends to be {name}",
                                 f"The real address is {real}. This one is {d}.", span, 25))
                break
        age = ages.get(d)
        if age is not None and age < 90:
            sigs.append(_sig(f"l{i}_age", "online", "high" if age < 30 else "medium",
                             "Website was registered very recently",
                             f"{d} was created only {age} days ago. Real banks and shops have been online for years.",
                             span, 30 if age < 30 else 15))
    return sigs


def radar_values(sigs, final_sms, final_url):
    vals = {a: 0 for a in AXES}
    for s in sigs:
        if s["severity"] != "good":
            vals[s["axis"]] += s["weight"]
    vals["wording"] = max(final_sms, 0)
    vals["links"] = max(vals["links"], final_url)
    return {a: int(min(100, v)) for a, v in vals.items()}


def link_check_rows(links, all_links, expanded, ages, listed, ranks):
    """One tick-list per link. ok: True = good, False = bad, None = could not check."""
    out = []
    for i, orig in enumerate(links):
        final = all_links[i] if i < len(all_links) else orig
        d = clean_domain(final)
        rows = []
        if orig in expanded:
            rows.append({"ok": False, "text": f"Short link. It really goes to {expanded[orig][:70]}"})
        elif is_shortener(clean_domain(orig)):
            rows.append({"ok": None, "text": "Short link. Where it leads could not be checked right now"})
        if is_trusted(d):
            rows.append({"ok": True, "text": f"{d} is an official, known website"})
        else:
            for b in BRANDS:
                if b in d:
                    name, real = BRAND_INFO.get(b, (b.upper(), "its official website"))
                    rows.append({"ok": False, "text": f"Not {real}, which is {name}'s real address"})
                    break
            end = next((e for e in BAD_ENDINGS if d.endswith(e)), None)
            if end:
                rows.append({"ok": False, "text": f"Uses a cheap '{end}' ending that scammers love"})
            if is_ip(d):
                rows.append({"ok": False, "text": "Uses a number instead of a website name"})
            if "@" in final:
                rows.append({"ok": False, "text": "Contains '@', a trick to hide the real website"})
            if not is_ip(d):
                age = ages.get(d)
                if age is None:
                    rows.append({"ok": None, "text": "Website age: not available (online check off or timed out)"})
                elif age < 90:
                    rows.append({"ok": False, "text": f"Registered only {age} days ago"})
                else:
                    yrs = age // 365
                    rows.append({"ok": True, "text": f"Registered {yrs} years ago" if yrs >= 1 else f"Registered {age} days ago"})
                if d in listed:
                    rows.append({"ok": False, "text": "On the URLhaus known-bad list"} if listed[d]
                                else {"ok": True, "text": "Not on the URLhaus known-bad list"})
                else:
                    rows.append({"ok": None, "text": "Known-bad list (URLhaus): not checked" +
                                 ("" if URLHAUS_KEY else " (no key set)")})
                r = ranks.get(d)
                if r:
                    rows.append({"ok": True, "text": f"Among the top {r:,} most visited websites"})
                elif r == 0:
                    rows.append({"ok": None, "text": "Not in the top 1,000,000 websites (most scam sites are not either)"})
        out.append({"link": orig, "domain": d, "rows": rows})
    return out


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
    # is it on the known-bad list? is it a top-million site?
    expanded, ages, listed, ranks = run_online_checks(links)
    # Judge the REAL destination when we know it (a short link that expands
    # is replaced by the site it leads to); keep the short link if we could not expand it.
    all_links = [expanded.get(l, l) for l in links]

    sms_score = check_sms(text)                                       # from teammate 1
    url_score = max([check_url(l) for l in all_links]) if all_links else 0   # from teammate 2
    extra, reasons = rule_reasons(text, all_links, ages, listed, ranks)
    sp_points, sp_reasons, flags = special_rules(text, all_links)
    extra += sp_points
    reasons = sp_reasons + reasons

    for short, final in expanded.items():
        reasons.insert(0, f"Short link really goes to: {final[:80]}")

    # If every link goes to a known, trusted (or very popular) website and there are no
    # pressure words, trust the text model less (it often over-reacts to messages with links)
    low = text.lower()
    has_pressure = any(w in low for w in URGENT_WORDS)
    known_good = lambda d: is_trusted(d) or (is_popular(d, ranks) and not listed.get(d))
    if (all_links and all(known_good(clean_domain(l)) for l in all_links)
            and not has_pressure and not sp_points):
        sms_score = int(sms_score * 0.3)
        url_score = 0
        reasons.append("All links go to known, trusted websites")
    elif (not all_links and not has_pressure and not sp_points and not (asks_private_details(text) or asks_otp(text))
          and not re.search(r"(?<!\d)(?:\+?91[\s-]?)?\d{10}(?!\d)", text)):
        # A plain notice: nothing to click, no number to call, no pressure.
        # Scammers almost always want you to click, call or hurry.
        sms_score = int(sms_score * 0.6)
        extra = extra * 0.5
        reasons.append("No link, no phone number and no pressure words")

    # Real bank alerts ("Rs 640 spent on card ending 7788 ... not you? call 1800...") use the same
    # urgent words as scams. Real ones have no link and no mobile number (only toll-free numbers).
    txn_ok = False
    if (re.search(TXN_ALERT, low) and not all_links and not sp_points and not (asks_private_details(text) or asks_otp(text))
            and not re.search(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{9}(?!\d)", text)):
        txn_ok = True
        sms_score = int(sms_score * 0.4)
        extra = extra * 0.4
        reasons.append("Looks like a normal bank or payment alert: no link and no mobile number to call")
    # Safety warnings that HELP people ("Beware of digital arrest...") should not scare the text model
    if flags.get("aware"):
        sms_score = int(sms_score * 0.4)

    # Combine everything into one score from 0 to 100
    score = max(sms_score, url_score) * 0.7 + extra * 1.0
    if any(v and v.get("online") for v in listed.values()):
        score = max(score, 85)        # a live page on the known-bad list is near-certain
    score = int(min(100, max(0, score)))

    if score >= 60:
        verdict = "Phishing"
    elif score >= 35:
        verdict = "Suspicious"
    else:
        verdict = "Safe"
        if not reasons:
            reasons.append("No warning signs found.")

    scam_type, advice, report = build_advice(verdict, classify_scam(text, flags))
    signals = collect_signals(text, links, all_links, expanded, ages, listed, ranks, flags, sms_score, url_score, txn_ok)
    radar = radar_values(signals, sms_score, url_score)
    link_checks = link_check_rows(links, all_links, expanded, ages, listed, ranks)

    link_details = []
    for l in links:
        final = expanded.get(l)
        d = clean_domain(final or l)
        link_details.append({"link": l, "goes_to": final, "domain": d, "age_days": ages.get(d),
                             "rank": ranks.get(d), "listed": bool(listed.get(d)) if d in listed else None})

    return {"score": score, "verdict": verdict, "reasons": reasons,
            "scam_type": scam_type, "advice": advice, "report": report,
            "text": text, "signals": signals, "radar": radar, "link_checks": link_checks,
            "link_details": link_details,
            "details": {"sms_score": sms_score, "url_score": url_score, "links_found": links,
                        "special_points": sp_points, "urlhaus_enabled": bool(URLHAUS_KEY)}}


@app.get("/")
def home():
    return FileResponse("index.html")
