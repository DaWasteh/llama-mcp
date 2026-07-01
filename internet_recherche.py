"""
Sicherer Internet-Recherche MCP-Server fuer llama.cpp Web UI.

Erlaubte Quellen: DuckDuckGo, Wikipedia, arXiv, GESTI (BG BA)

Sicherheitsfeatures:
- Keine Executables, Downloads, Dateisystem-Zugriff
- Prompt-Injection-Schutz mit Unicode-Normalisierung (Homoglyph-Schutz)
- Strikte Limits (Max Tiefe, Max Seiten, Max Token)
- Nur HTTP GET, keine POST/PUT/DELETE
- Blockierte Domains und URL-Schemata
- Aktive DNS-Validierung pro Request (DNS-Rebinding-Schutz)
- Rate-Limiting pro Engine-Instanz
- Connection-IP-Verifikation nach DNS-Aufloesung

Sicherheitspatches (Mai 2026):
- [KRIT] Unicode-Normalisierung (NFKC) gegen Homoglyph-Bypass
- [KRIT] DNS-Validierung jetzt im Request-Pfad aktiv (war toter Code)
- [HOCH] RateLimiter jetzt aktiv eingebunden (war toter Code)
- [HOCH] Connection-IP-Check gegen DNS-Rebinding
- [HOCH] Thread-Lokalitaet konsequent durch get_engine() statt Modul-Engine
- [HOCH] Thread-safe _visited_urls/_page_count (Lock)
- [MITT] Mehr Prompt-Injection-Patterns (MCP/llama.cpp/Tokenizer-spezifisch)
- [MITT] HTML-Groessenlimit (200KB) vor BeautifulSoup-Parsing
- [MITT] arXiv-Endpoint von http auf https umgestellt
- [MITT] arXiv-ID Regex unterstuetzt nun auch alte ID-Form (cs/9904001)

Server-Split & Security-Haertung (Juli 2026):
- [SERVER] Eigenstaendiger Server (main()+Port 8766), kein Coupling mehr
- [KRIT] IP-Encoding-Erkennung (dezimal/hex/oktal) auf URL-Ebene, da
         getaddrinfo plattformabhaengig ist und solche Forme z.T. nicht aufloest
- [KRIT] Wikipedia/arXiv jetzt ueber SafeHttpClient (DNS-Rebinding, Size-
         und Content-Type-Checks) statt eigener ungeschuetzter httpx-Clients
- [HOCH] URL-Userinfo (http://user:pass@host) blockiert (Daten-Exfiltration)
- [HOCH] Erweiterte Blockliste: .onion/.i2p/.localhost, weitere Paste-/File-Hoster
- [HOCH] Content-Disposition: attachment mit gefaehrlicher Endung blockiert
"""

import contextlib
import html
import logging
import re
import socket
import sys
import threading
import unicodedata
from collections import deque
from dataclasses import dataclass
from ipaddress import IPv4Address, ip_address, ip_network
from time import time
from typing import TYPE_CHECKING
from urllib.parse import quote_plus, urljoin, urlparse

if TYPE_CHECKING:
    from collections.abc import Mapping

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as e:
    print(f"FEHLER: MCP SDK nicht installiert. ({e})", file=sys.stderr)
    raise

try:
    import httpx
    from bs4 import BeautifulSoup  # pyright: ignore[reportMissingImports]
    from duckduckgo_search import DDGS  # pyright: ignore[reportMissingImports]
except ImportError as e:
    print(f"FEHLER: Fehlende Abhaengigkeit: {e}", file=sys.stderr)
    raise

# Geteiltes Server-Bootstrap (CORS/Transport/uvicorn) - siehe server_common.py
from server_common import build_argparser, run_mcp_server

# ============================================================
# Logger
# ============================================================
logger = logging.getLogger("internet_recherche")


# ============================================================
# Konfiguration & Sicherheitslimits
# ============================================================

MAX_PAGES_PER_SEARCH = 15
MAX_FOLLOW_LINKS = 3
MAX_RESULT_LENGTH = 5000
MAX_SEARCH_RESULTS = 5
HTTP_TIMEOUT = 15
MAX_RESPONSE_SIZE = 500_000  # 500 KB
MAX_HTML_PARSE_SIZE = 200_000  # 200 KB - separate Grenze fuer BeautifulSoup
REQUESTS_PER_WINDOW = 30  # Rate Limiting: Anfragen pro Zeitfenster
WINDOW_SECONDS = 60  # Rate Limiting: Zeitfenster in Sekunden
DNS_CACHE_SECONDS = 30  # Wie lange ein bestaetigter Hostname als "frisch" gilt

ALLOWED_SCHEMAS = {"http", "https"}

# Geschuetzte IP-Netze (SSRF-Schutz)
_PROTECTED_NETWORKS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"),
    ip_network("0.0.0.0/8"),
    ip_network("100.64.0.0/10"),
    ip_network("::1/128"),  # IPv6 Loopback
    ip_network("fc00::/7"),  # IPv6 Unique Local
    ip_network("fe80::/10"),  # IPv6 Link-Local
]

# Blockierte Domains (Daten-Exfiltration, Code-Execution, ungefilterter Content)
BLOCKED_DOMAINS = {
    # Paste- / Text-Dumps (Prompt-Injection- & Exfil-Vektor)
    "pastebin.com", "gist.github.com", "gist.githubusercontent.com",
    "hastebin.com", "paste.ee", "0bin.net", "dpaste.com", "termbin.com",
    "0x0.st", "transfer.sh", "file.io", "temp.sh", "rentry.co", "rentry.org",
    "paste.rs", "ix.io", "sprunge.us", "dumpz.org", "paste.org.ru",
    "pastelink.net", "controlc.com", "paste.debian.net", "paste.centos.org",
    # Code-Hoster / Modell-Hoster (ungefilterte Scripts/Modelle)
    "raw.githubusercontent.com", "huggingface.co", "cdn.jsdelivr.net",
    "unpkg.com", "jsdelivr.net", "codepen.io",
}

# Blockierte Domain-Suffixes (internes Netzwerk / Darknet / reserviert)
BLOCKED_DOMAIN_SUFFIXES = (
    ".internal", ".local", ".private", ".corp", ".home", ".lan",
    ".onion", ".i2p", ".localhost",           # Darknet / Loopback-Hostname
    ".test", ".example", ".invalid",           # RFC 2606 reserviert
)

# Blockierte URL-Endungen (Downloads/Executables)
BLOCKED_EXTENSIONS = {
    ".exe", ".dll", ".so", ".msi", ".bat", ".cmd", ".ps1", ".sh", ".bash",
    ".zsh", ".com", ".scr", ".pif", ".vbs", ".js", ".jar", ".app", ".dmg",
    ".iso", ".img", ".py", ".pl", ".rb", ".php", ".bin", ".elf", ".out",
}

ALLOWED_SOURCES = {"duckduckgo", "wikipedia", "arxiv", "gesti"}


def _is_ipv4_literal(hostname: str) -> bool:
    """Prueft ob Hostname eine IPv4-Literal-Notation ist."""
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) is not None


def _decode_ip_hostname(hostname: str) -> str | None:
    """Erkennt nicht-dotted IPv4-Encodings und gibt dotted-Form zurueck.

    Deckt klassische SSRF-Bypass-Vektoren ab, die getaddrinfo je Plattform
    inkonsistent behandelt (Windows loest z.B. Integer-IPs NICHT auf):
      - Dezimal:   2130706433        -> 127.0.0.1
      - Hex:       0x7f000001        -> 127.0.0.1
      - Oktal:     0177.0.0.1        -> 127.0.0.1  (pro-Oktett oktal)
    Liefert None, wenn es keine gueltige codierte IPv4 ist.
    """
    h = hostname.lower()
    # Reine Dezimal- oder Hex-Integer (ohne Punkt)
    if h.isdigit() or (h.startswith("0x") and all(c in "0123456789abcdef" for c in h[2:])):
        try:
            base = 16 if h.startswith("0x") else 10
            n = int(h, base)
            if 0 <= n <= 0xFFFFFFFF:
                return str(IPv4Address(n))
        except ValueError:
            return None
        return None
    # Oktal-dotted: alle Oktetts numerisch, mind. ein Oktett mit fuehrender Null
    if "." in hostname:
        parts = hostname.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts) and any(
            len(p) > 1 and p.startswith("0") for p in parts
        ):
            try:
                octets = [int(p, 8) for p in parts]
                if all(0 <= o <= 255 for o in octets):
                    return ".".join(str(o) for o in octets)
            except ValueError:
                return None
    return None


def _is_ipv6_literal(hostname: str) -> bool:
    """Prueft ob Hostname eine IPv6-Literal-Notation ist."""
    return ":" in hostname


def _is_ip_literal(hostname: str) -> bool:
    """Prueft, ob der Hostname eine IP-Adresse (IPv4 oder IPv6) ist."""
    return _is_ipv4_literal(hostname) or _is_ipv6_literal(hostname)


def is_private_ip(hostname: str) -> bool:
    """Prueft, ob hostname eine private/geschuetzte IP-Adresse ist (IPv4 und IPv6).

    Bei leerem Hostname: True (Sicherheitsvorgabe).
    Bei Nicht-IP-Eingabe: False (kein IP-Literal -> kann nicht beurteilt werden).
    """
    if not hostname:
        return True
    try:
        addr = ip_address(hostname)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast:
            return True
        return any(addr in network for network in _PROTECTED_NETWORKS)
    except ValueError:
        return False


def resolve_and_verify(hostname: str) -> bool:
    """Prueft, ob ALLE DNS-A/AAAA-Antworten zu oeffentlichen IPs zeigen.

    Wichtig: Wir muessen JEDEN Eintrag pruefen, nicht nur einen.
    Wenn auch nur eine Antwort auf eine private IP zeigt -> ablehnen.
    """
    if not hostname:
        return False
    if _is_ip_literal(hostname):
        return not is_private_ip(hostname)
    try:
        addr_info = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        if not addr_info:
            return False
        for info in addr_info:
            ip_str: str = str(info[4][0])  # type: ignore[assignment, index]
            if "%" in ip_str:  # IPv6 Zone-ID abschneiden
                ip_str = ip_str.split("%", 1)[0]
            if is_private_ip(ip_str):
                logger.warning(f"DNS-Aufloesung zeigt auf private IP: {hostname} -> {ip_str}")
                return False
        return True
    except (socket.gaierror, socket.herror, OSError) as e:
        logger.warning(f"DNS-Aufloesung fehlgeschlagen fuer {hostname}: {e}")
        return False


def is_safe_url(url: str) -> bool:
    """Prueft, ob eine URL sicher ist (Schema, Domain, Pfad). DNS wird separat geprueft."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ALLOWED_SCHEMAS:
            return False
        if not parsed.hostname:
            return False

        # Null-Byte-Schutz
        if "\x00" in url:
            return False

        # Userinfo (http://user:pass@host) blockieren - Daten-Exfiltrations-Vektor
        # und potentielle Basic-Auth-Verschleierung.
        if parsed.username or parsed.password:
            return False

        hostname = parsed.hostname.lower().rstrip(".")

        # Blockiere localhost und bekannte interne Hostnames
        if hostname in ("localhost", "0.0.0.0", "127.0.0.1", "::1", "ip6-localhost", "ip6-loopback"):
            return False

        # Blockiere private IP-Literale (dotted)
        if _is_ip_literal(hostname) and is_private_ip(hostname):
            return False

        # Blockiere codierte IPv4-Formen (dezimal/hex/oktal), die auf private
        # Netze zeigen (z.B. 2130706433 -> 127.0.0.1).
        decoded = _decode_ip_hostname(hostname)
        if decoded is not None and is_private_ip(decoded):
            return False

        # Blockiere blockierte Domains und Subdomains
        for blocked in BLOCKED_DOMAINS:
            if hostname == blocked or hostname.endswith("." + blocked):
                return False

        # Blockiere interne Domain-Suffixes
        if hostname.endswith(BLOCKED_DOMAIN_SUFFIXES):
            return False

        # Path-Pruefung
        path_lower = parsed.path.lower()
        return all(not path_lower.endswith(ext) for ext in BLOCKED_EXTENSIONS)
    except Exception:
        return False


# ============================================================
# Datenklassen
# ============================================================


@dataclass
class SearchResult:
    """Ein einzelnes Suchergebnis."""

    title: str
    url: str
    snippet: str
    source: str


@dataclass
class ScrapedPage:
    """Eine gescrapte Webseite."""

    url: str
    title: str
    content: str
    links: list[str]
    source: str


# ============================================================
# Sicherheits-Utilities
# ============================================================


def sanitize_html_to_text(html_content: str, max_length: int = MAX_RESULT_LENGTH) -> str:
    """Konvertiert HTML zu sicherem Text ohne Script/Style-Inhalte.

    Wendet eine HARTE Groessenbegrenzung VOR dem Parsing an, um
    BeautifulSoup-DoS durch riesige Eingaben zu verhindern.
    """
    try:
        if len(html_content) > MAX_HTML_PARSE_SIZE:
            html_content = html_content[:MAX_HTML_PARSE_SIZE]

        soup = BeautifulSoup(html_content, "html.parser")

        for tag in soup.find_all([
            "script", "style", "noscript", "iframe", "object", "embed",
            "form", "input", "textarea", "button", "link", "meta", "base",
            "svg",  # SVG kann Scripts enthalten
        ]):
            tag.decompose()

        for tag in soup.find_all(True):
            tag.attrs = {}

        text = soup.get_text(separator="\n", strip=True)
        text = re.sub(r"\n{3,}", "\n\n", text)

        if len(text) > max_length:
            text = text[:max_length] + "\n... [gekuerzt]"

        return text
    except Exception as e:
        return f"[Fehler bei der HTML-Parsung: {e}]"


class RateLimiter:
    """Einfaches Rate-Limiting pro Engine-Instanz (thread-safe)."""

    def __init__(self, max_requests: int = REQUESTS_PER_WINDOW, window_seconds: int = WINDOW_SECONDS):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: deque[float] = deque()
        self._lock = threading.Lock()

    def allow(self) -> bool:
        """Prueft, ob eine Anfrage erlaubt ist. Trackt die Anfrage atomar."""
        now = time()
        with self._lock:
            while self.requests and self.requests[0] < now - self.window_seconds:
                self.requests.popleft()
            if len(self.requests) >= self.max_requests:
                return False
            self.requests.append(now)
            return True

    def reset(self) -> None:
        """Setzt das Rate-Limit zurueck."""
        with self._lock:
            self.requests.clear()


# Globale Patterns - kompiliert beim Import fuer Performance
_INJECTION_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    # Direkte Anweisungen
    r"ignore\s+all\s+(previous\s+)?instructions?",
    r"disregard\s+(previous|all|the\s+above|earlier)\s+instructions?",
    r"you\s+are\s+now\s+(?:a\s+|an\s+)?(?:AI|assistant|bot|chatbot|different|evil|free|jailbreak|unrestricted|unfiltered|DAN|GPT|model\b)",
    r"from\s+now\s+on,?\s+(you|act|behave)",
    r"change\s+your\s+(behavior|rules|instructions|prompt|persona)",
    r"reset\s+(your\s+)?(instructions|prompt|system\s+prompt|conversation\s+context)",
    r"override\s+(your\s+)?(instructions|safety|guidelines|rules)",
    r"forget\s+(your\s+)?(previous|all|earlier)\s+instructions?",
    # System-Prompt Extraktion  (enger gefasst, um "Betriebssystem:", "file system:" etc. nicht zu treffen)
    r"(?:^|\n)\s*system\s*[:\-]\s*",
    r"show\s+(me\s+)?your\s+system\s+prompt",
    r"reveal\s+(your\s+)?(instructions|system\s+prompt|hidden\s+prompt)",
    r"previous\s+(?:system\s+)?prompt",
    r"above\s+instructions",
    r"display\s+(?:your\s+)?system\s+(?:prompt|instructions?)",
    r"print\s+(your\s+)?(system\s+)?prompt",
    r"repeat\s+(your\s+)?(initial|original|system)\s+(prompt|instructions)",
    # Code Execution
    r"\bexec\s*\(",
    r"\beval\s*\(",
    r"\bos\.system\b",
    r"\bsubprocess\.",
    r"\brm\s+-rf\b",
    r"\bwget\s+\S+\s*\|",
    r"\bcurl\s+\S+\s*\|\s*(sh|bash)",
    r"\bpython\s+-c\b",
    r"\bbash\s+-c\b",
    r"\bchmod\s+[0-7]{3,4}\b",
    r"\bnc\s+-[el]\b",
    r"\bmkfifo\b",
    r"\bncat\b",
    r"/dev/tcp/",
    r"\bbase64\s+-d\b",
    # Format-Injection (Chat-Template-Bypass)
    r"```(?:shell|bash|cmd|powershell|python|sh|zsh)\s*\n",
    r"<system\b",
    r"<role\s*=",
    r"<\|begin_of_message\|>",
    r"<\|end_of_message\|>",
    r"<\|start_of_content\|>",
    r"<\|im_start\|>",
    r"<\|im_end\|>",
    r"<\|endoftext\|>",
    r"<\|system\|>",
    r"<\|assistant\|>",
    r"<\|user\|>",
    r"\[INST\]",
    r"\[/INST\]",
    r"<<SYS>>",
    r"<</SYS>>",
    r"###\s*(System|Instruction|Human|Assistant)\s*:",
    # Base64 und Encoding
    r"\b(base64|hex|rot13)\s*[\-_]?(decode|encode|d|e)\b",
    r"[A-Za-z0-9+/]{100,}={0,2}",
    # Chain-of-Thought-Manipulation
    r"let\s+me\s+think\s+step\s*[\- ]\s*by\s*[\- ]\s*step",
    r"here\s+is\s+my\s+(full|complete|hidden)\s+(response|reasoning|chain)",
    r"think\s+silently",
    r"reason\s+without\s+showing",
    # Daten-Exfiltration
    r"send\s+this\s+to\s+https?",
    r"\bexfiltrat",
    r"steal\s+(your|the)\s+",
    r"extract\s+(your|the)\s+(system|api[\- ]?key|secret|password)",
    r"\bleak\s+(the|your)\s+(prompt|key|secret)",
    # Rollen-Ueberschreibung (BUGFIX: \b verhindert Match auf "now able", "now available" etc.)
    r"you\s+are\s+now\s+a\b(?!\w)",
    r"assume\s+the\s+role\s+of",
    r"act\s+as\s+if\s+you\s+(were|are)",
    r"adopt\s+the\s+persona\s+of",
    r"pretend\s+(you\s+are|to\s+be)",
    r"\bDAN\s+mode\b",
    r"developer\s+mode\s+(on|enabled)",
    # MCP / llama.cpp / Tool-Injection (NEU)
    r"use\s+(the\s+)?(?:read_file|write_file|delete_file|search_files|exec)\s+tool",
    r"\bmcp://",
    r"session\s*[\-_]?\s*(id|token)\s*[:=]",
    r"invoke\s+the\s+\w+\s+function",
    # Kontext-Manipulation (NEU)
    r"the\s+above\s+(text|content|instructions?|messages?)\s+(is|are)\s+(part\s+of\s+)?your\s+(system|new)",
    r"treat\s+the\s+following\s+as\s+(your\s+)?(?:new\s+)?(?:instructions?|system\s+prompt|commands?)",
    r"this\s+is\s+a\s+(test|simulation|drill|scenario|demonstration)\s+(and\s+)?(you\s+should|ignore)",
    r"for\s+(testing|demonstration|evaluation|research)\s+purposes,?\s+(please\s+)?(ignore|override|bypass)",
    # Jailbreak / Roleplay (NEU)
    r"\broleplay\s*[:\-]\s*you\s+(are|will)",
    r"\bjailbreak\s*[:\-]",
    r"in\s+this\s+(hypothetical|fictional|imaginary|alternate)\s+(scenario|world|story|universe)[^.]*(?:ignore|bypass|override|disregard)",
]]

_UNICODE_ESCAPE_RE = re.compile(r"\\u[0-9a-fA-F]{4}")
_HEX_ESCAPE_RE = re.compile(r"\\x[0-9a-fA-F]{2}")


def sanitize_for_prompt(text: str) -> str:
    """Sanitisiert Text fuer sichere Weitergabe an LLM-Prompts.

    Pipeline:
      1. Unicode-Normalisierung (NFKC) gegen Homoglyph-Bypass
      2. Backslash-Escape-Sequenzen entfernen (verhindert Pattern-Bypass)
      3. HTML-Entities dekodieren (Pattern arbeiten auf Klartext)
      4. Backslash-Newline/Tab umwandeln
      5. Pattern-Matching gegen Injection-Versuche
      6. HTML-Re-Escape als Defense-in-Depth
    """
    if not text:
        return ""

    # 1. Unicode-Normalisierung (verhindert "ìgnòre" statt "ignore")
    with contextlib.suppress(Exception):
        text = unicodedata.normalize("NFKC", text)

    # 2. Unicode/Hex-Escapes als Bypass-Versuch markieren
    text = _UNICODE_ESCAPE_RE.sub("[ENTFERNT: Unicode-Escape]", text)
    text = _HEX_ESCAPE_RE.sub("[ENTFERNT: Hex-Escape]", text)

    # 3. HTML-Entities dekodieren, damit Patterns auf Klartext matchen
    text = html.unescape(text)

    # 4. Literal-Escapes umwandeln, damit mehrzeilige Injections matchen
    text = text.replace("\\n", "\n").replace("\\t", "\t").replace("\\r", "\n")

    # 5. Pattern-Matching
    for pattern in _INJECTION_PATTERNS:
        text = pattern.sub("[ENTFERNT: Potenzielle Prompt-Injection]", text)

    # 6. HTML-Re-Escape (Defense-in-Depth)
    text = html.escape(text)
    return text


def is_safe_link(link: str, current_domain: str) -> bool:
    """Prueft, ob ein Link sicher zum Folgen ist."""
    if not is_safe_url(link):
        return False
    parsed = urlparse(link)
    hostname = parsed.hostname or ""
    if parsed.scheme not in ALLOWED_SCHEMAS:
        return False
    return hostname != current_domain


# ============================================================
# HTTP-Client mit Sicherheitslimits
# ============================================================


class SafeHttpClient:
    """Sicherer HTTP-Client mit Limits und DNS-Rebinding-Schutz."""

    def __init__(self, timeout: int = HTTP_TIMEOUT):
        self.timeout = timeout
        self.session = httpx.Client(
            timeout=self.timeout,
            follow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0 (SafeResearchBot/1.0; +https://safe-research.local)"},
            limits=httpx.Limits(max_connections=5, max_keepalive_connections=2),
        )
        # DNS-Cache fuer Rebinding-Schutz: Hostname -> timestamp
        self._verified_hosts: dict[str, float] = {}
        self._dns_lock = threading.Lock()

    @staticmethod
    def _sanitize_url_for_logging(url: str) -> str:
        """Extrahiert sichere Teile der URL fuer das Logging."""
        try:
            parsed = urlparse(url)
            return f"{parsed.scheme}://{parsed.hostname}{parsed.path}"
        except Exception:
            return "[URL konnte nicht analysiert werden]"

    def _verify_host_fresh(self, hostname: str) -> bool:
        """Pruefe DNS frisch oder verwende kurzen Cache (gegen DNS-Rebinding).

        Negative Ergebnisse werden NICHT gecached (Rebinding-Schutz).
        """
        with self._dns_lock:
            now = time()
            cached = self._verified_hosts.get(hostname)
            if cached is not None and (now - cached) < DNS_CACHE_SECONDS:
                return True
            if not resolve_and_verify(hostname):
                return False
            self._verified_hosts[hostname] = now
            return True

    def _check_response(self, response, url: str, max_size: int) -> bool:
        """Validiert eine HTTP-Antwort. True = sicher verwendbar.

        Prueft (Defense-in-Depth):
          - Antwort-IP nicht private (DNS-Rebinding belt-and-suspenders)
          - Response-Groesse <= max_size (DoS-Schutz)
          - Content-Type ist Text/HTML/XML/JSON (keine Binaries/Malware)
          - Content-Disposition: attachment mit gefaehrlicher Endung -> blockiert
        """
        response_host = response.url.host
        if response_host and _is_ip_literal(response_host) and is_private_ip(response_host):
            logger.warning(f"Antwort von privater IP: {response_host}")
            return False

        if len(response.content) > max_size:
            logger.warning(f"Response zu gross: {len(response.content)} bytes")
            return False

        content_type = response.headers.get("content-type", "").lower()
        if not any(t in content_type for t in ("text/html", "text/plain", "xml", "json")):
            logger.warning(f"Nicht-Text Content-Type: {content_type}")
            return False

        # Attachment-Download mit gefaehrlicher Endung blocken (Malware-Vektor)
        disposition = response.headers.get("content-disposition", "").lower()
        if "attachment" in disposition and any(ext in disposition for ext in BLOCKED_EXTENSIONS):
            logger.warning(f"Attachment mit gefaehrlicher Endung blockiert: {self._sanitize_url_for_logging(url)}")
            return False
        return True

    def _safe_get(self, url: str, params=None, headers=None, max_size: int = MAX_RESPONSE_SIZE):
        """GET mit allen Sicherheitschecks. Liefert httpx.Response oder None."""
        if not is_safe_url(url):
            logger.warning(f"Blockierte unsichere URL: {self._sanitize_url_for_logging(url)}")
            return None

        hostname = (urlparse(url).hostname or "").lower()

        # DNS-Rebinding-Schutz: Frische Validierung pro Request
        if not self._verify_host_fresh(hostname):
            logger.warning(f"DNS-Validierung fehlgeschlagen: {self._sanitize_url_for_logging(url)}")
            return None

        try:
            response = self.session.get(url, params=params, headers=headers)
            if not self._check_response(response, url, max_size):
                return None
            return response
        except httpx.TimeoutException:
            logger.warning(f"Timeout bei {self._sanitize_url_for_logging(url)}")
            return None
        except httpx.InvalidURL:
            logger.warning(f"Ungueltige URL: {self._sanitize_url_for_logging(url)}")
            return None
        except httpx.TooManyRedirects:
            logger.warning(f"Zu viele Redirects: {self._sanitize_url_for_logging(url)}")
            return None
        except Exception:
            logger.warning(f"Fehler bei {self._sanitize_url_for_logging(url)}: [interner Fehler]")
            return None

    def fetch(self, url: str, *, params=None, headers=None, max_size: int = MAX_RESPONSE_SIZE) -> str | None:
        """Sichert eine URL mit Groessenlimit und DNS-Rebinding-Schutz (Text)."""
        response = self._safe_get(url, params=params, headers=headers, max_size=max_size)
        return str(response.text) if response is not None else None

    def fetch_json(
        self,
        url: str,
        params: "Mapping[str, str | int | float | bool | None] | None" = None,
        headers: "Mapping[str, str] | None" = None,
        max_size: int = MAX_RESPONSE_SIZE,
    ) -> object | None:
        """Wie fetch(), aber mit Query-Params und JSON-Parsing.

        Fuer vertrauenswuerdige JSON-APIs (Wikipedia). XML-APIs (arXiv)
        stattdessen fetch() verwenden.
        """
        response = self._safe_get(url, params=params, headers=headers, max_size=max_size)
        if response is None:
            return None
        try:
            data: object = response.json()
            return data
        except ValueError:
            logger.warning(f"Ungueltiges JSON von {self._sanitize_url_for_logging(url)}")
            return None

    def close(self):
        self.session.close()


# ============================================================
# Suchmaschinen-Implementierungen
# ============================================================


class DuckDuckGoSearcher:
    """DuckDuckGo Suchmaschine (privatsphaere-freundlich, kein Tracking)."""

    def search(self, query: str, max_results: int = MAX_SEARCH_RESULTS) -> list[SearchResult]:
        try:
            results = []
            ddgs = DDGS()
            for result in ddgs.text(query, max_results=max_results):
                title = result.get("title", "")
                url = result.get("href", "")
                snippet = result.get("body", "")
                if url and is_safe_url(url):
                    results.append(SearchResult(title=title, url=url, snippet=snippet, source="duckduckgo"))
            return results
        except Exception as e:
            logger.error(f"DuckDuckGo-Fehler: {e}")
            return []


class WikipediaSearcher:
    """Wikipedia-Suchmaschine (ueber SafeHttpClient -> DNS-/Size-Schutz aktiv)."""

    WIKI_API_URL = "https://{lang}.wikipedia.org/w/api.php"

    def __init__(self, http_client: "SafeHttpClient"):
        self.client = http_client

    def search(self, query: str, max_results: int = MAX_SEARCH_RESULTS) -> list[SearchResult]:
        results: list[SearchResult] = []
        for lang in ["de", "en"]:
            if len(results) >= max_results:
                break
            try:
                api_url = self.WIKI_API_URL.format(lang=lang)
                params: Mapping[str, str | int | float | bool | None] = {
                    "action": "query",
                    "list": "search",
                    "srsearch": query,
                    "srlimit": min(max_results - len(results), 5),
                    "format": "json",
                    "srprop": "snippet|title|wordcount",
                    "srinfo": "suggestion",
                }
                headers = {"User-Agent": "llama-mcp-research/1.0 (Internet-Recherche; +https://github.com/Sebas/llama-mcp)"}
                data = self.client.fetch_json(api_url, params=params, headers=headers)
                if not isinstance(data, dict):
                    continue
                search_terms = data.get("query", {}).get("search", [])
                for term in search_terms:
                    title = term.get("title", "")
                    snippet = term.get("snippet", "")
                    article_url = f"https://{lang}.wikipedia.org/wiki/{quote_plus(title)}"
                    results.append(SearchResult(
                        title=title, url=article_url,
                        snippet=self._clean_wikipedia_snippet(snippet),
                        source=f"wikipedia({lang})",
                    ))
                    if len(results) >= max_results:
                        break
            except Exception as e:
                logger.error(f"Wikipedia({lang})-Fehler: {e}")
                continue
        return results[:max_results]

    def _clean_wikipedia_snippet(self, snippet: str) -> str:
        if not snippet:
            return ""
        snippet = html.unescape(snippet)
        snippet = re.sub(r"\[\d+\]", "", snippet)
        return snippet.strip()

    def get_article(self, url: str) -> ScrapedPage | None:
        try:
            parsed = urlparse(url)
            # Lang aus Hostnamen extrahieren (de.wikipedia.org -> "de")
            # BUGFIX: vorher wurde lang aus dem Pfad gelesen → ergab immer "wiki"
            hostname = parsed.hostname or "en.wikipedia.org"
            lang = hostname.split(".")[0] if hostname.endswith("wikipedia.org") else "en"
            if lang not in ("de", "en", "fr", "es", "it", "pt", "nl", "pl", "ru", "ja", "zh"):
                lang = "en"
            # Titel aus Pfad extrahieren: /wiki/Artikelname -> "Artikelname"
            path_parts = parsed.path.strip("/").split("/", 1)
            title = path_parts[1] if len(path_parts) > 1 else path_parts[0] if path_parts else ""

            api_url = self.WIKI_API_URL.format(lang=lang)
            params: Mapping[str, str | int | float | bool | None] = {
                "action": "query",
                "titles": title,
                "prop": "extracts|info",
                "inprop": "url",
                "explaintext": True,
                "format": "json",
            }
            headers = {"User-Agent": "llama-mcp-research/1.0 (Internet-Recherche; +https://github.com/Sebas/llama-mcp)"}
            data = self.client.fetch_json(api_url, params=params, headers=headers)
            if not isinstance(data, dict):
                return None
            pages = data.get("query", {}).get("pages", {})
            for _page_id, page_data in pages.items():
                if page_data.get("missing"):
                    return None
                article_title = page_data.get("title", "")
                extract = page_data.get("extract", "")
                if extract:
                    if len(extract) > MAX_RESULT_LENGTH:
                        extract = extract[:MAX_RESULT_LENGTH] + "\n... [gekuerzt]"
                    sanitized = sanitize_for_prompt(extract)
                    return ScrapedPage(
                        url=url, title=article_title, content=sanitized,
                        links=[], source=f"wikipedia({lang})",
                    )
            return None
        except Exception as e:
            logger.error(f"Wikipedia-Artikel-Fehler: {e}")
            return None


class ArXivSearcher:
    """arXiv-Suchmaschine fuer wissenschaftliche Paper (ueber SafeHttpClient)."""

    ARXIV_API = "https://export.arxiv.org/api/query"  # https statt http (Patch)

    def __init__(self, http_client: "SafeHttpClient"):
        self.client = http_client

    def search(self, query: str, max_results: int = MAX_SEARCH_RESULTS) -> list[SearchResult]:
        results: list[SearchResult] = []
        try:
            xml_text = self.client.fetch(self.ARXIV_API, params={
                "query": f"all:{query}",
                "start": 0,
                "max_results": min(max_results, 10),
                "sortBy": "relevance",
                "sortOrder": "descending",
            })
            if not xml_text:
                return results
            from xml.etree import ElementTree
            root = ElementTree.fromstring(xml_text)
            namespace = {
                "atom": "http://www.w3.org/2005/Atom",
                "opensearch": "http://a9.com/-/spec/opensearch/1.1/",
            }
            for entry in root.findall(".//atom:entry", namespace):
                title = (entry.findtext("atom:title", "") or "").strip().replace("\n", " ")
                summary = (entry.findtext("atom:summary", "") or "").strip().replace("\n", " ")
                link = entry.findtext("atom:link", "") or ""
                abstract_url = ""
                for link_elem in entry.findall("atom:link", namespace):
                    href = link_elem.get("href", "")
                    if "abs" in href.lower() or "entry" in href.lower():
                        abstract_url = href
                if not abstract_url:
                    abstract_url = link
                if abstract_url and is_safe_url(abstract_url):
                    results.append(SearchResult(
                        title=title, url=abstract_url,
                        snippet=self._clean_arxiv_text(summary), source="arxiv",
                    ))
        except Exception as e:
            logger.error(f"arXiv-Fehler: {e}")
        return results[:max_results]

    def _clean_arxiv_text(self, text: str) -> str:
        if not text:
            return ""
        text = text.replace("&lt;", "<").replace("&gt;", ">")
        text = text.replace("&amp;", "&").replace("&quot;", '"')
        text = text.replace("&apos;", "'")
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    def get_paper_details(self, url: str) -> ScrapedPage | None:
        try:
            arxiv_id = urlsplit_id(url)
            if not arxiv_id:
                return None
            xml_text = self.client.fetch(self.ARXIV_API, params={
                "search_query": f"id:{arxiv_id}", "max_results": 1,
            })
            if not xml_text:
                return None
            from xml.etree import ElementTree
            root = ElementTree.fromstring(xml_text)
            namespace = {"atom": "http://www.w3.org/2005/Atom"}
            for entry in root.findall(".//atom:entry", namespace):
                title = (entry.findtext("atom:title", "") or "").strip().replace("\n", " ")
                summary = (entry.findtext("atom:summary", "") or "").strip().replace("\n", " ")
                authors = []
                for author in entry.findall("atom:author", namespace):
                    name = author.findtext("atom:name", "") or ""
                    if name:
                        authors.append(name)
                if summary:
                    content = (
                        f"Titel: {title}\n"
                        f"Autoren: {', '.join(authors)}\n\n"
                        f"Zusammenfassung:\n{self._clean_arxiv_text(summary)}"
                    )
                    if len(content) > MAX_RESULT_LENGTH:
                        content = content[:MAX_RESULT_LENGTH] + "\n... [gekuerzt]"
                    sanitized = sanitize_for_prompt(content)
                    return ScrapedPage(url=url, title=title, content=sanitized,
                                      links=[], source="arxiv")
            return None
        except Exception as e:
            logger.error(f"arXiv-Paper-Fehler: {e}")
            return None


def urlsplit_id(url: str) -> str:
    """arXiv-ID extrahieren - unterstuetzt neue (2301.12345) und alte (cs/9904001) Formate."""
    try:
        parsed = urlparse(url)
        path = parsed.path.strip("/")
        # Neues Format: YYMM.NNNNN[vN]
        new_match = re.search(r"(\d{4}\.\d{4,5})(v\d+)?", path)
        if new_match:
            return new_match.group(1)
        # Altes Format: cs.AI/9904001 oder cs/9904001
        old_match = re.search(r"([a-z\-]+(?:\.[A-Z]{2})?/\d{7})(v\d+)?", path)
        if old_match:
            return old_match.group(1)
        return ""
    except Exception:
        return ""


class GESTISearcher:
    """GESTI-Suche der BG BA (Gefahrstoffe)."""

    def search(self, query: str, max_results: int = MAX_SEARCH_RESULTS) -> list[SearchResult]:
        results = []
        try:
            ddgs = DDGS()
            for result in ddgs.text(f"site:gesti.bgba.de {query}", max_results=max_results):
                url = result.get("href", "")
                if "gesti.bgba.de" in url and is_safe_url(url):
                    results.append(SearchResult(
                        title=result.get("title", ""), url=url,
                        snippet=result.get("body", ""), source="gesti",
                    ))
        except Exception as e:
            logger.error(f"GESTI-Fehler: {e}")
        return results


class GitHubSearcher:
    """GitHub-Suche ueber die offizielle api.github.com.

    Sicher: raw.githubusercontent.com bleibt blockiert; wir nutzen nur die
    Such-API, die JSON-Metadaten (keinen Roquellcode) liefert. Code-Suche
    erfordert einen Auth-Token (sonst liefert GitHub 401) - ohne Token wird
    repositories-Suche verwendet.
    """

    GITHUB_API = "https://api.github.com/search"
    UA = "llama-mcp-research/1.0 (Internet-Recherche; +https://github.com/DaWasteh/llama-mcp)"

    def __init__(self, http_client: "SafeHttpClient"):
        self.client = http_client

    def search(self, query: str, search_type: str = "repositories",
               max_results: int = MAX_SEARCH_RESULTS) -> list[SearchResult]:
        endpoint = "code" if search_type == "code" else "repositories"
        try:
            data = self.client.fetch_json(
                f"{self.GITHUB_API}/{endpoint}",
                params={"q": query, "per_page": min(max_results, 10)},
                headers={"User-Agent": self.UA, "Accept": "application/vnd.github+json"},
            )
        except Exception as e:
            logger.error(f"GitHub-Fehler: {e}")
            return []
        if not isinstance(data, dict):
            return []

        results: list[SearchResult] = []
        items = data.get("items", []) or []
        for item in items[:max_results]:
            if endpoint == "code":
                repo = item.get("repository", {}) or {}
                # Repo-URL als Primärlink: Datei-URLs (blob/.../*.py) enden oft auf
                # blockierten Endungen und liefern ueber unseren Text-Fetch keinen
                # Mehrwert. Dateipfad steht im Titel.
                url = repo.get("html_url", "") or item.get("html_url", "")
                title = f"{repo.get('full_name', '')}/{item.get('path', '')}"
                snippet = item.get("name", "")
            else:
                url = item.get("html_url", "")
                title = item.get("full_name", "")
                stars = item.get("stargazers_count", 0)
                desc = item.get("description") or ""
                snippet = f"{desc} [★ {stars}]".strip()
            if url and is_safe_url(url):
                results.append(SearchResult(title=title, url=url, snippet=snippet, source="github"))
        return results


class NewsSearcher:
    """Nachrichten-Suche via DuckDuckGo News (kein zusaetzlicher API-Key)."""

    def search(self, query: str, max_results: int = MAX_SEARCH_RESULTS) -> list[SearchResult]:
        results: list[SearchResult] = []
        try:
            ddgs = DDGS()
            for r in ddgs.news(query, max_results=max_results):
                url = r.get("url", "")
                if url and is_safe_url(url):
                    results.append(SearchResult(
                        title=r.get("title", ""), url=url,
                        snippet=r.get("body", ""), source="news",
                    ))
        except Exception as e:
            logger.error(f"News-Fehler: {e}")
        return results


# ============================================================
# Haupt-Recherche-Engine
# ============================================================


class InternetResearchEngine:
    """Haupt-Engine fuer sichere Internet-Recherche (thread-lokal verwenden!)."""

    def __init__(self):
        self.http_client = SafeHttpClient()
        self.ddg = DuckDuckGoSearcher()
        self.wiki = WikipediaSearcher(self.http_client)
        self.arxiv = ArXivSearcher(self.http_client)
        self.gesti = GESTISearcher()
        self.github = GitHubSearcher(self.http_client)
        self.news = NewsSearcher()
        self.rate_limiter = RateLimiter()
        self._visited_urls: set[str] = set()
        self._page_count = 0
        self._state_lock = threading.Lock()

    def reset(self):
        """Suche zuruecksetzen."""
        with self._state_lock:
            self._visited_urls.clear()
            self._page_count = 0

    def check_rate_limit(self) -> dict | None:
        """Gibt ein Fehler-Dict zurueck, wenn das Rate-Limit ueberschritten wurde."""
        if not self.rate_limiter.allow():
            logger.warning("Rate-Limit ueberschritten")
            return {
                "success": False,
                "error": f"Rate-Limit ueberschritten (max {REQUESTS_PER_WINDOW}/{WINDOW_SECONDS}s)",
                "results": [],
            }
        return None

    def search(
        self,
        query: str,
        sources: list[str] | None = None,
        max_results: int = MAX_SEARCH_RESULTS,
        follow_links: bool = False,
        max_follow_links: int = MAX_FOLLOW_LINKS,
    ) -> dict:
        """Fuehrt eine sichere Internet-Recherche durch."""
        rl_error = self.check_rate_limit()
        if rl_error:
            rl_error["query"] = query
            return rl_error

        if sources is None:
            sources = ["duckduckgo", "wikipedia"]
        sources = [s.lower() for s in sources if s.lower() in ALLOWED_SOURCES]
        if not sources:
            sources = ["duckduckgo", "wikipedia"]

        self.reset()
        all_results: list[dict] = []
        total_pages = 0

        try:
            if "duckduckgo" in sources:
                for r in self.ddg.search(query, max_results):
                    all_results.append({
                        "title": r.title, "url": r.url,
                        "snippet": sanitize_for_prompt(r.snippet), "source": r.source,
                    })
                    total_pages += 1
            if "wikipedia" in sources:
                for r in self.wiki.search(query, max_results):
                    all_results.append({
                        "title": r.title, "url": r.url,
                        "snippet": sanitize_for_prompt(r.snippet), "source": r.source,
                    })
                    total_pages += 1
            if "arxiv" in sources:
                for r in self.arxiv.search(query, max_results):
                    all_results.append({
                        "title": r.title, "url": r.url,
                        "snippet": sanitize_for_prompt(r.snippet), "source": r.source,
                    })
                    total_pages += 1
            if "gesti" in sources:
                for r in self.gesti.search(query, max_results):
                    all_results.append({
                        "title": r.title, "url": r.url,
                        "snippet": sanitize_for_prompt(r.snippet), "source": r.source,
                    })
                    total_pages += 1

            if follow_links and max_follow_links > 0:
                all_results, total_pages = self._follow_links(all_results, max_follow_links, max_results * 3)

            all_results = all_results[: max_results * 3]

            return {
                "success": True, "query": query, "sources_used": sources,
                "total_results": len(all_results), "pages_scraped": total_pages,
                "results": all_results, "warnings": self._generate_warnings(total_pages),
            }
        finally:
            self.reset()

    def search_and_read(
        self,
        query: str,
        sources: list[str] | None = None,
        max_pages: int = MAX_PAGES_PER_SEARCH,
    ) -> dict:
        """Suche und lese vollstaendige Seiteninhalte."""
        rl_error = self.check_rate_limit()
        if rl_error:
            rl_error["query"] = query
            rl_error["detailed_pages"] = []
            return rl_error

        if sources is None:
            sources = ["duckduckgo", "wikipedia"]
        self.reset()

        try:
            search_results = self.search(query, sources, max_pages)
            if not search_results.get("success"):
                return search_results

            detailed_results = []
            for result in search_results["results"][:max_pages]:
                with self._state_lock:
                    if self._page_count >= max_pages:
                        break
                page = self._read_page(result["url"], result.get("source", ""))
                if page:
                    detailed_results.append({
                        "url": page.url, "title": page.title,
                        "content": page.content, "source": page.source,
                    })

            search_results["detailed_pages"] = detailed_results
            with self._state_lock:
                search_results["pages_read"] = self._page_count
            return search_results
        finally:
            self.reset()

    def read_url(self, url: str) -> dict:
        """Liest eine spezifische URL sicher."""
        rl_error = self.check_rate_limit()
        if rl_error:
            rl_error["url"] = url
            return rl_error
        self.reset()
        try:
            page = self._read_page(url, "")
            if page:
                return {
                    "success": True, "url": url, "title": page.title,
                    "content": page.content, "source": page.source,
                }
            return {"success": False, "url": url, "error": "Seite konnte nicht gelesen werden"}
        finally:
            self.reset()

    def get_archived(self, url: str) -> dict:
        """Ruft eine archivierte Fassung der URL ueber die Wayback Machine ab.

        Pieline (alles ueber SafeHttpClient -> DNS-/Size-/Content-Type-Schutz):
          1. archive.org/wayback/available -> naechster Snapshot (JSON)
          2. Snapshot-URL gegen is_safe_url pruefen (defense-in-depth)
          3. Snapshot laden + HTML zu Text + sanitize_for_prompt
        """
        rl_error = self.check_rate_limit()
        if rl_error:
            rl_error["url"] = url
            return rl_error
        try:
            avail = self.http_client.fetch_json(
                "https://archive.org/wayback/available",
                params={"url": url},
            )
            if not isinstance(avail, dict):
                return {"success": False, "url": url, "error": "Archiv-API nicht erreichbar"}
            closest = (avail.get("archived_snapshots") or {}).get("closest") or {}
            snapshot_url = closest.get("url", "")
            timestamp = closest.get("timestamp", "")
            if not snapshot_url:
                return {"success": False, "url": url, "error": "Kein archivierter Snapshot gefunden"}
            if not is_safe_url(snapshot_url):
                return {"success": False, "url": url, "error": "Snapshot-URL aus Sicherheitsgruenden blockiert"}
            html_content = self.http_client.fetch(snapshot_url)
            if not html_content:
                return {"success": False, "url": url, "error": "Snapshot konnte nicht geladen werden"}
            title = ""
            with contextlib.suppress(Exception):
                soup = BeautifulSoup(html_content[:MAX_HTML_PARSE_SIZE], "html.parser")
                t = soup.find("title")
                title = t.get_text(strip=True) if t else urlparse(url).hostname or ""
            content = sanitize_for_prompt(sanitize_html_to_text(html_content))
            return {
                "success": True, "url": url, "snapshot_url": snapshot_url,
                "timestamp": timestamp, "title": title, "content": content,
            }
        except Exception as e:
            logger.error(f"Wayback-Fehler fuer {url}: {e}")
            return {"success": False, "url": url, "error": "Ein interner Fehler ist aufgetreten"}

    def _read_page(self, url: str, source_hint: str) -> ScrapedPage | None:
        """Seite sicher lesen."""
        if not is_safe_url(url):
            logger.warning(f"Blockierte URL: {SafeHttpClient._sanitize_url_for_logging(url)}")
            return None

        with self._state_lock:
            if url in self._visited_urls:
                return None
            if self._page_count >= MAX_PAGES_PER_SEARCH:
                logger.warning("Maximale Seitenanzahl erreicht")
                return None
            self._visited_urls.add(url)
            self._page_count += 1

        if "wikipedia.org" in url:
            return self.wiki.get_article(url)
        if "arxiv.org" in url:
            arxiv_id = urlsplit_id(url)
            if arxiv_id:
                page = self.arxiv.get_paper_details(url)
                if page:
                    return page

        html_content = self.http_client.fetch(url)
        if not html_content:
            return None

        try:
            html_for_parsing = html_content[:MAX_HTML_PARSE_SIZE]
            soup = BeautifulSoup(html_for_parsing, "html.parser")
            title = soup.find("title")
            title_text = title.get_text(strip=True) if title else urlparse(url).hostname or "Ohne Titel"
            content = sanitize_html_to_text(html_content)
            content = sanitize_for_prompt(content)
            current_domain = urlparse(url).hostname or ""
            links: list[str] = []
            for a_tag in soup.find_all("a", href=True):
                href = str(a_tag.get("href", ""))
                full_url = str(urljoin(url, href))
                if is_safe_link(full_url, current_domain):
                    links.append(full_url)
                    if len(links) >= MAX_FOLLOW_LINKS:
                        break
            return ScrapedPage(
                url=url, title=title_text, content=content,
                links=links, source=source_hint or "web",
            )
        except Exception as e:
            logger.error(f"Fehler beim Parsen von {SafeHttpClient._sanitize_url_for_logging(url)}: {e}")
            return None

    def _follow_links(self, results: list[dict], max_follow: int, total_limit: int) -> tuple:
        """Folgt sicheren Links in den Suchergebnissen."""
        new_results = []
        page_count = 0
        for result in results:
            if page_count >= total_limit:
                break
            url = result.get("url", "")
            if not is_safe_url(url):
                continue
            if result.get("source") in ("duckduckgo",):
                page = self._read_page(url, "web")
                if page:
                    page_count += 1
                    new_results.append({
                        "title": page.title, "url": page.url,
                        "snippet": page.content[:500], "source": page.source,
                        "followed_from": result.get("url"),
                    })
                    if len(new_results) >= max_follow:
                        break
        return results + new_results, page_count

    def _generate_warnings(self, page_count: int) -> list[str]:
        warnings = []
        if page_count >= MAX_PAGES_PER_SEARCH:
            warnings.append(f"Maximale Seitenanzahl ({MAX_PAGES_PER_SEARCH}) erreicht")
        elif page_count >= MAX_PAGES_PER_SEARCH * 0.8:
            warnings.append("Nahe am Limit - Ergebnisse koennten unvollstaendig sein")
        return warnings

    def close(self):
        self.http_client.close()


# ============================================================
# Thread-lokale Engine-Instanz
# ============================================================

_local = threading.local()


def get_engine() -> InternetResearchEngine:
    """Gibt eine thread-lokale Engine-Instanz zurueck."""
    eng = getattr(_local, "engine", None)
    if eng is None:
        eng = InternetResearchEngine()
        _local.engine = eng
    return eng


# ============================================================
# MCP-Server (eigenstaendig oder einbettbar)
# ============================================================

mcp_research = FastMCP("internet-research-server")


def _register_tools_to_server(mcp_server):
    """Registriert alle Recherche-Tools auf einem MCP-Server.

    WICHTIG: Verwendet get_engine() (thread-lokal) statt einer Modul-Engine,
    damit konkurrente HTTP-Worker keine geteilten _visited_urls / _page_count haben.
    """
    tool_dec = mcp_server.tool

    @tool_dec()
    def internet_research(
        query: str,
        sources: str = "duckduckgo,wikipedia",
        max_results: int = 5,
        follow_links: bool = False,
    ) -> dict:
        """Sichere Internet-Recherche mit mehreren Quellen.

        Args:
            query: Suchbegriff oder Frage.
            sources: Komma-getrennte Quellen: duckduckgo, wikipedia, arxiv, gesti.
            max_results: Max. Suchergebnisse (1-5).
            follow_links: True um bis zu 3 sichere Folgelinks pro Seite zu folgen.
        """
        try:
            source_list = [s.strip() for s in sources.split(",") if s.strip()]
            max_results = max(1, min(max_results, MAX_SEARCH_RESULTS))
            return get_engine().search(
                query=query, sources=source_list, max_results=max_results, follow_links=follow_links
            )
        except Exception as e:
            logger.error(f"internet_research interner Fehler: {e!s}")
            return {"success": False, "error": "Ein interner Fehler ist aufgetreten",
                    "query": query, "results": []}

    @tool_dec()
    def internet_research_detailed(
        query: str,
        sources: str = "duckduckgo,wikipedia",
        max_pages: int = 5,
    ) -> dict:
        """Sichere Internet-Recherche mit vollstaendigen Seiteninhalten.

        Args:
            query: Suchbegriff.
            sources: Komma-getrennte Quellen.
            max_pages: Max. vollstaendig gelesene Seiten (1-10).
        """
        try:
            source_list = [s.strip() for s in sources.split(",") if s.strip()]
            max_pages = max(1, min(max_pages, 10))
            return get_engine().search_and_read(query=query, sources=source_list, max_pages=max_pages)
        except Exception as e:
            logger.error(f"internet_research_detailed interner Fehler: {e!s}")
            return {"success": False, "error": "Ein interner Fehler ist aufgetreten",
                    "query": query, "results": [], "detailed_pages": []}

    @tool_dec()
    def read_webpage(url: str) -> dict:
        """Liest eine spezifische Webseite sicher.

        Args:
            url: Vollstaendige URL (http/https).
        """
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.hostname:
                return {"success": False, "error": "Ungueltige URL", "url": url}
            if not is_safe_url(url):
                return {"success": False, "error": "URL aus Sicherheitsgruenden blockiert", "url": url}
            return get_engine().read_url(url)
        except Exception as e:
            logger.error(f"read_webpage interner Fehler: {e!s}")
            return {"success": False, "error": "Ein interner Fehler ist aufgetreten", "url": url}

    @tool_dec()
    def search_wikipedia(query: str, language: str = "de") -> dict:
        """Durchsucht Wikipedia (DE oder EN).

        Args:
            query: Suchbegriff.
            language: "de" oder "en".
        """
        try:
            if language not in ("de", "en"):
                language = "de"
            eng = get_engine()
            rl_error = eng.check_rate_limit()
            if rl_error:
                rl_error["query"] = query
                return rl_error
            results = eng.wiki.search(query, max_results=5)
            formatted = [{
                "title": r.title, "url": r.url,
                "snippet": sanitize_for_prompt(r.snippet)[:300], "source": r.source,
            } for r in results]
            return {"success": True, "query": query, "language": language,
                    "results": formatted, "count": len(formatted)}
        except Exception as e:
            logger.error(f"search_wikipedia interner Fehler: {e!s}")
            return {"success": False, "error": "Ein interner Fehler ist aufgetreten",
                    "query": query, "results": []}

    @tool_dec()
    def search_arxiv(query: str) -> dict:
        """Durchsucht arXiv fuer wissenschaftliche Paper.

        Args:
            query: Suchbegriff.
        """
        try:
            eng = get_engine()
            rl_error = eng.check_rate_limit()
            if rl_error:
                rl_error["query"] = query
                return rl_error
            results = eng.arxiv.search(query, max_results=5)
            formatted = [{
                "title": r.title, "url": r.url,
                "snippet": sanitize_for_prompt(r.snippet)[:500], "source": r.source,
            } for r in results]
            return {"success": True, "query": query, "results": formatted, "count": len(formatted)}
        except Exception as e:
            logger.error(f"search_arxiv interner Fehler: {e!s}")
            return {"success": False, "error": "Ein interner Fehler ist aufgetreten",
                    "query": query, "results": []}

    @tool_dec()
    def search_gesti(query: str) -> dict:
        """Durchsucht GESTI (Gefahrstoffe) der BG BA.

        Args:
            query: Suchbegriff (z.B. "Aceton").
        """
        try:
            eng = get_engine()
            rl_error = eng.check_rate_limit()
            if rl_error:
                rl_error["query"] = query
                return rl_error
            results = eng.gesti.search(query, max_results=5)
            formatted = [{
                "title": r.title, "url": r.url,
                "snippet": sanitize_for_prompt(r.snippet)[:300], "source": r.source,
            } for r in results]
            return {"success": True, "query": query, "results": formatted, "count": len(formatted)}
        except Exception as e:
            logger.error(f"search_gesti interner Fehler: {e!s}")
            return {"success": False, "error": "Ein interner Fehler ist aufgetreten",
                    "query": query, "results": []}

    @tool_dec()
    def search_github(query: str, search_type: str = "repositories", max_results: int = 5) -> dict:
        """Durchsucht GitHub nach Repositories oder Code (via offizielle api.github.com).

        Args:
            query: Suchbegriff.
            search_type: "repositories" (Default) oder "code".
                        Code-Suche erfordert i.d.R. einen GitHub-Token.
            max_results: Max. Ergebnisse (1-10).
        """
        try:
            if search_type not in ("repositories", "code"):
                search_type = "repositories"
            max_results = max(1, min(max_results, 10))
            eng = get_engine()
            rl_error = eng.check_rate_limit()
            if rl_error:
                rl_error["query"] = query
                return rl_error
            results = eng.github.search(query, search_type=search_type, max_results=max_results)
            formatted = [{
                "title": r.title, "url": r.url,
                "snippet": sanitize_for_prompt(r.snippet)[:400], "source": r.source,
            } for r in results]
            return {"success": True, "query": query, "search_type": search_type,
                    "results": formatted, "count": len(formatted),
                    "note": "Code-Suche benoetigt ggf. einen GitHub-Token (sonst leer)."}
        except Exception as e:
            logger.error(f"search_github interner Fehler: {e!s}")
            return {"success": False, "error": "Ein interner Fehler ist aufgetreten",
                    "query": query, "results": []}

    @tool_dec()
    def search_news(query: str, max_results: int = 5) -> dict:
        """Sucht aktuelle Nachrichten (via DuckDuckGo News, kein API-Key).

        Args:
            query: Suchbegriff / Thema.
            max_results: Max. Ergebnisse (1-10).
        """
        try:
            max_results = max(1, min(max_results, 10))
            eng = get_engine()
            rl_error = eng.check_rate_limit()
            if rl_error:
                rl_error["query"] = query
                return rl_error
            results = eng.news.search(query, max_results=max_results)
            formatted = [{
                "title": r.title, "url": r.url,
                "snippet": sanitize_for_prompt(r.snippet)[:300], "source": r.source,
            } for r in results]
            return {"success": True, "query": query, "results": formatted, "count": len(formatted)}
        except Exception as e:
            logger.error(f"search_news interner Fehler: {e!s}")
            return {"success": False, "error": "Ein interner Fehler ist aufgetreten",
                    "query": query, "results": []}

    @tool_dec()
    def read_archived(url: str) -> dict:
        """Ruft eine archivierte Fassung einer URL ueber die Wayback Machine ab.

        Nuetzlich fuer geloeschte/historische Seiten. Nutzt web.archive.org
        (sichere, legitime Quelle) mit denselben Schranken wie read_webpage.

        Args:
            url: Original-URL, deren Archivfassung gesucht wird.
        """
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.hostname:
                return {"success": False, "error": "Ungueltige URL", "url": url}
            if not is_safe_url(url):
                return {"success": False, "error": "URL aus Sicherheitsgruenden blockiert", "url": url}
            return get_engine().get_archived(url)
        except Exception as e:
            logger.error(f"read_archived interner Fehler: {e!s}")
            return {"success": False, "error": "Ein interner Fehler ist aufgetreten", "url": url}

    @tool_dec()
    def safe_web_scrape(url: str, max_content_length: int = 3000) -> dict:
        """Sicheres Scraping einer Webseite (extrahiert Text).

        Args:
            url: Vollstaendige URL.
            max_content_length: Max. Laenge des extrahierten Inhalts (max 5000).
        """
        try:
            if not is_safe_url(url):
                return {"success": False, "error": "URL aus Sicherheitsgruenden blockiert", "url": url}
            max_content_length = max(100, min(max_content_length, MAX_RESULT_LENGTH))
            eng = get_engine()
            rl_error = eng.check_rate_limit()
            if rl_error:
                rl_error["url"] = url
                return rl_error
            html_content = eng.http_client.fetch(url)
            if not html_content:
                return {"success": False, "error": "Inhalt konnte nicht abgerufen werden", "url": url}
            content = sanitize_html_to_text(html_content, max_length=max_content_length)
            try:
                soup = BeautifulSoup(html_content[:MAX_HTML_PARSE_SIZE], "html.parser")
                title_tag = soup.find("title")
                title = title_tag.get_text(strip=True) if title_tag else urlparse(url).hostname or "Ohne Titel"
            except Exception:
                title = "Titel unbekannt"
            return {
                "success": True, "url": url, "title": title,
                "content": sanitize_for_prompt(content),
                "content_length": len(content),
            }
        except Exception as e:
            logger.error(f"safe_web_scrape interner Fehler: {e!s}")
            return {"success": False, "error": "Ein interner Fehler ist aufgetreten", "url": url}


# Registriere Tools auf dem research-spezifischen Server
_register_tools_to_server(mcp_research)


# Eigenstaendiger Server-Name + Default-Port (eigenstaendig vom Dateisystem-Server)
RESEARCH_SERVER_NAME = "internet-research-server"
RESEARCH_DEFAULT_PORT = 8766


def main() -> None:
    """Startet den Internet-Recherche-MCP-Server als eigenstaendigen Prozess."""
    args = build_argparser(RESEARCH_SERVER_NAME, default_port=RESEARCH_DEFAULT_PORT).parse_args()

    logger.info("Internet-Recherche Server starting...")
    logger.info("Erlaubte Quellen: DuckDuckGo, Wikipedia, arXiv, GESTI")
    logger.info("Quellen außerhalb dieser Liste werden strikt blockiert (SSRF/Schutz).")

    run_mcp_server(
        mcp=mcp_research,
        server_name=RESEARCH_SERVER_NAME,
        host=args.host,
        port=args.port,
        transport=args.transport,
        streamable_http_app_factory=mcp_research.streamable_http_app,
        sse_app_factory=mcp_research.sse_app,
    )


if __name__ == "__main__":
    main()


def register_research_tools(mcp_instance):
    """Registriert alle Internet-Recherche-Tools auf einem bestehenden MCP-Server.

    Kompatibilitaets-API fuer externe Einbinder, die die Tools in einen eigenen
    FastMCP-Server mounten wollen. Der Dateisystem-Server selbst nutzt diese nicht
    mehr - die Server sind sauber getrennt.
    """
    _register_tools_to_server(mcp_instance)
