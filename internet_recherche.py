"""
Sicherer Internet-Recherche MCP-Server fuer llama.cpp Web UI (Port 8766).

Quellen: DuckDuckGo (ddgs), Wikipedia, arXiv, GESTIS (DGUV), GitHub API,
DuckDuckGo News, Wayback Machine sowie direktes Lesen oeffentlicher Webseiten.

Sicherheitsarchitektur:
- Nur HTTP GET, kein Dateisystem-Zugriff, keine Downloads/Executables
- SSRF-Schutz auf URL-, DNS- und Socket-Ebene (Zero-TOCTOU Connect-Check,
  IPv4/IPv6/Mapped/Shorthand/IDNA-Normalisierung, Port-Whitelist 80/443,
  manuelle Redirect-Validierung, Blocklisten, Streaming-Byte-Cap)
- Prompt-Injection-Sanitisierung fuer Inhalte UND Titel (Invisible-Char-Strip,
  NFKC + Homoglyph-/Diakritika-Faltung, Chat-Template- & Tool-Injection-Patterns)
- XML-Guard gegen DOCTYPE/ENTITY, prozessweites Rate-Limiting
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
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from time import time
from typing import TYPE_CHECKING
from urllib.parse import quote, unquote, unquote_plus, urljoin, urlparse

if TYPE_CHECKING:
    from collections.abc import Mapping

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as e:
    print(f"FEHLER: MCP SDK nicht installiert. ({e})", file=sys.stderr)
    print('Fuehre aus: python -m pip install "mcp[cli]==1.29.0"', file=sys.stderr)
    raise

try:
    import httpcore
    import httpx
    from bs4 import BeautifulSoup  # pyright: ignore[reportMissingImports]
    try:
        from ddgs import DDGS  # pyright: ignore[reportMissingImports]
    except ImportError:
        from duckduckgo_search import DDGS as _LEGACY_DDGS  # pyright: ignore[reportMissingImports]

        DDGS = _LEGACY_DDGS  # type: ignore[misc, assignment]
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
MAX_REDIRECTS = 3  # Manuell verfolgte Redirects (jeder Hop wird neu validiert)

ALLOWED_SCHEMAS = {"http", "https"}
ALLOWED_PORTS = {None, 80, 443}

# Geschuetzte IP-Netze (SSRF-Schutz; zusaetzlich greift `not addr.is_global`)
_PROTECTED_NETWORKS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"),
    ip_network("0.0.0.0/8"),
    ip_network("100.64.0.0/10"),
    ip_network("192.0.2.0/24"),    # TEST-NET-1
    ip_network("198.18.0.0/15"),   # Benchmarking
    ip_network("198.51.100.0/24"), # TEST-NET-2
    ip_network("203.0.113.0/24"),  # TEST-NET-3
    ip_network("::/128"),          # IPv6 Unspecified
    ip_network("::1/128"),         # IPv6 Loopback
    ip_network("64:ff9b::/96"),    # NAT64
    ip_network("fc00::/7"),        # IPv6 Unique Local
    ip_network("fe80::/10"),       # IPv6 Link-Local
]

# Blockierte Domains (Daten-Exfiltration, Code-Execution, Cloud-Metadata, ungefilterter Content)
BLOCKED_DOMAINS = {
    # Cloud-Metadata-Aliase
    "metadata.goog", "metadata.google.internal", "instance-data",
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
# HINWEIS: .php gehoert NICHT hierher - server-seitige Scripts liefern
# gerendertes HTML/JSON (z.B. Wikipedia-API /w/api.php).
BLOCKED_EXTENSIONS = {
    ".exe", ".dll", ".so", ".msi", ".bat", ".cmd", ".ps1", ".sh", ".bash",
    ".zsh", ".com", ".scr", ".pif", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".wsh", ".hta", ".lnk", ".reg", ".inf", ".scf", ".cpl", ".sys", ".drv",
    ".ocx", ".jar", ".app", ".dmg", ".pkg", ".apk", ".deb", ".rpm", ".cab",
    ".iso", ".img", ".wasm", ".py", ".pl", ".rb", ".bin", ".elf", ".out",
}

ALLOWED_SOURCES = {"duckduckgo", "wikipedia", "arxiv", "gesti"}

_LOCALHOST_HOSTNAMES = frozenset({
    "localhost", "0.0.0.0", "127.0.0.1", "::1", "::", "ip6-localhost", "ip6-loopback",
})

# IDNA-Punkt-Aequivalente (UTS #46): werden von HTTP-Clients zu '.' normalisiert
_IDNA_DOTS_TABLE = str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."})


def _normalize_hostname(raw_hostname: str) -> str | None:
    """Normalisiert einen Hostnamen gegen Fullwidth-/IDNA-SSRF-Bypasses.

    Wandelt Fullwidth-ASCII (z.B. U+FF4C..U+FF54 fuer 'localhost') und
    IDNA-Punkt-Aequivalente (U+3002/U+FF0E/U+FF61) in kanonisches ASCII/Punycode um.
    Liefert None bei ungueltigem Hostnamen.
    """
    if not raw_hostname:
        return None
    host = unicodedata.normalize("NFKC", raw_hostname).translate(_IDNA_DOTS_TABLE).lower().rstrip(".")
    if not host:
        return None
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii").lower().rstrip(".")
        except UnicodeError:
            return None
    return host or None


def _is_ipv4_literal(hostname: str) -> bool:
    """Prueft ob Hostname eine IPv4-Literal-Notation ist."""
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) is not None


def _parse_ipv4_part(part: str) -> int | None:
    """Parst ein einzelnes IPv4-Segment im BSD inet_aton-Format (dezimal/oktal/hex)."""
    if not part:
        return None
    low = part.lower()
    try:
        if low.startswith("0x"):
            if len(low) <= 2 or not all(c in "0123456789abcdef" for c in low[2:]):
                return None
            return int(low, 16)
        if len(low) > 1 and low.startswith("0"):
            if not all(c in "01234567" for c in low):
                return None
            return int(low, 8)
        if not low.isdigit():
            return None
        return int(low, 10)
    except ValueError:
        return None


def _decode_ip_hostname(hostname: str) -> str | None:
    """Erkennt nicht-standardmaessige IPv4-Encodings (POSIX inet_aton) und gibt dotted-Form zurueck.

    Deckt SSRF-Bypass-Vektoren ab, die getaddrinfo plattformabhaengig aufloest:
      - 1-Teil (dez/hex/oktal): 2130706433, 0x7f000001, 017700000001 -> 127.0.0.1
      - 2-Teil Shorthand:       127.1, 0x7f.1                        -> 127.0.0.1
      - 3-Teil Shorthand:       127.0.1, 0177.0.0                    -> 127.0.0.1 / 127.0.0.0
      - 4-Teil Oktal/Hex/Mix:   0177.0.0.1, 0x7f.0.0.1               -> 127.0.0.1
    Liefert None fuer normale 4-Oktett-Dezimal-IPs (wie 8.8.8.8) oder Domainnamen.
    """
    if not hostname or ":" in hostname:
        return None
    parts = hostname.split(".")
    if not (1 <= len(parts) <= 4):
        return None
    # Standard 4-Teil dotted-dezimal (ohne fuehrende Null/Hex) ist kein Encoding
    if len(parts) == 4 and all(
        p.isdigit() and (len(p) == 1 or not p.startswith("0")) for p in parts
    ):
        return None

    nums: list[int] = []
    for p in parts:
        val = _parse_ipv4_part(p)
        if val is None:
            return None
        nums.append(val)

    # inet_aton-Semantik: letzte Komponente fuellt die verbleibenden Bytes
    if len(nums) == 1:
        n = nums[0]
        if 0 <= n <= 0xFFFFFFFF:
            return str(IPv4Address(n))
        return None
    if len(nums) == 2:
        a, b = nums
        if 0 <= a <= 0xFF and 0 <= b <= 0xFFFFFF:
            return str(IPv4Address((a << 24) | b))
        return None
    if len(nums) == 3:
        a, b, c = nums
        if 0 <= a <= 0xFF and 0 <= b <= 0xFF and 0 <= c <= 0xFFFF:
            return str(IPv4Address((a << 24) | (b << 16) | c))
        return None
    a, b, c, d = nums
    if all(0 <= x <= 0xFF for x in (a, b, c, d)):
        return f"{a}.{b}.{c}.{d}"
    return None


def _is_ipv6_literal(hostname: str) -> bool:
    """Prueft ob Hostname eine IPv6-Literal-Notation ist."""
    return ":" in hostname


def _is_ip_literal(hostname: str) -> bool:
    """Prueft, ob der Hostname eine IP-Adresse (IPv4 oder IPv6) ist."""
    return _is_ipv4_literal(hostname) or _is_ipv6_literal(hostname)


def is_private_ip(hostname: str) -> bool:
    """Prueft, ob hostname eine private/nicht-oeffentliche IP-Adresse ist (IPv4 und IPv6).

    Erfasst auch IPv4-mapped IPv6 (::ffff:127.0.0.1), 6to4, Teredo, CGNAT,
    Unspecified (:: / 0.0.0.0) sowie alle nicht-globalen Adressbereiche.
    Bei leerem Hostname: True (fail-closed). Bei Nicht-IP-Eingabe: False.
    """
    if not hostname:
        return True
    cleaned = hostname.strip()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1]
    if "%" in cleaned:  # IPv6 Zone-ID abschneiden
        cleaned = cleaned.split("%", 1)[0]
    try:
        addr = ip_address(cleaned)
        if isinstance(addr, IPv6Address):
            if addr.ipv4_mapped is not None and is_private_ip(str(addr.ipv4_mapped)):
                return True
            if addr.sixtofour is not None and is_private_ip(str(addr.sixtofour)):
                return True
            if addr.teredo is not None and (
                is_private_ip(str(addr.teredo[0])) or is_private_ip(str(addr.teredo[1]))
            ):
                return True
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified
            or not addr.is_global
        ):
            return True
        return any(addr in network for network in _PROTECTED_NETWORKS)
    except ValueError:
        return False


def _resolve_public_ips(hostname: str, port: int | None = None) -> list[str]:
    """Loest hostname auf und gibt alle oeffentlichen IPs zurueck (leer bei Fehler oder privater IP).

    Wichtig: JEDE Antwort wird geprueft. Zeigt auch nur ein Eintrag auf eine
    private/nicht-globale IP, wird eine leere Liste zurueckgegeben.
    """
    if not hostname:
        return []
    if _is_ip_literal(hostname):
        return [] if is_private_ip(hostname) else [hostname]
    try:
        addr_info = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        if not addr_info:
            return []
        ips: list[str] = []
        for info in addr_info:
            ip_str: str = str(info[4][0])  # type: ignore[assignment, index]
            if "%" in ip_str:  # IPv6 Zone-ID abschneiden
                ip_str = ip_str.split("%", 1)[0]
            if is_private_ip(ip_str):
                logger.warning(f"DNS-Aufloesung zeigt auf private IP: {hostname} -> {ip_str}")
                return []
            if ip_str not in ips:
                ips.append(ip_str)
        return ips
    except (socket.gaierror, socket.herror, OSError) as e:
        logger.warning(f"DNS-Aufloesung fehlgeschlagen fuer {hostname}: {e}")
        return []


def resolve_and_verify(hostname: str) -> bool:
    """Prueft, ob ALLE DNS-A/AAAA-Antworten zu oeffentlichen IPs zeigen."""
    return bool(_resolve_public_ips(hostname))


def _has_control_chars(value: str) -> bool:
    """Prueft auf ASCII-Steuerzeichen (Null-Bytes, CR/LF, Tabs etc.)."""
    return any(ord(c) < 0x20 or ord(c) == 0x7F for c in value)


def is_safe_url(url: str) -> bool:
    """Prueft, ob eine URL sicher ist (Schema, Port, Hostname, IP-Encoding, Blocklisten, Pfad).

    DNS-Aufloesung erfolgt separat in resolve_and_verify() / _SafeSyncBackend.
    """
    try:
        if not url or _has_control_chars(url):
            return False
        parsed = urlparse(url)
        if parsed.scheme not in ALLOWED_SCHEMAS:
            return False
        if not parsed.hostname:
            return False

        # Userinfo (inkl. leerem '@' wie http://@host/) und Backslash-Authority blockieren
        if parsed.username or parsed.password or "@" in parsed.netloc or "\\" in parsed.netloc:
            return False

        # Port-Whitelist (verhindert SSRF auf interne Dienste wie Redis/SSH/SMTP)
        try:
            port = parsed.port
        except ValueError:
            return False
        if port not in ALLOWED_PORTS:
            return False

        hostname = _normalize_hostname(parsed.hostname)
        if not hostname:
            return False

        # Blockiere localhost und bekannte interne Hostnames
        if hostname in _LOCALHOST_HOSTNAMES:
            return False

        # Blockiere private/nicht-globale IP-Literale (dotted IPv4 und IPv6)
        if _is_ip_literal(hostname) and is_private_ip(hostname):
            return False

        # Blockiere codierte IPv4-Formen (dezimal/hex/oktal/shorthand), die auf
        # private Netze zeigen (z.B. 2130706433, 127.1, 0x7f.0.0.1 -> 127.0.0.1).
        decoded = _decode_ip_hostname(hostname)
        if decoded is not None and is_private_ip(decoded):
            return False

        # Single-Label-Hostnamen ohne Punkt (z.B. http://intranet/) blockieren,
        # ausser gueltige oeffentliche IP-Encodings oder IPv6-Literale.
        if "." not in hostname and not _is_ipv6_literal(hostname) and decoded is None:
            return False

        # Blockiere blockierte Domains und Subdomains
        for blocked in BLOCKED_DOMAINS:
            if hostname == blocked or hostname.endswith("." + blocked):
                return False

        # Blockiere interne Domain-Suffixes
        if hostname.endswith(BLOCKED_DOMAIN_SUFFIXES):
            return False

        # Path-Pruefung (ohne rstrip('/'), damit Wayback-URLs wie /web/.../https://example.com/ nicht an .com scheitern)
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

    def remaining(self) -> int:
        """Anzahl aktuell noch erlaubter Anfragen im Zeitfenster (ohne zu tracken)."""
        now = time()
        with self._lock:
            while self.requests and self.requests[0] < now - self.window_seconds:
                self.requests.popleft()
            return max(0, self.max_requests - len(self.requests))

    def reset(self) -> None:
        """Setzt das Rate-Limit zurueck."""
        with self._lock:
            self.requests.clear()


# Prozessweiter Rate-Limiter: Die Engine ist thread-lokal, das Limit darf es
# NICHT sein - sonst bekommt jeder HTTP-Worker-Thread sein eigenes Kontingent
# und das Limit ist bei parallelen Sessions faktisch wirkungslos.
_GLOBAL_RATE_LIMITER = RateLimiter()


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
    # Chat-Template- & Tool-Call-Injection (ChatML, Llama 2/3/4, Gemma, Mistral/Qwen/DeepSeek)
    r"```(?:shell|bash|cmd|powershell|python|sh|zsh)\s*\n",
    r"<system\b",
    r"<role\s*=",
    r"<\|begin_of_message\|>",
    r"<\|end_of_message\|>",
    r"<\|start_of_content\|>",
    r"<\|begin_of_text\|>",
    r"<\|end_of_text\|>",
    r"<\|start_header_id\|>",
    r"<\|end_header_id\|>",
    r"<\|eot_id\|>",
    r"<\|python_tag\|>",
    r"<\|im_start\|>",
    r"<\|im_end\|>",
    r"<\|endoftext\|>",
    r"<\|system\|>",
    r"<\|assistant\|>",
    r"<\|user\|>",
    r"<\|tool_call\|>",
    r"<\|tool_response\|>",
    r"</?tool_call>",
    r"<start_of_turn>",
    r"<end_of_turn>",
    r"\[TOOL_CALLS\]",
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
    # Rollen-Ueberschreibung (\b verhindert Match auf "now able", "now available" etc.)
    r"you\s+are\s+now\s+a\b(?!\w)",
    r"assume\s+the\s+role\s+of",
    r"act\s+as\s+if\s+you\s+(were|are)",
    r"adopt\s+the\s+persona\s+of",
    r"pretend\s+(you\s+are|to\s+be)",
    r"\bDAN\s+mode\b",
    r"developer\s+mode\s+(on|enabled)",
    # MCP / llama.cpp / Tool-Injection
    r"use\s+(the\s+)?(?:read_file|read_file_binary|write_file|write_file_binary|delete_file|search_files|search_content|find_replace|move_file|copy_file|chmod_file|decompress_archive|empty_directory|create_symlink|exec)\s+tool",
    r"\bmcp://",
    r"session\s*[\-_]?\s*(id|token)\s*[:=]",
    r"invoke\s+the\s+\w+\s+function",
    # Kontext-Manipulation
    r"the\s+above\s+(text|content|instructions?|messages?)\s+(is|are)\s+(part\s+of\s+)?your\s+(system|new)",
    r"treat\s+the\s+following\s+as\s+(your\s+)?(?:new\s+)?(?:instructions?|system\s+prompt|commands?)",
    r"this\s+is\s+a\s+(test|simulation|drill|scenario|demonstration)\s+(and\s+)?(you\s+should|ignore)",
    r"for\s+(testing|demonstration|evaluation|research)\s+purposes,?\s+(please\s+)?(ignore|override|bypass)",
    # Jailbreak / Roleplay
    r"\broleplay\s*[:\-]\s*you\s+(are|will)",
    r"\bjailbreak\s*[:\-]",
    r"in\s+this\s+(hypothetical|fictional|imaginary|alternate)\s+(scenario|world|story|universe)[^.]*(?:ignore|bypass|override|disregard)",
    # Deutsche Prompt-Injection-Patterns
    r"ignoriere\s+alle\s+(?:vorherigen|bisherigen|obigen)\s+Anweisungen",
    r"vergiss\s+alle\s+(?:vorherigen|bisherigen|obigen)\s+Anweisungen",
    r"(?:zeige|gib)\s+(?:mir\s+)?(?:deinen|den)\s+System[\- ]?Prompt",
    r"du\s+bist\s+(?:ab\s+sofort|jetzt)\s+(?:ein\s+)?(?:unzensiert|freier|boeser|böser|anderer\s+Assistent|DAN)",
]]

_UNICODE_ESCAPE_RE = re.compile(r"\\u[0-9a-fA-F]{4}")
_HEX_ESCAPE_RE = re.compile(r"\\x[0-9a-fA-F]{2}")
_XML_DANGEROUS_DECL_RE = re.compile(r"<!\s*(?:doctype|entity)\b", re.IGNORECASE)

_CONFUSABLES_MAP = str.maketrans({
    # Kyrillische Homoglyphen
    "\u0430": "a", "\u0410": "A",
    "\u0435": "e", "\u0415": "E",
    "\u043e": "o", "\u041e": "O",
    "\u0440": "p", "\u0420": "P",
    "\u0441": "c", "\u0421": "C",
    "\u0443": "y", "\u0423": "Y",
    "\u0445": "x", "\u0425": "X",
    "\u0456": "i", "\u0406": "I",
    "\u0455": "s", "\u0405": "S",
    "\u0458": "j", "\u0408": "J",
    "\u043a": "k", "\u041a": "K",
    "\u043c": "m", "\u041c": "M",
    "\u0442": "t", "\u0422": "T",
    "\u04bb": "h", "\u04ba": "H",
    # Griechische Homoglyphen
    "\u03b1": "a", "\u0391": "A",
    "\u03b5": "e", "\u0395": "E",
    "\u03bf": "o", "\u039f": "O",
    "\u03c1": "p", "\u03a1": "P",
    "\u03b9": "i", "\u0399": "I",
    "\u03ba": "k", "\u039a": "K",
    "\u03bd": "v", "\u03a4": "T",
})


def _strip_invisible_chars(text: str) -> str:
    """Entfernt unsichtbare Format-/Steuerzeichen (ZWSP, Soft-Hyphen, Bidi, Unicode-Tags)."""
    return "".join(
        ch for ch in text
        if ch in ("\n", "\r", "\t") or unicodedata.category(ch) not in ("Cf", "Cc")
    )


def _fold_confusables(text: str) -> str:
    """Faltet Diakritika (NFKD) und kyrillische/griechische Homoglyphen auf ASCII.

    Wird nur fuer das zusaetzliche Pattern-Matching genutzt, damit legitime
    Umlaute in normalem Text unveraendert bleiben.
    """
    decomposed = unicodedata.normalize("NFKD", text)
    no_marks = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
    return no_marks.translate(_CONFUSABLES_MAP)


def sanitize_for_prompt(text: str) -> str:
    """Sanitisiert Text fuer sichere Weitergabe an LLM-Prompts.

    Pipeline:
      1. Unsichtbare Format-/Steuerzeichen entfernen (ZWSP, Bidi, Unicode-Tags)
      2. Unicode-Normalisierung (NFKC) gegen Fullwidth-Bypass
      3. Backslash-Escape-Sequenzen markieren
      4. HTML-Entities dekodieren (Patterns arbeiten auf Klartext)
      5. Literal-Newline/Tab umwandeln
      6. Pattern-Matching (direkt + Homoglyph-/Diakritika-gefaltet)
      7. HTML-Re-Escape als Defense-in-Depth
    """
    if not text:
        return ""

    # 1. Unsichtbare Format-/Steuerzeichen entfernen
    text = _strip_invisible_chars(text)

    # 2. Unicode-Normalisierung (Fullwidth-ASCII etc.)
    with contextlib.suppress(Exception):
        text = unicodedata.normalize("NFKC", text)

    # 3. Unicode/Hex-Escapes als Bypass-Versuch markieren
    text = _UNICODE_ESCAPE_RE.sub("[ENTFERNT: Unicode-Escape]", text)
    text = _HEX_ESCAPE_RE.sub("[ENTFERNT: Hex-Escape]", text)

    # 4. HTML-Entities dekodieren, damit Patterns auf Klartext matchen
    text = html.unescape(text)

    # 5. Literal-Escapes umwandeln, damit mehrzeilige Injections matchen
    text = text.replace("\\n", "\n").replace("\\t", "\t").replace("\\r", "\n")

    # 6. Pattern-Matching direkt + Homoglyph-/Diakritika-Pruefung
    for pattern in _INJECTION_PATTERNS:
        text = pattern.sub("[ENTFERNT: Potenzielle Prompt-Injection]", text)

    folded = _fold_confusables(text)
    if folded != text:
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(folded):
                folded = pattern.sub("[ENTFERNT: Potenzielle Prompt-Injection]", folded)
                text = folded

    # 7. HTML-Re-Escape (Defense-in-Depth)
    text = html.escape(text)
    return text


def safe_parse_xml(xml_text: str):
    """Parst XML mit Schutz gegen Entity-Angriffe (Billion Laughs / XXE).

    DOCTYPE- und ENTITY-Deklarationen im gesamten Dokument werden abgelehnt.
    Liefert Element oder None.
    """
    if not xml_text:
        return None
    if _XML_DANGEROUS_DECL_RE.search(xml_text):
        logger.warning("XML mit DOCTYPE/ENTITY-Deklaration blockiert")
        return None
    from xml.etree import ElementTree
    try:
        return ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as e:
        logger.warning(f"XML-Parse-Fehler: {e}")
        return None


def explain_url_block(url: str, *, check_dns: bool = True) -> list[str]:
    """Erklaert, WARUM eine URL blockiert wird (leere Liste = URL ist ok).

    Fuehrt KEINEN HTTP-Request aus. Prueft dieselben Regeln wie is_safe_url
    plus optional DNS-Aufloesung.
    """
    reasons: list[str] = []
    if not url:
        return ["Leere URL"]
    if "\x00" in url:
        reasons.append("URL enthaelt Null-Byte")
    elif _has_control_chars(url):
        reasons.append("URL enthaelt Steuerzeichen")
    try:
        parsed = urlparse(url)
    except Exception:
        return ["URL konnte nicht geparst werden"]

    if parsed.scheme not in ALLOWED_SCHEMAS:
        reasons.append(f"Schema '{parsed.scheme}' nicht erlaubt (nur http/https)")
    if not parsed.hostname:
        reasons.append("Kein Hostname in der URL")
        return reasons
    if parsed.username or parsed.password or "@" in parsed.netloc:
        reasons.append("Userinfo (user:pass@) in URL blockiert (Exfiltrations-Vektor)")
    if "\\" in parsed.netloc:
        reasons.append("Backslash in URL-Authority blockiert")

    try:
        port = parsed.port
        if port not in ALLOWED_PORTS:
            reasons.append(f"Port {port} nicht erlaubt (nur 80/443)")
    except ValueError:
        reasons.append("Ungueltiger Port in der URL")

    hostname = _normalize_hostname(parsed.hostname)
    if not hostname:
        reasons.append("Ungueltiger Hostname (IDNA-Normalisierung fehlgeschlagen)")
        return reasons

    if hostname in _LOCALHOST_HOSTNAMES:
        reasons.append("Localhost/interner Hostname blockiert")
    if _is_ip_literal(hostname) and is_private_ip(hostname):
        reasons.append("Private/reservierte IP-Adresse blockiert")
    decoded = _decode_ip_hostname(hostname)
    if decoded is not None and is_private_ip(decoded):
        reasons.append(f"Codierte private IP erkannt ({hostname} -> {decoded})")
    if "." not in hostname and not _is_ipv6_literal(hostname) and decoded is None and hostname not in _LOCALHOST_HOSTNAMES:
        reasons.append("Interner Single-Label-Hostname ohne TLD blockiert")
    for blocked in BLOCKED_DOMAINS:
        if hostname == blocked or hostname.endswith("." + blocked):
            reasons.append(f"Domain auf Blockliste: {blocked}")
            break
    for suffix in BLOCKED_DOMAIN_SUFFIXES:
        if hostname.endswith(suffix):
            reasons.append(f"Blockiertes Domain-Suffix: {suffix}")
            break
    path_lower = parsed.path.lower()
    for ext in BLOCKED_EXTENSIONS:
        if path_lower.endswith(ext):
            reasons.append(f"Blockierte Datei-Endung: {ext}")
            break

    # DNS nur pruefen, wenn bis hierhin nichts dagegen spricht
    if check_dns and not reasons and not resolve_and_verify(hostname):
        reasons.append("DNS-Aufloesung fehlgeschlagen oder zeigt auf private IP")
    return reasons


def _hostname_matches(url: str, domain: str) -> bool:
    """Prueft hostname-basiert (kein Substring-Match!), ob url zu domain gehoert.

    Verhindert Spoofing wie https://gesti.bgba.de.evil.com/ oder
    https://evil.com/wikipedia.org, das ein "domain in url" durchlassen wuerde.
    """
    try:
        hostname = (urlparse(url).hostname or "").lower().rstrip(".")
        domain = domain.lower()
        return hostname == domain or hostname.endswith("." + domain)
    except Exception:
        return False


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
# HTTP-Client mit Sicherheitslimits (Zero-TOCTOU DNS-Schutz)
# ============================================================

RESEARCH_USER_AGENT = "llama-mcp-research/1.1 (+https://github.com/DaWasteh/llama-mcp)"
_SENSITIVE_REDIRECT_HEADERS = frozenset({"authorization", "cookie", "proxy-authorization"})


class _SafeSyncBackend(httpcore.SyncBackend):
    """Socket-Backend mit Zero-TOCTOU DNS-Rebinding- und Blind-SSRF-Schutz.

    Loest DNS beim Verbindungsaufbau genau einmal auf, prueft ALLE IPs gegen
    is_private_ip() und verbindet direkt mit der validierten IP (TLS SNI und
    Zertifikatspruefung durch httpcore bleiben unveraendert aktiv).
    """

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options=None,
    ) -> httpcore.NetworkStream:
        ips = _resolve_public_ips(host, port)
        if not ips:
            raise httpcore.ConnectError(f"Verbindung zu privater/ungueltiger Adresse blockiert: {host}")
        last_err: Exception | None = None
        for ip_str in ips:
            try:
                return super().connect_tcp(
                    ip_str,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except httpcore.ConnectError as e:
                last_err = e
        raise last_err or httpcore.ConnectError(f"Verbindung fehlgeschlagen: {host}")


class SafeHttpClient:
    """Sicherer HTTP-Client mit Limits und Zero-TOCTOU DNS-Rebinding-Schutz."""

    def __init__(self, timeout: int = HTTP_TIMEOUT):
        self.timeout = timeout
        limits = httpx.Limits(max_connections=5, max_keepalive_connections=2)
        transport = httpx.HTTPTransport(limits=limits)
        transport._pool._network_backend = _SafeSyncBackend()  # type: ignore[attr-defined]
        self.session = httpx.Client(
            timeout=self.timeout,
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": RESEARCH_USER_AGENT},
            transport=transport,
        )
        # Kurzer DNS-Vorabcache fuer schnelles Fail-Fast; die eigentliche
        # Socket-Verbindung validiert zusaetzlich frisch in _SafeSyncBackend.
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
        """Pruefe DNS frisch oder verwende kurzen Cache (negative Ergebnisse nie gecached)."""
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
          - Antwort-IP nicht private
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

        # Attachment-Download mit gefaehrlicher Endung blocken (prueft ALLE filename/filename*-Parameter)
        disposition = response.headers.get("content-disposition", "").lower()
        if "attachment" in disposition:
            matches: list[str] = []
            for m in re.finditer(r'filename\*?\s*=\s*(?:"([^"]+)"|([^;]+))', disposition):
                raw_name = (m.group(1) or m.group(2) or "").strip()
                # RFC 5987: utf-8''name.exe -> name.exe (vor Quote-Strip, da '' Teil der Syntax ist)
                if "''" in raw_name:
                    raw_name = raw_name.split("''", 1)[1]
                matches.append(unquote(raw_name).strip().strip("\"'"))
            candidates = matches or [disposition]
            for candidate in candidates:
                if any(candidate.endswith(ext) for ext in BLOCKED_EXTENSIONS):
                    logger.warning(
                        f"Attachment mit gefaehrlicher Endung blockiert: {self._sanitize_url_for_logging(url)}"
                    )
                    return False
        return True

    @staticmethod
    def _get_peer_ip(response) -> str | None:
        """Liest die tatsaechlich verbundene Server-IP aus der Response."""
        try:
            stream = response.extensions.get("network_stream")
            if stream is None:
                return None
            addr = stream.get_extra_info("server_addr")
            if addr:
                ip_str = str(addr[0])
                if "%" in ip_str:  # IPv6 Zone-ID abschneiden
                    ip_str = ip_str.split("%", 1)[0]
                return ip_str
        except Exception:
            return None
        return None

    @staticmethod
    def _read_capped(response, max_size: int) -> bytes | None:
        """Liest den Response-Body streamend mit hartem Byte-Limit (Memory-DoS-Schutz)."""
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_bytes(chunk_size=65536):
            total += len(chunk)
            if total > max_size:
                return None
            chunks.append(chunk)
        return b"".join(chunks)

    _REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})

    def _safe_get(self, url: str, params=None, headers=None, max_size: int = MAX_RESPONSE_SIZE):
        """GET mit allen Sicherheitschecks. Liefert httpx.Response oder None.

        Sicherheitspipeline pro Hop (Redirects werden MANUELL verfolgt):
          1. is_safe_url (Schema/Port/Domain/IDNA/IP-Encoding/Blocklisten)
          2. DNS-Vorabvalidierung + Zero-TOCTOU Socket-Validierung (_SafeSyncBackend)
          3. Peer-IP der offenen Verbindung pruefen (Defense-in-Depth)
          4. Nur 2xx-Status akzeptieren (bei Cross-Origin-Redirect sensible Header droppen)
          5. Content-Length-Vorabpruefung + gecappter Streaming-Read
          6. _check_response (Content-Type, Disposition, Groesse)
        """
        req_headers = dict(headers) if headers else None

        for _hop in range(MAX_REDIRECTS + 1):
            if not is_safe_url(url):
                logger.warning(f"Blockierte unsichere URL: {self._sanitize_url_for_logging(url)}")
                return None

            parsed_cur = urlparse(url)
            hostname = _normalize_hostname(parsed_cur.hostname or "") or ""
            if not hostname:
                return None

            if not self._verify_host_fresh(hostname):
                logger.warning(f"DNS-Validierung fehlgeschlagen: {self._sanitize_url_for_logging(url)}")
                return None

            try:
                with self.session.stream("GET", url, params=params, headers=req_headers) as response:
                    peer_ip = self._get_peer_ip(response)
                    if peer_ip and is_private_ip(peer_ip):
                        logger.warning(f"Verbindung zu privater IP blockiert: {peer_ip}")
                        return None

                    if response.status_code in self._REDIRECT_CODES:
                        location = response.headers.get("location", "")
                        if not location:
                            return None
                        next_url = urljoin(url, location)
                        parsed_next = urlparse(next_url)
                        # Bei Origin-Wechsel sensible Header entfernen
                        if req_headers and (
                            parsed_next.scheme != parsed_cur.scheme
                            or (parsed_next.hostname or "").lower() != (parsed_cur.hostname or "").lower()
                            or parsed_next.port != parsed_cur.port
                        ):
                            req_headers = {
                                k: v for k, v in req_headers.items()
                                if k.lower() not in _SENSITIVE_REDIRECT_HEADERS
                            }
                        url = next_url
                        params = None  # Query steckt ab jetzt in der Redirect-URL
                        continue

                    if not (200 <= response.status_code < 300):
                        logger.warning(
                            f"HTTP {response.status_code} bei {self._sanitize_url_for_logging(url)}"
                        )
                        return None

                    content_length = response.headers.get("content-length", "")
                    if content_length.isdigit() and int(content_length) > max_size:
                        logger.warning(f"Content-Length zu gross: {content_length} bytes")
                        return None

                    body = self._read_capped(response, max_size)
                    if body is None:
                        logger.warning(f"Response zu gross (Stream-Abbruch): {self._sanitize_url_for_logging(url)}")
                        return None

                    response._content = body

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

        logger.warning(f"Redirect-Limit ({MAX_REDIRECTS}) erreicht: {self._sanitize_url_for_logging(url)}")
        return None

    def fetch(self, url: str, *, params=None, headers=None, max_size: int = MAX_RESPONSE_SIZE) -> str | None:
        """Laedt eine URL mit Groessenlimit und DNS-Rebinding-Schutz (Text)."""
        response = self._safe_get(url, params=params, headers=headers, max_size=max_size)
        return str(response.text) if response is not None else None

    def fetch_json(
        self,
        url: str,
        params: "Mapping[str, str | int | float | bool | None] | None" = None,
        headers: "Mapping[str, str] | None" = None,
        max_size: int = MAX_RESPONSE_SIZE,
    ) -> object | None:
        """Wie fetch(), aber mit JSON-Parsing fuer JSON-APIs."""
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
    """Websuche via ddgs (DuckDuckGo/Meta-Suche, kein API-Key)."""

    def search(self, query: str, max_results: int = MAX_SEARCH_RESULTS) -> list[SearchResult]:
        try:
            results: list[SearchResult] = []
            ddgs = DDGS()
            for result in ddgs.text(query, max_results=max_results):
                title = result.get("title", "")
                url = result.get("href", "")
                snippet = result.get("body", "")
                if url and is_safe_url(url):
                    results.append(SearchResult(title=title, url=url, snippet=snippet, source="duckduckgo"))
            return results
        except Exception as e:
            if "no results found" in str(e).lower():
                logger.debug(f"DuckDuckGo keine Treffer fuer '{query}'")
            else:
                logger.error(f"DuckDuckGo-Fehler: {e}")
            return []


class WikipediaSearcher:
    """Wikipedia-Suchmaschine (ueber SafeHttpClient -> DNS-/Size-Schutz aktiv)."""

    WIKI_API_URL = "https://{lang}.wikipedia.org/w/api.php"

    def __init__(self, http_client: "SafeHttpClient"):
        self.client = http_client

    def search(
        self,
        query: str,
        max_results: int = MAX_SEARCH_RESULTS,
        language: str | None = None,
    ) -> list[SearchResult]:
        results: list[SearchResult] = []
        langs = [language] if language in ("de", "en") else ["de", "en"]
        for lang in langs:
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
                headers = {"User-Agent": RESEARCH_USER_AGENT}
                data = self.client.fetch_json(api_url, params=params, headers=headers)
                if not isinstance(data, dict):
                    continue
                search_terms = data.get("query", {}).get("search", [])
                for term in search_terms:
                    title = term.get("title", "")
                    snippet = term.get("snippet", "")
                    article_slug = quote(title.replace(" ", "_"), safe="()_:")
                    article_url = f"https://{lang}.wikipedia.org/wiki/{article_slug}"
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
        snippet = re.sub(r"<[^>]+>", "", snippet)
        snippet = html.unescape(snippet)
        snippet = re.sub(r"\[\d+\]", "", snippet)
        return re.sub(r"\s+", " ", snippet).strip()

    def get_article(self, url: str) -> ScrapedPage | None:
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or "en.wikipedia.org"
            lang = hostname.split(".")[0] if hostname.endswith("wikipedia.org") else "en"
            if lang not in ("de", "en", "fr", "es", "it", "pt", "nl", "pl", "ru", "ja", "zh"):
                lang = "en"
            # Titel aus Pfad extrahieren und URL-dekodieren (verhindert Doppel-Encoding bei Umlauten)
            path_parts = parsed.path.strip("/").split("/", 1)
            raw_title = path_parts[1] if len(path_parts) > 1 else path_parts[0] if path_parts else ""
            title = unquote_plus(raw_title)

            api_url = self.WIKI_API_URL.format(lang=lang)
            params: Mapping[str, str | int | float | bool | None] = {
                "action": "query",
                "titles": title,
                "prop": "extracts|info",
                "inprop": "url",
                "explaintext": True,
                "format": "json",
            }
            headers = {"User-Agent": RESEARCH_USER_AGENT}
            data = self.client.fetch_json(api_url, params=params, headers=headers)
            if not isinstance(data, dict):
                return None
            pages = data.get("query", {}).get("pages", {})
            for _page_id, page_data in pages.items():
                if page_data.get("missing"):
                    return None
                article_title = sanitize_for_prompt(page_data.get("title", ""))
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

    ARXIV_API = "https://export.arxiv.org/api/query"

    def __init__(self, http_client: "SafeHttpClient"):
        self.client = http_client

    def search(self, query: str, max_results: int = MAX_SEARCH_RESULTS) -> list[SearchResult]:
        results: list[SearchResult] = []
        try:
            xml_text = self.client.fetch(self.ARXIV_API, params={
                "search_query": f"all:{query}",
                "start": 0,
                "max_results": min(max_results, 10),
                "sortBy": "relevance",
                "sortOrder": "descending",
            })
            if not xml_text:
                return results
            root = safe_parse_xml(xml_text)
            if root is None:
                return results
            namespace = {
                "atom": "http://www.w3.org/2005/Atom",
                "opensearch": "http://a9.com/-/spec/opensearch/1.1/",
            }
            for entry in root.findall(".//atom:entry", namespace):
                title = (entry.findtext("atom:title", "", namespace) or "").strip().replace("\n", " ")
                summary = (entry.findtext("atom:summary", "", namespace) or "").strip().replace("\n", " ")
                entry_id = (entry.findtext("atom:id", "", namespace) or "").strip()
                abstract_url = ""
                for link_elem in entry.findall("atom:link", namespace):
                    href = link_elem.get("href", "")
                    if "abs" in href.lower() or "entry" in href.lower():
                        abstract_url = href
                        break
                if not abstract_url:
                    abstract_url = entry_id
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
        text = html.unescape(text)
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
            root = safe_parse_xml(xml_text)
            if root is None:
                return None
            namespace = {"atom": "http://www.w3.org/2005/Atom"}
            for entry in root.findall(".//atom:entry", namespace):
                title = (entry.findtext("atom:title", "", namespace) or "").strip().replace("\n", " ")
                summary = (entry.findtext("atom:summary", "", namespace) or "").strip().replace("\n", " ")
                authors = []
                for author in entry.findall("atom:author", namespace):
                    name = author.findtext("atom:name", "", namespace) or ""
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
                    return ScrapedPage(
                        url=url, title=sanitize_for_prompt(title), content=sanitized,
                        links=[], source="arxiv",
                    )
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
    """GESTIS-Stoffdatenbank der DGUV (Gefahrstoffe, ueber SafeHttpClient)."""

    GESTIS_API_URL = "https://gestis-api.dguv.de/api/search/{lang}"
    GESTIS_WEB_URL = "https://gestis.dguv.de/data"
    _CAS_RE = re.compile(r"^\d{2,7}-\d{2}-\d$")

    def __init__(self, http_client: "SafeHttpClient | None" = None):
        self.client = http_client

    def search(self, query: str, max_results: int = MAX_SEARCH_RESULTS) -> list[SearchResult]:
        q = query.strip()
        if not q:
            return []
        client = self.client
        owns_client = False
        if client is None:
            client = SafeHttpClient()
            owns_client = True

        results: list[SearchResult] = []
        param_key = "cas_nr" if self._CAS_RE.match(q) else "stoffname"
        try:
            for lang in ("de", "en"):
                data = client.fetch_json(
                    self.GESTIS_API_URL.format(lang=lang),
                    params={param_key: q},
                    headers={"User-Agent": RESEARCH_USER_AGENT},
                )
                if not isinstance(data, list) or not data:
                    continue
                for item in data[:max_results]:
                    if not isinstance(item, dict):
                        continue
                    name = str(item.get("name") or "").strip()
                    zvg = str(item.get("zvg_nr") or "").strip()
                    cas = str(item.get("cas_nr") or "").strip()
                    if not zvg:
                        continue
                    url = f"{self.GESTIS_WEB_URL}?name={quote(zvg, safe='')}&lang={lang}"
                    if _hostname_matches(url, "gestis.dguv.de") and is_safe_url(url):
                        parts = [p for p in (f"CAS: {cas}" if cas else "", f"ZVG: {zvg}") if p]
                        snippet = f"{' | '.join(parts)} | GESTIS-Stoffdatenbank (DGUV)"
                        results.append(SearchResult(
                            title=name or f"GESTIS {zvg}",
                            url=url,
                            snippet=snippet,
                            source="gesti",
                        ))
                if results:
                    break
        except Exception as e:
            logger.error(f"GESTIS-Fehler: {e}")
        finally:
            if owns_client:
                client.close()
        return results[:max_results]


class GitHubSearcher:
    """GitHub-Suche ueber die offizielle api.github.com (nur Metadaten, kein raw.githubusercontent)."""

    GITHUB_API = "https://api.github.com/search"

    def __init__(self, http_client: "SafeHttpClient"):
        self.client = http_client

    def search(self, query: str, search_type: str = "repositories",
               max_results: int = MAX_SEARCH_RESULTS) -> list[SearchResult]:
        endpoint = "code" if search_type == "code" else "repositories"
        try:
            data = self.client.fetch_json(
                f"{self.GITHUB_API}/{endpoint}",
                params={"q": query, "per_page": min(max_results, 10)},
                headers={"User-Agent": RESEARCH_USER_AGENT, "Accept": "application/vnd.github+json"},
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
    """Nachrichten-Suche via ddgs News (kein API-Key)."""

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
            if "no results found" in str(e).lower():
                logger.debug(f"News keine Treffer fuer '{query}'")
            else:
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
        self.gesti = GESTISearcher(self.http_client)
        self.github = GitHubSearcher(self.http_client)
        self.news = NewsSearcher()
        self.rate_limiter = _GLOBAL_RATE_LIMITER  # geteilt ueber alle Threads
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

    def _run_search(
        self,
        query: str,
        sources: list[str] | None = None,
        max_results: int = MAX_SEARCH_RESULTS,
        follow_links: bool = False,
        max_follow_links: int = MAX_FOLLOW_LINKS,
    ) -> dict:
        """Interne Such-Ausfuehrung (ohne erneuten Rate-Limit-Abzug)."""
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
                        "title": sanitize_for_prompt(r.title), "url": r.url,
                        "snippet": sanitize_for_prompt(r.snippet), "source": r.source,
                    })
                    total_pages += 1
            if "wikipedia" in sources:
                for r in self.wiki.search(query, max_results):
                    all_results.append({
                        "title": sanitize_for_prompt(r.title), "url": r.url,
                        "snippet": sanitize_for_prompt(r.snippet), "source": r.source,
                    })
                    total_pages += 1
            if "arxiv" in sources:
                for r in self.arxiv.search(query, max_results):
                    all_results.append({
                        "title": sanitize_for_prompt(r.title), "url": r.url,
                        "snippet": sanitize_for_prompt(r.snippet), "source": r.source,
                    })
                    total_pages += 1
            if "gesti" in sources:
                for r in self.gesti.search(query, max_results):
                    all_results.append({
                        "title": sanitize_for_prompt(r.title), "url": r.url,
                        "snippet": sanitize_for_prompt(r.snippet), "source": r.source,
                    })
                    total_pages += 1

            if follow_links and max_follow_links > 0:
                all_results, followed_pages = self._follow_links(all_results, max_follow_links, max_results * 3)
                total_pages += followed_pages

            all_results = all_results[: max_results * 3]

            return {
                "success": True, "query": query, "sources_used": sources,
                "total_results": len(all_results), "pages_scraped": total_pages,
                "results": all_results, "warnings": self._generate_warnings(total_pages),
            }
        finally:
            self.reset()

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
        return self._run_search(
            query=query,
            sources=sources,
            max_results=max_results,
            follow_links=follow_links,
            max_follow_links=max_follow_links,
        )

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
            search_results = self._run_search(query, sources, max_pages)
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

        Pipeline (alles ueber SafeHttpClient -> DNS-/Size-/Content-Type-Schutz):
          1. Original-URL gegen is_safe_url pruefen
          2. archive.org/wayback/available -> naechster Snapshot (JSON)
          3. Snapshot-URL gegen is_safe_url + web.archive.org-Domain pruefen
          4. Snapshot laden + HTML zu Text + sanitize_for_prompt (Inhalt + Titel)
        """
        if not is_safe_url(url):
            return {"success": False, "url": url, "error": "URL aus Sicherheitsgruenden blockiert"}
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
            if not is_safe_url(snapshot_url) or not _hostname_matches(snapshot_url, "web.archive.org"):
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
                "timestamp": timestamp, "title": sanitize_for_prompt(title), "content": content,
            }
        except Exception as e:
            logger.error(f"Wayback-Fehler fuer {SafeHttpClient._sanitize_url_for_logging(url)}: {e}")
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

        if _hostname_matches(url, "wikipedia.org"):
            return self.wiki.get_article(url)
        if _hostname_matches(url, "arxiv.org"):
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
                url=url, title=sanitize_for_prompt(title_text), content=content,
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

    Verwendet get_engine() (thread-lokal) statt einer Modul-Engine,
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
            results = eng.wiki.search(query, max_results=5, language=language)
            formatted = [{
                "title": sanitize_for_prompt(r.title), "url": r.url,
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
                "title": sanitize_for_prompt(r.title), "url": r.url,
                "snippet": sanitize_for_prompt(r.snippet)[:500], "source": r.source,
            } for r in results]
            return {"success": True, "query": query, "results": formatted, "count": len(formatted)}
        except Exception as e:
            logger.error(f"search_arxiv interner Fehler: {e!s}")
            return {"success": False, "error": "Ein interner Fehler ist aufgetreten",
                    "query": query, "results": []}

    @tool_dec()
    def search_gesti(query: str) -> dict:
        """Durchsucht die DGUV GESTIS-Stoffdatenbank (Gefahrstoffe).

        Args:
            query: Stoffname (z.B. "Aceton") oder CAS-Nummer (z.B. "67-64-1").
        """
        try:
            eng = get_engine()
            rl_error = eng.check_rate_limit()
            if rl_error:
                rl_error["query"] = query
                return rl_error
            results = eng.gesti.search(query, max_results=5)
            formatted = [{
                "title": sanitize_for_prompt(r.title), "url": r.url,
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
                "title": sanitize_for_prompt(r.title), "url": r.url,
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
                "title": sanitize_for_prompt(r.title), "url": r.url,
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
                "success": True, "url": url, "title": sanitize_for_prompt(title),
                "content": sanitize_for_prompt(content),
                "content_length": len(content),
            }
        except Exception as e:
            logger.error(f"safe_web_scrape interner Fehler: {e!s}")
            return {"success": False, "error": "Ein interner Fehler ist aufgetreten", "url": url}

    @tool_dec()
    def check_url_safety(url: str) -> dict:
        """Prueft OHNE HTTP-Request, ob eine URL erlaubt waere - und warum nicht.

        Bei statisch zulaessigen URLs wird zusaetzlich die DNS-Aufloesung
        (rate-limitiert gegen DNS-Exfiltration) geprueft.

        Args:
            url: Zu pruefende URL (http/https).
        """
        try:
            reasons = explain_url_block(url, check_dns=False)
            if not reasons:
                rl_error = get_engine().check_rate_limit()
                if rl_error:
                    rl_error["url"] = url
                    return rl_error
                hostname = _normalize_hostname(urlparse(url).hostname or "") or ""
                if not resolve_and_verify(hostname):
                    reasons.append("DNS-Aufloesung fehlgeschlagen oder zeigt auf private IP")
            return {
                "success": True,
                "url": url,
                "allowed": not reasons,
                "block_reasons": reasons,
            }
        except Exception as e:
            logger.error(f"check_url_safety interner Fehler: {e!s}")
            return {"success": False, "error": "Ein interner Fehler ist aufgetreten", "url": url}

    @tool_dec()
    def get_server_status() -> dict:
        """Zeigt Status, Limits und erlaubte Quellen des Recherche-Servers.

        Verbraucht KEIN Rate-Limit-Kontingent.
        """
        try:
            return {
                "success": True,
                "server": RESEARCH_SERVER_NAME,
                "allowed_sources": [*sorted(ALLOWED_SOURCES), "github", "news"],
                "rate_limit": {
                    "max_requests": REQUESTS_PER_WINDOW,
                    "window_seconds": WINDOW_SECONDS,
                    "remaining": _GLOBAL_RATE_LIMITER.remaining(),
                },
                "limits": {
                    "max_pages_per_search": MAX_PAGES_PER_SEARCH,
                    "max_search_results": MAX_SEARCH_RESULTS,
                    "max_result_length": MAX_RESULT_LENGTH,
                    "max_response_size_bytes": MAX_RESPONSE_SIZE,
                    "max_redirects": MAX_REDIRECTS,
                    "http_timeout_seconds": HTTP_TIMEOUT,
                },
                "blocked_domains_count": len(BLOCKED_DOMAINS),
                "blocked_extensions_count": len(BLOCKED_EXTENSIONS),
            }
        except Exception as e:
            logger.error(f"get_server_status interner Fehler: {e!s}")
            return {"success": False, "error": "Ein interner Fehler ist aufgetreten"}


# Registriere Tools auf dem research-spezifischen Server
_register_tools_to_server(mcp_research)


# Eigenstaendiger Server-Name + Default-Port (eigenstaendig vom Dateisystem-Server)
RESEARCH_SERVER_NAME = "internet-research-server"
RESEARCH_DEFAULT_PORT = 8766


def main() -> None:
    """Startet den Internet-Recherche-MCP-Server als eigenstaendigen Prozess."""
    args = build_argparser(RESEARCH_SERVER_NAME, default_port=RESEARCH_DEFAULT_PORT).parse_args()

    logger.info("Internet-Recherche Server starting...")
    logger.info("Quellen: DuckDuckGo, Wikipedia, arXiv, GESTIS (DGUV), GitHub API, News, Wayback")

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
