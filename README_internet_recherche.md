# Sichere Internet-Recherche für llama.cpp Web UI

Eigenständiger MCP-Server (`internet_recherche.py`, Port **8766**) für sichere
Internet-Recherche. Läuft in einem eigenen Prozess, völlig entkoppelt vom
Dateisystem-Server.

## Übersicht

Dieses Modul bietet **sichere Internet-Recherche-Funktionen** für llama.cpp,
ohne Sicherheitsrisiken einzugehen. Das LLM kann Informationen aus dem Internet
beziehen, aber **keine** Dateien herunterladen, ausführen oder Schreibzugriffe
im Netz durchführen.

> **Sicherheits-Update (Juli 2026):** Gehärtete SSRF-/Exfiltrations-Schutz-
> maßnahmen. Siehe [Abschnitt "Sicherheitsfeatures"](#sicherheitsfeatures).

## Verfügbare Quellen

| Quelle | Beschreibung | Tool |
|--------|-------------|------|
| **DuckDuckGo** | Privatsphäre-freundliche Websuche (kein Tracking) | `internet_research`, `safe_web_scrape` |
| **Wikipedia** | Deutsche und englische Wikipedia | `search_wikipedia`, `internet_research` |
| **arXiv** | Wissenschaftliche Paper (Physik, Mathematik, KI, etc.) | `search_arxiv`, `internet_research` |
| **GESTI** | Gefahrstoffdaten der BG BA (Deutschland) | `search_gesti`, `internet_research` |
| **GitHub** | Repositories/Code via `api.github.com` (sicher) | `search_github` |
| **News** | Aktuelle Nachrichten (DuckDuckGo News) | `search_news` |
| **Wayback** | Archivierte/historische Seiten (`web.archive.org`) | `read_archived` |

## Verfügbare Tools

### 1. `internet_research`

Haupttool für allgemeine Internetsuche.

```python
internet_research(
    query="Python Programmierung",
    sources="duckduckgo,wikipedia",
    max_results=5,
    follow_links=False
)
```

### 2. `internet_research_detailed`

Suche mit vollständigen Seiteninhalten (langsamere, aber detailliertere Ergebnisse).

```python
internet_research_detailed(
    query="Quantencomputing Grundlagen",
    sources="wikipedia,duckduckgo",
    max_pages=5
)
```

### 3. `read_webpage`

Liest eine spezifische URL.

```python
read_webpage("https://de.wikipedia.org/wiki/Python")
```

### 4. `search_wikipedia`

Spezialisierte Wikipedia-Suche.

```python
search_wikipedia("Python Programmiersprache", language="de")
```

### 5. `search_arxiv`

Suche nach wissenschaftlichen Paper.

```python
search_arxiv("attention is all you need")
```

### 6. `search_gesti`

Suche nach Gefahrstoffinformationen.

```python
search_gesti("Aceton")
```

### 7. `safe_web_scrape`

Sicheres Scraping beliebiger Webseiten.

```python
safe_web_scrape("https://example.com/article", max_content_length=3000)
```

### 8. `search_github` (neu)

GitHub-Suche über die offizielle `api.github.com` (sicher, kein `raw.githubusercontent`).

```python
search_github("llama.cpp mcp server", search_type="repositories")
search_github("FastMCP streamable_http", search_type="code")  # braucht ggf. GitHub-Token
```

### 9. `search_news` (neu)

Aktuelle Nachrichten via DuckDuckGo News (kein API-Key).

```python
search_news("KI-Regulierung EU")
```

### 10. `read_archived` (neu)

Ruft eine archivierte Fassung einer URL über die Wayback Machine ab (für gelöschte/historische Seiten).

```python
read_archived("https://example.com/old-article")
```

## Sicherheitsfeatures

### Server-Split & Unifikation des HTTP-Pfads (Juli 2026)

- **Eigenständiger Server**: Recherche läuft als eigener Prozess (Port 8766),
  getrennt vom Dateisystem-Server. Kein Coupling mehr.
- **Wikipedia & arXiv jetzt über `SafeHttpClient`**: Beide Suchmaschinen rufen ihre
  JSON/XML-APIs nicht mehr über nackte, ungeschützte `httpx.Client`s auf, sondern
  über denselben `SafeHttpClient` wie das Web-Scraping. Damit greifen für **alle**
  ausgehenden Requests einheitlich: DNS-Rebinding-Schutz, Size-Limit,
  Content-Type-Whitelist und Connection-IP-Verifikation.
- **`fetch_json()`**: Neue Methode für vertrauenswürdige JSON-APIs (Wikipedia) mit
  denselben Schranken wie `fetch()`.

### SSRF-Schutz (gehärtet, Juli 2026)

- **IP-Encoding-Erkennung auf URL-Ebene**: Dezimal- (`2130706433`), Hex-
  (`0x7f000001`) und oktale (`0177.0.0.1`) IPv4-Codierungen, die auf private/
  Loopback-/Metadata-Netze zeigen, werden zuverlässig blockiert. Notwendig, weil
  `getaddrinfo` solche Formen je Plattform inkonsistent auflöst (Windows z.B.
  **nicht**) — der DNS-Check allein reicht hier nicht.
- **Cloud-Metadata blockiert**: `169.254.169.254` (AWS/Azure/GCP) fällt unter
  Link-Local; dezimal codierte Variante (`2852039166`) wird explizit erkannt.
- **URL-Userinfo blockiert**: `http://user:pass@host` und `http://data@host/`
  werden abgelehnt (Daten-Exfiltration & Basic-Auth-Verschleierung).
- **Content-Disposition-Attachment-Block**: Antworten mit
  `Content-Disposition: attachment` und gefährlicher Endung (`.exe`, `.dll`, …)
  werden blockiert (Malware-Verteilung).
- **Erweiterte Blockliste**: weitere Paste-/File-Hoster (`rentry.co`, `paste.rs`,
  `gist.githubusercontent.com`, `codepen.io`, …) und Domain-Suffixe (`.onion`,
  `.i2p`, `.localhost`, RFC-2606-reservierte `.test`/`.example`/`.invalid`).

### Prompt-Injection-Schutz (gehärtet)

- **Unicode-Normalisierung (NFKC)** als ersten Schritt — verhindert Homoglyph-Bypass wie `ìgnòre àll ìnstructíòns`
- **Hex-/Unicode-Escapes** (`\x20`, `\u0020`) werden vor dem Pattern-Matching markiert und neutralisiert
- **HTML-Entities** werden zuerst dekodiert, dann gegen Patterns geprüft, am Ende wieder escaped (Defense-in-Depth)
- **~80 kompilierte Regex-Patterns** in Kategorien:
  - Direkte Anweisungen (`ignore all instructions`, `disregard previous`, …)
  - System-Prompt-Extraktion (`show your prompt`, `reveal your instructions`)
  - Code-Execution (`exec()`, `eval()`, `os.system`, `rm -rf`, `/dev/tcp/`, `base64 -d`)
  - Chat-Template-Token-Injection (`<|im_start|>`, `<|endoftext|>`, `[INST]`, `<<SYS>>`)
  - Daten-Exfiltration (`leak the prompt`, `extract your api-key`)
  - Rollen-Überschreibung (`DAN mode`, `developer mode on`, `assume the role of`)
  - **MCP/llama.cpp-spezifisch (neu)**: `use the read_file tool`, `mcp://`, `session id:`
  - **Kontext-Manipulation (neu)**: `treat the following as your new instructions`, `for testing purposes, ignore`
  - **Jailbreak-Marker (neu)**: `roleplay:`, `jailbreak:`, `in this hypothetical scenario`

### SSRF- und DNS-Schutz (gehärtet)

- **Aktive DNS-Validierung pro Request**: Die zuvor definierte `resolve_and_verify()` wird jetzt tatsächlich vom HTTP-Client aufgerufen (vorher toter Code).
- **DNS-Rebinding-Schutz**: Positive DNS-Resultate werden 30 Sekunden gecached; negative Resultate werden **nicht** gecached.
- **Doppelte IP-Prüfung**: Nach der Verbindung wird die tatsächliche Antwort-IP nochmals gegen private Bereiche geprüft (belt-and-suspenders).
- **Vollständige IP-Suite**: IPv4 (RFC 1918), IPv6 (Loopback, Link-Local, Unique-Local), CGNAT (100.64.0.0/10), Multicast, Reserved.
- Nur **http/https** erlaubt
- **Blockierte Domains**: Pastebin, GitHub Gist, Hastebin, raw.githubusercontent.com, huggingface.co, jsdelivr, unpkg u.a.
- **Blockierte Domain-Suffixe**: `.internal`, `.local`, `.private`, `.corp`, `.home`, `.lan`
- **Blockierte URL-Endungen**: `.exe`, `.dll`, `.bat`, `.ps1`, `.sh`, `.py`, `.bin`, `.elf` u.a.
- **Keine Redirects** (`follow_redirects=False`)
- **HTTPS für arXiv** (vorher `http://`)
- **Connection-Pool-Limits**: max. 5 gleichzeitige Verbindungen
- **Connection-Limits** für HTTP-Client (max_connections=5)

### Rate-Limiting (jetzt aktiv)

- 30 Anfragen pro 60-Sekunden-Fenster pro Engine-Instanz (vorher: Klasse vorhanden, aber nicht aufgerufen)
- Wird in allen Tools (`internet_research`, `read_webpage`, `search_wikipedia`, `search_arxiv`, `search_gesti`, `safe_web_scrape`) geprüft
- Thread-sicher (Lock-geschützter Deque)

### Thread-Sicherheit (gehärtet)

- **`InternetResearchEngine` ist pro Thread isoliert** (`get_engine()` via `threading.local`)
- `_visited_urls` und `_page_count` durch internes `_state_lock` geschützt
- Wikipedia-API-Calls verwenden eigene kurzlebige Clients (keine geteilte Session)

### Content-Limits

- Max. **15 Seiten** pro Suche
- Max. **3 Folgelinks** pro Seite
- Max. **500 KB** Response-Größe (HTTP)
- Max. **200 KB** HTML-Input für BeautifulSoup (DoS-Schutz beim Parsing)
- Max. **5 000 Zeichen** Output pro Seite
- Max. **15 Sekunden** Timeout pro Anfrage

### Was *nicht* möglich ist

- **Keine Executables**
- **Keine Downloads**
- **Keine Dateioperationen** (lesen/schreiben/löschen)
- **Keine Netzwerk-Schreibzugriffe** (nur GET-Anfragen)
- **Kein Dateisystem-Zugriff**

## Installation

```bash
pip install -r requirements-recherche.txt
```

oder einzeln:

```bash
pip install duckduckgo-search beautifulsoup4 httpx
```

## Verwendung

### Start als eigener Server

```bat
server_recherche.bat
```

oder direkt:

```bash
python internet_recherche.py --host 127.0.0.1 --port 8766 --transport streamable-http
```

MCP-URL für die llama.cpp WebUI: `http://127.0.0.1:8766/mcp`

### Transport-Modi

`streamable-http` (Default, für WebUI), `sse`, `stdio` (lokale Nutzung).

CORS und Bind-Host sind identisch konfiguriert wie beim Dateisystem-Server
(siehe `server_common.py`, Umgebungsvariable `MCP_ALLOWED_ORIGINS`).

## Architektur

```
internet_recherche.py
├── Sicherheits-Utilities
│   ├── is_safe_url()           # URL-Validierung (Schema, Domain, Pfad, Userinfo, IP-Encoding)
│   ├── _decode_ip_hostname()   # dez/hex/oktal IPv4-Encodings entschärfen (SSRF)
│   ├── resolve_and_verify()    # DNS-Aufloesung mit Privat-IP-Check
│   ├── is_private_ip()         # IPv4 + IPv6 + spezielle Netze
│   ├── sanitize_html_to_text() # HTML zu Text (mit Groessen-Limit)
│   └── sanitize_for_prompt()   # NFKC + Hex-Escape + Patterns
│
├── Suchmaschinen
│   ├── DuckDuckGoSearcher
│   ├── WikipediaSearcher
│   ├── ArXivSearcher        (mit https und altem ID-Format)
│   └── GESTISearcher
│
├── SafeHttpClient
│   ├── _verify_host_fresh() # DNS-Cache + Rebinding-Schutz
│   ├── _check_response()    # Size, Content-Type, Attachment, Antwort-IP
│   ├── fetch()              # Text (HTML/XML), mit Sicherheitschecks
│   └── fetch_json()         # JSON-APIs (Wikipedia), mit Sicherheitschecks
│
├── RateLimiter              # Thread-safe Sliding-Window-Limiter
│
└── InternetResearchEngine   # Thread-lokal (get_engine())
    ├── check_rate_limit()
    ├── search()
    ├── search_and_read()
    └── read_url()
```

## Beispiel-Ausgabe

```json
{
    "success": true,
    "query": "Python Programmierung",
    "sources_used": ["duckduckgo", "wikipedia"],
    "total_results": 8,
    "pages_scraped": 2,
    "results": [
        {
            "title": "Python (Programmiersprache)",
            "url": "https://de.wikipedia.org/wiki/Python_(Programmiersprache)",
            "snippet": "Python ist eine...",
            "source": "wikipedia(de)"
        }
    ],
    "warnings": []
}
```

## Rate-Limit-Antwort

Wenn das Rate-Limit überschritten wurde:

```json
{
    "success": false,
    "error": "Rate-Limit ueberschritten (max 30/60s)",
    "query": "...",
    "results": []
}
```

## Bekannte Einschränkungen

- **DDG-Suche unterliegt Rate-Limits seitens DuckDuckGo**: Bei zu vielen Anfragen liefert das `duckduckgo-search`-Paket leere Ergebnisse. Das ist kein Bug dieses Servers.
- **Negative DNS-Resultate werden nicht gecached**: Eine fehlgeschlagene DNS-Aufloesung führt bei jeder weiteren Anfrage zur erneuten Aufloesung. Das ist Absicht (DNS-Rebinding-Schutz), kann aber bei schlechter Netzverbindung zu wiederholten Verzögerungen führen.
- **Wikipedia-Suche prüft nur Klartext-Snippets**: Die Snippets enthalten `<span class="searchmatch">`-Tags, die `sanitize_for_prompt` schluckt.
