# Internet-Recherche MCP-Server (`internet_recherche.py`)

Eigenständiger MCP-Server (Port **8766**) für sichere Web-Recherche aus der llama.cpp WebUI. Läuft vollständig entkoppelt vom Dateisystem-Server — ohne Dateisystem-Zugriff, ohne Downloads und ausschließlich per HTTP `GET`.

## Start & Installation

```bash
pip install -r requirements-recherche.txt
python internet_recherche.py --host 127.0.0.1 --port 8766 --transport streamable-http
```

Unter Windows alternativ einfach `server_recherche.bat` ausführen.

- **MCP-URL für llama.cpp WebUI:** `http://127.0.0.1:8766/mcp`
- **Transport-Modi:** `streamable-http` (Standard), `sse`, `stdio`
- **CORS & Host:** Identisch zu `server_common.py` (konfigurierbar via `MCP_ALLOWED_ORIGINS`)

## Quellen

| Quelle | Backend | Tool |
|--------|---------|------|
| **DuckDuckGo** | `ddgs` Websuche | `internet_research`, `internet_research_detailed` |
| **Wikipedia** | MediaWiki API (`de`/`en`) | `search_wikipedia`, `internet_research`, `read_webpage` |
| **arXiv** | `export.arxiv.org` Atom API (HTTPS) | `search_arxiv`, `internet_research`, `read_webpage` |
| **GESTIS (DGUV)** | `gestis-api.dguv.de` Gefahrstoffdatenbank | `search_gesti`, `internet_research` |
| **GitHub** | `api.github.com/search` (nur Metadaten) | `search_github` |
| **News** | `ddgs` News-Suche | `search_news` |
| **Wayback Machine** | `archive.org` / `web.archive.org` | `read_archived` |
| **Webseiten direkt** | `SafeHttpClient` | `read_webpage`, `safe_web_scrape` |

## Tools

| Tool | Parameter | Beschreibung |
|------|-----------|--------------|
| `internet_research` | `query`, `sources="duckduckgo,wikipedia"`, `max_results=5`, `follow_links=False` | Kombinierte Suche (`duckduckgo`, `wikipedia`, `arxiv`, `gesti`) |
| `internet_research_detailed` | `query`, `sources="duckduckgo,wikipedia"`, `max_pages=5` | Suche inkl. vollständigem Abruf der gefundenen Seiten (1–10) |
| `read_webpage` | `url` | Einzelne öffentliche URL lesen (mit Wikipedia-/arXiv-API-Fastpath) |
| `safe_web_scrape` | `url`, `max_content_length=3000` | Bereinigten Seitentext extrahieren (100–5 000 Zeichen) |
| `search_wikipedia` | `query`, `language="de"` | Wikipedia gezielt auf `de` oder `en` durchsuchen |
| `search_arxiv` | `query` | Wissenschaftliche Paper auf arXiv suchen |
| `search_gesti` | `query` | Gefahrstoffe nach Stoffname oder CAS-Nummer in GESTIS suchen |
| `search_github` | `query`, `search_type="repositories"`, `max_results=5` | GitHub-Repositories oder Code (erfordert ggf. Token) suchen |
| `search_news` | `query`, `max_results=5` | Aktuelle Nachrichten über DuckDuckGo News |
| `read_archived` | `url` | Neuesten Wayback-Machine-Snapshot einer URL lesen |
| `check_url_safety` | `url` | Prüft ohne HTTP-Request, ob und warum eine URL blockiert würde |
| `get_server_status` | — | Zeigt Limits, Quellen und verbleibendes Rate-Limit (verbraucht kein Kontingent) |

## Sicherheitsarchitektur

Alle direkten HTTP-Aufrufe (Webseiten, Wikipedia, arXiv, GESTIS, GitHub, Wayback Machine) laufen zentral durch `SafeHttpClient`.

### SSRF- & DNS-Rebinding-Schutz

- **Zero-TOCTOU Socket-Validierung (`_SafeSyncBackend`)**: Beim TCP-Verbindungsaufbau wird DNS genau einmal aufgelöst, jede zurückgegebene A/AAAA-IP geprüft und direkt zur validierten IP verbunden (TLS SNI und Zertifikatsprüfung bleiben erhalten). Private IPs erhalten nicht einmal ein TCP-SYN (kein Blind-SSRF).
- **Peer-IP-Verifikation**: Zusätzlich wird nach dem Verbindungsaufbau die tatsächliche Peer-IP des Streams geprüft.
- **Umfassende IP-Klassifikation**: Blockiert alle nicht-globalen Adressen (`not addr.is_global`) inkl. RFC 1918, Loopback, Link-Local / Cloud-Metadata (`169.254.169.254`), CGNAT (`100.64.0.0/10`), Unspecified (`0.0.0.0`, `::`), IPv4-mapped IPv6 (`::ffff:127.0.0.1`), 6to4, Teredo, NAT64 sowie RFC-Testnetze.
- **URL- & Hostname-Normalisierung**:
  - Nur `http`/`https` und Ports `80`/`443` erlaubt.
  - IDNA-/NFKC-Normalisierung gegen Fullwidth- und Unicode-Punkt-Bypasses (`ｌｏｃａｌｈｏｓｔ`, `127。0。0。1`).
  - Vollständige POSIX-`inet_aton`-Erkennung für dezimale, oktale, hexadezimale und verkürzte IPv4-Formen (`2130706433`, `0x7f000001`, `127.1`, `0177.0.0.1`, `0x7f.0.0.1`).
  - Blockiert Steuerzeichen/Null-Bytes, Userinfo (`user:pass@`, `@host`), Backslashes in der Authority und interne Single-Label-Hostnamen.
  - `trust_env=False` verhindert Proxy-/`.netrc`-Bypasses über Umgebungsvariablen.
- **Sichere Redirect-Verfolgung**: Maximal 3 Hops, manuell verfolgt — jeder Hop durchläuft die komplette URL-, DNS- und Socket-Validierung; bei Origin-Wechsel werden sensible Header entfernt.
- **Blocklisten**: Cloud-Metadata-Aliase (`metadata.goog`, `instance-data`), Paste-/File-Hoster (`pastebin.com`, `gist.github.com`, `rentry.co`, `0x0.st`, …), Rohcode-/Modell-Hoster (`raw.githubusercontent.com`, `huggingface.co`, `jsdelivr.net`, …), interne/Darknet-/RFC-2606-Suffixe (`.internal`, `.local`, `.lan`, `.onion`, `.i2p`, `.localhost`, …) sowie ausführbare Dateiendungen (`.exe`, `.dll`, `.ps1`, `.sh`, `.py`, `.hta`, `.msi`, `.wasm`, …).

### Response-, Parser- & DoS-Schutz

- **Nur HTTP `2xx`** wird akzeptiert.
- **Streaming-Byte-Cap**: `Content-Length`-Vorabprüfung plus sofortiger Abbruch im Stream ab **500 KB** (kein Memory-DoS).
- **Content-Type- & Attachment-Prüfung**: Nur Text/HTML/XML/JSON; `Content-Disposition: attachment` mit gefährlicher Endung in `filename` oder `filename*` wird blockiert.
- **HTML- & XML-Schutz**: BeautifulSoup-Eingabe auf **200 KB** begrenzt (`script`, `style`, `iframe`, `svg`, Formulare und alle Attribute werden entfernt); `safe_parse_xml()` lehnt jedes XML mit `DOCTYPE`- oder `ENTITY`-Deklaration ab (Billion-Laughs-/XXE-Schutz).
- **Prozessweites Rate-Limiting**: Global geteiltes Sliding-Window (**30 Anfragen / 60 s**) über alle Worker-Threads (inkl. DNS-Lookups in `check_url_safety`).
- **Limits**: Max. 15 Seiten pro Suche, max. 3 Folgelinks, max. 5 000 Zeichen pro Seite, 15 s HTTP-Timeout, max. 5 gleichzeitige Verbindungen.

### Prompt-Injection-Schutz

Alle externen Inhalte — **einschließlich Seitentiteln und Such-Snippets** — durchlaufen `sanitize_for_prompt()`:

1. Entfernen unsichtbarer Unicode-Format- und Steuerzeichen (ZWSP, Soft-Hyphen, Bidi-Overrides, Unicode-Tag-Zeichen `U+E0000`–`U+E007F`).
2. NFKC-Normalisierung sowie Neutralisierung von `\uXXXX`/`\xXX`-Escapes und HTML-Entity-Dekodierung.
3. Pattern-Matching auf Klartext sowie auf einer diakritika-/homoglyph-gefalteten Prüfkopie (erkennt akzentuierte sowie kyrillische/griechische Bypasses, ohne normale Umlaute zu verändern) gegen:
   - Direkte Anweisungs-Overrides & System-Prompt-Extraktion (EN & DE)
   - Chat-Template- & Tool-Call-Tokens (ChatML, Llama 2/3/4, Gemma, `[TOOL_CALLS]`, `<tool_call>`)
   - MCP-Tool-Missbrauch (inkl. der Dateisystem-Tools) & Shell-/Code-Execution-Muster
   - Exfiltrations- und Jailbreak-Muster
4. Abschließendes HTML-Escaping (Defense-in-Depth).

## Bekannte Einschränkungen

- **DuckDuckGo-Rate-Limits**: Externe Suchmaschinen können bei hoher Abfragefrequenz temporär drosseln oder leere Trefferlisten liefern.
- **Prompt-Injection-Filter sind Defense-in-Depth**: Regex- und Normalisierungsfilter fangen bekannte Muster und Obfuskationen ab, ersetzen aber keine Trennung zwischen Daten und privilegierten Werkzeugen — deshalb laufen Recherche- und Dateisystem-Server als getrennte Prozesse.
- **Wayback-Snapshots**: Es werden ausschließlich Snapshots akzeptiert, deren Ziel-URL auf `web.archive.org` liegt und `is_safe_url()` besteht.
