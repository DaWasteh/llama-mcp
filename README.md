# MCP-Server für llama.cpp

Zwei eigenständige Model Context Protocol (MCP) Server für die llama.cpp WebUI:

| Server | Datei | Port | Zweck |
|--------|-------|------|-------|
| **Dateisystem-Server** | [`lokales_dateisystem.py`](lokales_dateisystem.py) | `8765` | Zugriff auf das lokale Dateisystem (Windows/Linux/macOS) |
| **Internet-Recherche-Server** | [`internet_recherche.py`](internet_recherche.py) | `8766` | Sichere Web-Recherche (DuckDuckGo, Wikipedia, arXiv, GESTIS, GitHub, News, Wayback) |

Beide Server laufen als getrennte Prozesse ohne gegenseitige Imports und teilen lediglich den HTTP-/CORS-Bootstrap in [`server_common.py`](server_common.py). Details zum Recherche-Server stehen in [`README_internet_recherche.md`](README_internet_recherche.md).

## Schnellstart

1. Python 3.10+ (empfohlen 3.12+) installieren
2. Virtuelle Umgebung einrichten:

   ```bat
   python -m venv .venv
   .venv\Scripts\activate.bat
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

3. Gewünschten Server starten (unter Windows richten die `.bat`-Skripte das `.venv` automatisch ein):

   | Skript | Startet | MCP-URL für llama.cpp WebUI |
   |--------|---------|-----------------------------|
   | `server_dateisystem.bat` | Dateisystem-Server | `http://127.0.0.1:8765/mcp` |
   | `server_recherche.bat` | Internet-Recherche-Server | `http://127.0.0.1:8766/mcp` |

   Direktstart (Windows/Linux/macOS):

   ```bash
   python lokales_dateisystem.py --host 127.0.0.1 --port 8765 --transport streamable-http
   python internet_recherche.py --host 127.0.0.1 --port 8766 --transport streamable-http
   ```

> Beide Server können parallel laufen. In der llama.cpp WebUI muss die vollständige URL inklusive `/mcp`-Pfad eingetragen werden.

## Abhängigkeiten

- [`requirements-dateisystem.txt`](requirements-dateisystem.txt) — nur Dateisystem-Server
- [`requirements-recherche.txt`](requirements-recherche.txt) — nur Internet-Recherche-Server (`ddgs`, `beautifulsoup4`, `httpx`, …)
- [`requirements.txt`](requirements.txt) — beide Server zusammen

## Dateisystem-Tools (`lokales_dateisystem.py`, Port 8765)

### Dateien

| Tool | Beschreibung | Parameter |
|------|--------------|-----------|
| `read_file` | Textdatei lesen (max. 50 MB) | `path` |
| `read_file_binary` | Binärdatei als Base64 lesen (max. 50 MB) | `path` |
| `write_file` | Textdatei schreiben oder anhängen (max. 50 MB) | `path`, `content`, `append=False`, `encoding="utf-8"` |
| `write_file_binary` | Base64-Daten schreiben (max. 50 MB) | `path`, `content`, `encoding="base64"` |
| `find_replace` | Suchen & Ersetzen (literal/Regex, optional Backup, max. 10 MB) | `path`, `pattern`, `replacement`, `use_regex=False`, `count=0`, `backup=False` |
| `rename_file` | Datei oder Ordner umbenennen | `path`, `new_name` |
| `touch_file` | Zeitstempel aktualisieren oder leere Datei anlegen | `path`, `times=None` |
| `get_file_lines` | Zeilenbereich lesen | `path`, `start=0`, `end=None` |

### Verzeichnisse

| Tool | Beschreibung | Parameter |
|------|--------------|-----------|
| `list_directory` | Verzeichnis auflisten (max. 10 000 Einträge) | `path`, `recursive=False`, `hidden=False`, `max_entries=10000` |
| `get_tree` | Verzeichnisbaum (max. 5 000 Einträge, Tiefe 1–10) | `path`, `max_depth=5`, `hidden=False` |
| `create_directory` | Ordner erstellen | `path`, `parents=True` |
| `delete_file` | Datei, Ordner oder Symlink löschen (folgt keinen Symlinks) | `path` |
| `count_entries` | Dateien und Ordner zählen (max. 10 000 rekursiv) | `path`, `recursive=False` |
| `empty_directory` | Verzeichnis leeren | `path`, `keep_structure=True` |
| `move_directory` | Verzeichnis verschieben | `source`, `destination` |

### Kopieren, Verschieben & Links

| Tool | Beschreibung | Parameter |
|------|--------------|-----------|
| `copy_file` | Datei kopieren | `source`, `destination` |
| `copy_directory` | Verzeichnis rekursiv kopieren | `source`, `destination`, `preserve_times=True` |
| `move_file` | Datei verschieben | `source`, `destination` |
| `create_symlink` | Symbolischen Link erstellen | `path`, `target`, `is_directory=False` |
| `resolve_symlink` | Symlink-Ziel auflösen | `path` |
| `create_hardlink` | Hardlink erstellen | `path`, `target` |

### Archive & Suche

| Tool | Beschreibung | Parameter |
|------|--------------|-----------|
| `compress_archive` | ZIP oder Tarball (`.tar.gz`, `.tgz`, `.tar.bz2`, `.tar.xz`) erstellen | `path`, `archive_path`, `compression="DEFLATED"` |
| `decompress_archive` | ZIP/Tarball entpacken (ZIP-Slip-, Symlink- & Bomb-Schutz) | `archive_path`, `destination` |
| `search_files` | Dateien per Glob-Muster suchen (max. 10 000 gescannt) | `path`, `pattern="*"`, `max_results=100`, `case_sensitive=False` |
| `search_content` | Dateiinhalte durchsuchen (Regex, Dateien > 5 MB übersprungen) | `path`, `pattern`, `file_pattern="*"`, `max_results=50`, `context_lines=0` |
| `get_recent_files` | Zuletzt geänderte Dateien finden | `path`, `max_results=20`, `time_range_days=7` |

### System & Status

| Tool | Beschreibung | Parameter |
|------|--------------|-----------|
| `get_file_info` | Metadaten inkl. `symlink_target` und `realpath` | `path` |
| `get_file_hash` | Hash berechnen (`md5`, `sha1`, `sha256`, `sha512`, max. 50 MB) | `path`, `algorithm="sha256"` |
| `get_file_permissions` | Dateiberechtigungen lesen | `path` |
| `chmod_file` | Berechtigungen setzen (max. `0o755`, kein setuid/setgid/world-writable) | `path`, `mode` |
| `get_disk_usage` | Speicherplatz anzeigen | `path="."` |
| `list_drives` | Laufwerke mit Kapazität auflisten | — |
| `get_working_directory` | Arbeitsverzeichnis und System-Info | — |
| `get_user_directories` | Benutzerordner (Desktop, Dokumente, …) | — |
| `get_temp_directory` | Temp-Verzeichnis und Speicherbelegung | — |
| `path_exists` | Existenz und Typ prüfen | `path` |
| `get_allowed_roots` | Erlaubte Roots und blockierte Systempfade | — |
| `get_server_status` | Server-Limits, Root-Konfiguration und Plattform-Info | — |

## Internet-Recherche-Tools (`internet_recherche.py`, Port 8766)

Vollständige Dokumentation und Sicherheitsarchitektur: [`README_internet_recherche.md`](README_internet_recherche.md).

| Tool | Beschreibung |
|------|--------------|
| `internet_research` | Kombinierte Suche über DuckDuckGo, Wikipedia, arXiv und GESTIS |
| `internet_research_detailed` | Suche mit vollständigem Abruf der gefundenen Seiten |
| `read_webpage` | Einzelne öffentliche URL sicher abrufen |
| `safe_web_scrape` | Bereinigten Text einer Webseite mit Längenlimit extrahieren |
| `search_wikipedia` | Wikipedia-Suche (`de` oder `en`) |
| `search_arxiv` | Wissenschaftliche Paper auf arXiv suchen |
| `search_gesti` | Gefahrstoffe in der DGUV GESTIS-Stoffdatenbank suchen (Name oder CAS-Nr.) |
| `search_github` | Repositories/Code über `api.github.com` suchen |
| `search_news` | Aktuelle Nachrichten über DuckDuckGo News |
| `read_archived` | Archivierte Seitenfassung über die Wayback Machine abrufen |
| `check_url_safety` | URL-Sicherheitsprüfung mit detaillierten Blockgründen (ohne HTTP-Request) |
| `get_server_status` | Aktive Limits, Quellen und Rate-Limit-Restkontingent |

## Sicherheit (Dateisystem-Server)

- **Pfad- & Symlink-Schutz**: `is_path_safe()` prüft sowohl den Eingabepfad als auch das aufgelöste `os.path.realpath()` gegen blockierte Systemverzeichnisse (u. a. `/etc/shadow`, `/etc/sudoers*`, `/etc/ssh`, `/sys`, `/dev`, `/root/.ssh`, `C:\Windows\System32\config`, `C:\Windows\System32\drivers`, `C:\$Recycle.Bin`) sowie Null-Bytes. `delete_file` folgt keinen Symlinks.
- **Archiv-Schutz**: `decompress_archive` blockiert absolute Pfade, Drive-Letters, Path-Traversal (`../`), Symlinks im Archiv sowie ZIP-Bombs (> 10 000 Dateien, > 500 MB entpackt oder Kompressionsverhältnis > 100× bei > 10 MB).
- **DoS- & Rechte-Limits**: 50 MB Datei-Limit, max. 10 000 rekursive Einträge (`truncated: true` bei Abbruch), `chmod_file` auf ≤ `0o755` beschränkt.
- **Netzwerk & CORS**: Standard-Bind auf `127.0.0.1` (Warnung bei `0.0.0.0`/`::`), restriktive Localhost-CORS-Liste (`allow_credentials=False`).

### Umgebungsvariablen

| Variable | Beschreibung | Default |
|----------|--------------|---------|
| `MCP_FILESYSTEM_ROOT` | Standard-Wurzelverzeichnis | Home-Verzeichnis |
| `MCP_ALLOWED_ORIGINS` | Kommagetrennte erlaubte CORS-Origins (`*` nur lokal nutzen) | `http://127.0.0.1:8080,http://localhost:8080,http://127.0.0.1:8765,http://localhost:8765,http://127.0.0.1:8766,http://localhost:8766,http://127.0.0.1:1234,http://localhost:1234` |

### Bekannte Einschränkungen

- **Keine eingebaute Authentifizierung**: Zugriffsschutz erfolgt über das lokale Binding (`127.0.0.1`) und CORS. Server nicht ungeschützt ins Netzwerk exponieren.
- **TOCTOU bei Dateisystemzugriffen**: Auf Mehrbenutzersystemen existiert theoretisch ein Zeitfenster zwischen Pfadprüfung und Dateioperation (Single-User-Design).
- **UTF-8 unter Windows**: Bei Umlautproblemen im Terminal `PYTHONUTF8=1` und `PYTHONIOENCODING=utf-8` setzen.

## Transport-Modi

`--transport` unterstützt `streamable-http` (Standard für llama.cpp WebUI), `sse` und `stdio`.
