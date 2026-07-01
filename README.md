# MCP Server für llama.cpp

Zwei **sauber getrennte** Model Context Protocol (MCP) Server für llama.cpp:

| Server | Datei | Port | Zweck |
|--------|-------|------|------|
| **Dateisystem-Server** | `lokales_dateisystem.py` | `8765` | Zugriff auf das lokale Dateisystem (Windows/Linux/macOS) |
| **Internet-Recherche-Server** | `internet_recherche.py` | `8766` | Sichere Web-Recherche (DuckDuckGo, Wikipedia, arXiv, GESTI) |

Jeder Server läuft als **eigener Prozess** mit eigenem Start-Skript. Sie importieren nur ein winziges gemeinsames Bootstrap-Modul ([`server_common.py`](server_common.py)) — sind aber logisch vollständig entkoppelt.

> **Sicherheits-Updates:** Die Dateisystem-Härtung (Mai 2026) siehe [Sicherheit](#sicherheit). Die Internet-Recherche-Härtung (Juli 2026) siehe [`README_internet_recherche.md`](README_internet_recherche.md).

## Schnellstart

1. Python 3.12+ installieren
2. Virtuelle Umgebung einrichten:

   ```bat
   python -m venv .venv
   .venv\Scripts\activate.bat
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

3. **Gewünschten Server starten** (jedes Skript richtet das venv automatisch ein):

   | Skript | Startet | URL für llama.cpp WebUI |
   |--------|---------|------------------------|
   | `server_dateisystem.bat` | Dateisystem-Server | `http://127.0.0.1:8765/mcp` |
   | `server_recherche.bat` | Internet-Recherche-Server | `http://127.0.0.1:8766/mcp` |

   Alternativ direkt:

   ```bat
   python lokales_dateisystem.py --host 127.0.0.1 --port 8765 --transport streamable-http
   python internet_recherche.py --host 127.0.0.1 --port 8766 --transport streamable-http
   ```

> **Hinweis:** Beide Server können **gleichzeitig** laufen (unterschiedliche Ports). Trage die jeweilige `/mcp`-URL (mit Pfad!) in der llama.cpp WebUI ein.

## Abhängigkeiten (schlank)

Für minimale Installationen gibt es zwei Requirements-Dateien — installiere nur das, was du brauchst:

- [`requirements-dateisystem.txt`](requirements-dateisystem.txt) — nur Dateisystem-Server (kein `duckduckgo-search`/`beautifulsoup4` nötig)
- [`requirements-recherche.txt`](requirements-recherche.txt) — nur Internet-Recherche-Server
- [`requirements.txt`](requirements.txt) — beide auf einmal

## Verfügbare Tools

### Dateioperationen

| Tool                  | Beschreibung                                          | Parameter                                             |
|-----------------------|-------------------------------------------------------|-------------------------------------------------------|
| read_file             | Dateiinhalt lesen (max. 50 MB)                        | `path`                                                |
| read_file_binary      | Datei als Base64-codierte Binärdaten lesen (max. 50 MB)| `path`                                               |
| write_file            | Datei schreiben / anhängen (max. 50 MB)               | `path`, `content`, `append=False`, `encoding="utf-8"` |
| write_file_binary     | Binärdaten (Base64) in Datei schreiben (max. 50 MB)   | `path`, `content`, `encoding="base64"`                |
| rename_file           | Datei oder Verzeichnis umbenennen                     | `path`, `new_name`                                    |
| touch_file            | Zeitstempel aktualisieren oder Datei erstellen        | `path`, `times=None`                                  |
| get_file_lines        | Zeilenbereich lesen (Start/Ende Zeile)                | `path`, `start=0`, `end=None`                         |

### Verzeichnisoperationen

| Tool               | Beschreibung                                      | Parameter                                                     |
|--------------------|---------------------------------------------------|---------------------------------------------------------------|
| list_directory     | Verzeichnis auflisten (mit hidden/recursiv)       | `path`, `recursive=False`, `hidden=False`, `max_entries=10000`|
| get_tree           | Verzeichnisbaum (max. 5000 Einträge, Tiefe 1-10)  | `path`, `max_depth=5`, `hidden=False`                         |
| create_directory   | Ordner erstellen (mit Eltern-Pfaden)              | `path`, `parents=True`                                        |
| delete_file        | Datei/Ordner löschen (Symlinks werden NICHT gefolgt)| `path`                                                      |
| count_entries      | Anzahl Dateien/Ordner zählen (max. 10000 rekursiv)| `path`, `recursive=False`                                     |
| empty_directory    | Verzeichnis leeren (Option: Struktur behalten)    | `path`, `keep_structure=True`                                 |
| move_directory     | Komplettes Verzeichnis verschieben                | `source`, `destination`                                       |

### Kopieren & Verschieben

| Tool                | Beschreibung                                   | Parameter                                      |
|---------------------|------------------------------------------------|------------------------------------------------|
| copy_file           | Datei kopieren                                 | `source`, `destination`                        |
| copy_directory      | Verzeichnis rekursiv kopieren                  | `source`, `destination`, `preserve_times=True` |
| move_file           | Datei verschieben / umbenennen                 | `source`, `destination`                        |
| create_hardlink     | Hardlink erstellen                             | `path`, `target`                               |

### Archivoperationen (ZIP-Slip- und ZIP-Bomb-geschützt)

| Tool                 | Beschreibung                                                                   | Parameter                                         |
|----------------------|--------------------------------------------------------------------------------|---------------------------------------------------|
| compress_archive     | Datei/Verzeichnis als ZIP komprimieren (max. 10000 Dateien)                    | `path`, `archive_path`, `compression="DEFLATED"`  |
| decompress_archive   | ZIP-Archiv entpacken — mit Path-Traversal-, Symlink- und Bomb-Schutz           | `archive_path`, `destination`                     |

### Suche

| Tool             | Beschreibung                                            | Parameter                                                        |
|------------------|---------------------------------------------------------|------------------------------------------------------------------|
| search_files     | Dateien mit Glob-Muster suchen (max. 10000 gescannt)    | `path`, `pattern="*"`, `max_results=100`, `case_sensitive=False` |
| get_recent_files | Zuletzt geänderte Dateien finden                        | `path`, `max_results=20`, `time_range_days=7`                    |

### Informationen

| Tool                 | Beschreibung                                          | Parameter                     |
|----------------------|-------------------------------------------------------|-------------------------------|
| get_file_info        | Dateiinformationen (inkl. symlink_target + realpath)  | `path`                        |
| get_disk_usage       | Festplattenauslastung anzeigen                        | `path="."`                    |
| get_working_directory| Aktuelles Arbeitsverzeichnis und System-Info          | (keine)                       |
| get_allowed_roots    | Konfigurierte Root-Pfade und blockierte Pfade         | (keine)                       |
| get_file_hash        | Hash berechnen (MD5, SHA1, SHA256, SHA512), max. 50 MB | `path`, `algorithm="sha256"`  |
| get_file_permissions | Dateiberechtigungen lesen (Unix-Modus)                | `path`                        |
| chmod_file           | Berechtigungen ändern — restriktiv (max. 0o755)       | `path`, `mode`                |
| list_drives          | Alle Laufwerke mit Kapazität anzeigen                 | (keine)                       |
| get_user_directories | Benutzer-Ordner (Desktop, Dokumente, etc.)            | (keine)                       |
| get_temp_directory   | Temp-Verzeichnis mit Speicherplatz-Analyse            | (keine)                       |
| path_exists          | Pfadexistenz und Typ prüfen                           | `path`                        |

### Symlinks

| Tool             | Beschreibung                          | Parameter                              |
|------------------|---------------------------------------|----------------------------------------|
| create_symlink   | Symbolischen Link erstellen           | `path`, `target`, `is_directory=False` |
| resolve_symlink  | Symlink auflösen und Ziel anzeigen    | `path`                                 |

### Internet-Recherche (eigener Server!)

Die Internet-Recherche-Tools laufen auf einem **eigenen Server** (`internet_recherche.py`, Port 8766),
**NICHT** auf dem Dateisystem-Server. Siehe [`README_internet_recherche.md`](README_internet_recherche.md)
für die vollständige Doku und Sicherheitsfeatures.

| Tool                       | Beschreibung                                     |
|----------------------------|--------------------------------------------------|
| internet_research          | Allgemeine Internetsuche (DuckDuckGo, Wikipedia) |
| internet_research_detailed | Suche mit vollständigen Seiteninhalten           |
| read_webpage               | Spezifische URL lesen                            |
| search_wikipedia           | Spezialisierte Wikipedia-Suche                   |
| search_arxiv               | Wissenschaftliche Paper suchen                   |
| search_gesti               | Gefahrstoffdaten suchen                          |
| safe_web_scrape            | Sicheres Scraping beliebiger Webseiten           |

Start: `server_recherche.bat` oder `python internet_recherche.py --port 8766`.

## Sicherheit

Der Dateisystem-Server enthält die folgenden Härtungen gegenüber der Erstversion:

### Kritische Schutzmaßnahmen

- **Symlink-Ziel-Validierung** (`is_path_safe`): Jeder Pfad-Zugriff prüft nicht nur den eingegebenen Pfad, sondern auch das Symlink-Ziel (`os.path.realpath`). Ein Symlink namens `~/legit.txt → /etc/shadow` wird zuverlässig abgelehnt.
- **ZIP-Slip-Schutz** in `decompress_archive`: Pro Eintrag werden absolute Pfade, Drive-Letters, Path-Traversal (`../`) und Symlinks im Archiv abgelehnt. Zusätzlich wird der normalisierte Zielpfad gegen das (real aufgelöste) Zielverzeichnis validiert.
- **ZIP-Bomb-Schutz**: `decompress_archive` weist Archive ab mit:
  - Mehr als 10 000 Dateien
  - Mehr als 500 MB entpacktes Gesamtvolumen
  - Kompressionsverhältnis > 100× bei > 10 MB unkomprimierter Größe
- **Null-Byte-Schutz** in allen Pfad-Eingaben (`\x00` blockiert).

### Hohe Priorität

- **Eintrags-Limits für rekursive Operationen**: `list_directory`, `get_tree`, `count_entries`, `search_files`, `get_recent_files` und `get_temp_directory` brechen nach maximalen Eintragsmengen ab (DoS-Schutz). Antworten enthalten `truncated: true`, wenn das Limit erreicht wurde.
- **Größenlimits**: `read_file`, `read_file_binary`, `write_file`, `write_file_binary`, `get_file_hash` und `get_file_lines` lehnen Dateien über 50 MB ab.
- **Restriktives `chmod_file`**: Akzeptiert nur Modi ≤ 0o755 und blockiert `setuid`, `setgid` und world-writable Bits (kein 0o777, 0o666, 0o4xxx, 0o2xxx).
- **CORS konfigurierbar** statt `*`: Standard ist jetzt eine kommagetrennte Liste von localhost-Origins; per Umgebungsvariable `MCP_ALLOWED_ORIGINS` änderbar.
- **`delete_file` folgt keinen Symlinks**: Symlinks selbst werden gelöscht, nicht das Ziel.
- **Erweiterte blockierte Pfade**: `/etc/sudoers.d`, `/etc/ssh`, `/sys`, `/dev`, `/root/.ssh`, `C:\Windows\System32\drivers`, `C:\$Recycle.Bin`, `C:\System Volume Information` u.a.
- **Bind-Warnung**: Server warnt beim Start, wenn auf `0.0.0.0` oder `::` gebunden wird.

### Konfiguration

Umgebungsvariablen:

| Variable                | Beschreibung                           | Default             |
|-------------------------|----------------------------------------|--------------------------------|
| `MCP_FILESYSTEM_ROOT`   | Startverzeichnis                       | Home-Verzeichnis    |
| `MCP_ALLOWED_ORIGINS`   | Kommagetrennte CORS-Origins. `*` erlaubt alle (NUR für reines Localhost!) | `http://127.0.0.1:8080,http://localhost:8080,http://127.0.0.1:8765,http://localhost:8765`|

Beispiel für Produktion:

```bash
set MCP_ALLOWED_ORIGINS=http://127.0.0.1:8080
python lokales_dateisystem.py --host 127.0.0.1 --port 8765
```

### Bekannte Einschränkungen / nicht behoben

- **TOCTOU-Race**: Zwischen `is_path_safe` und der eigentlichen Datei-Operation könnte ein lokaler Angreifer theoretisch einen Symlink unterschieben. Auf Single-User-Systemen (typischer llama.cpp-Use-Case) ist das kein realistisches Risiko; Mitigation per File-Descriptor-basierter API (`openat`) wurde wegen Portabilitäts-Verlust nicht umgesetzt.
- **Keine eingebaute Authentifizierung**: Beide MCP-Server haben keine Auth-Schicht; das ist im aktuellen MCP-Protokoll auch nicht standardisiert. Schutz erfolgt ausschließlich über das Binding auf `127.0.0.1` (Default) und CORS.
- **chmod_file mit max. 0o755**: Wer 0o775 (Gruppe schreiben) oder 0o770 benötigt, kommt mit dieser Restriktion nicht durch. Begründung: Risiko durch LLM-Fehlsteuerung höher als Nutzen.

## Transport-Modi

| Modus              | Beschreibung                           |
|--------------------|----------------------------------------|
| streamable-http    | HTTP-Transport (empfohlen für WebUI)   |
| sse                | Server-Sent Events                     |
| stdio              | Standard-Ein/Ausgabe (lokale Nutzung)  |

## Hinweis

Der Server nutzt UTF-8-Codierung für Eingabe/Ausgabe. Bei Problemen mit Umlauten bitte sicherstellen, dass die Umgebungsvariablen `PYTHONUTF8=1` und `PYTHONIOENCODING=utf-8` gesetzt sind.

## Beispiel-URLs

```
Dateisystem-Server:   http://127.0.0.1:8765/mcp
Internet-Recherche:    http://127.0.0.1:8766/mcp
```
