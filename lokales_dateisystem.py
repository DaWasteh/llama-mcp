"""
MCP Server für lokalen Dateisystem-Zugriff (Windows/Linux/macOS).

Kompatibel mit llama.cpp WebUI via Streamable HTTP Transport.

Sicherheits-Patches (Mai 2026):
- [KRIT] Symlink-Ziel-Validierung (realpath) in is_path_safe()
- [KRIT] ZIP-Slip-Schutz in decompress_archive()
- [KRIT] ZIP-Bomb-Schutz (Decompression-Ratio + Total-Size-Limit)
- [HOCH] Eintragslimits fuer rekursive Operationen (list_directory, get_tree, count_entries, ...)
- [HOCH] CORS jetzt per Umgebungsvariable konfigurierbar (statt "*")
- [HOCH] Dateigroessen-Limit fuer read_file/write_file
- [HOCH] chmod restriktiv: keine setuid/setgid/world-writable
- [HOCH] Null-Byte-Schutz fuer alle Pfad-Eingaben
- [MITT] write_file_binary mit Base64-Decode-Limit
- [MITT] Loggen sicherheitsrelevanter Ereignisse
"""

import base64
import binascii
import contextlib
import fnmatch
import hashlib
import io
import logging
import os
import platform
import shutil
import sys
import tempfile
import time
import zipfile
from datetime import datetime
from pathlib import Path

# ============================================================
# Stderr auf UTF-8 zwingen (Windows-Konsole nutzt sonst cp1252)
# ============================================================
if isinstance(sys.stderr, io.TextIOWrapper):
    with contextlib.suppress(Exception):
        sys.stderr.reconfigure(encoding="utf-8")

# ============================================================
# Logger
# ============================================================
logger = logging.getLogger("lokales_dateisystem")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("[MCP-FS] %(levelname)s %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# ============================================================
# MCP SDK Import
# ============================================================
try:
    from mcp.server.fastmcp import FastMCP
except ImportError as e:
    print(f"FEHLER: MCP SDK nicht korrekt installiert. ({e})", file=sys.stderr)
    print("Fuehre aus: pip install --upgrade mcp", file=sys.stderr)
    sys.exit(1)

# Geteiltes Server-Bootstrap (CORS/Transport/uvicorn) - siehe server_common.py
from server_common import build_argparser, run_mcp_server  # noqa: E402

# ============================================================
# Konfiguration
# ============================================================

SERVER_NAME = "filesystem-server"
DEFAULT_ROOT = os.environ.get("MCP_FILESYSTEM_ROOT", str(Path.home()))

# Blockierte Pfade - Systemkritische Verzeichnisse
BLOCKED_PATHS = {
    # Windows
    r"C:\Windows\System32\config",
    r"C:\Windows\System32\drivers",
    r"C:\Program Files\WindowsApps",
    r"C:\$Recycle.Bin",
    r"C:\System Volume Information",
    # Linux/macOS
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/ssh",
    "/proc/kcore",
    "/proc/sys",
    "/sys",
    "/dev",
    "/root/.ssh",
    # macOS
    "/private/etc/sudoers",
    "/private/etc/master.passwd",
}

ALLOWED_ROOTS = [DEFAULT_ROOT]
IS_WINDOWS = platform.system() == "Windows"

# Sicherheitslimits (Patch)
MAX_FILE_READ_SIZE = 50 * 1024 * 1024  # 50 MB
MAX_FILE_WRITE_SIZE = 50 * 1024 * 1024  # 50 MB
MAX_RECURSIVE_ENTRIES = 10_000  # Max. Eintraege bei rekursiven Listings
MAX_TREE_ENTRIES = 5_000
MAX_ZIP_TOTAL_SIZE = 500 * 1024 * 1024  # 500 MB entpacktes Gesamtvolumen
MAX_ZIP_COMPRESSION_RATIO = 100  # uncompressed/compressed >= 100 => verdaechtig
MAX_ZIP_FILES = 10_000  # Max. Dateien pro Archiv
MAX_BINARY_BASE64_SIZE = 50 * 1024 * 1024  # 50 MB nach Decode


# ============================================================
# Sicherheits-Utilities
# ============================================================


def _has_null_byte(path: str) -> bool:
    """Prueft auf Null-Bytes im Pfad (Bypass-Schutz)."""
    return "\x00" in path


def _normalize_for_compare(path: str) -> str:
    """Pfad fuer Vergleiche normalisieren (case-insensitive auf Windows)."""
    norm = os.path.normpath(path)
    if IS_WINDOWS:
        norm = norm.lower()
    return norm


def is_path_blocked(path: str) -> bool:
    """Prueft, ob ein Pfad in der Blocked-Liste ist (case-insensitive auf Windows).

    Hinweis: Diese Funktion prueft NUR den uebergebenen Pfad, NICHT Symlink-Ziele.
    Fuer eine vollstaendige Sicherheitspruefung is_path_safe() verwenden.
    """
    if _has_null_byte(path):
        return True
    norm = _normalize_for_compare(path)
    for blocked in BLOCKED_PATHS:
        nb = _normalize_for_compare(blocked)
        # Echtes Prefix-Matching (mit Trennzeichen), nicht nur startswith
        if norm == nb or norm.startswith(nb + os.sep) or norm.startswith(nb + "/"):
            return True
    return False


def is_path_safe(path: str, must_exist: bool = False) -> tuple[bool, str]:
    """Vollstaendige Sicherheitspruefung inkl. Symlink-Aufloesung.

    Liefert (ok, reason). Wenn ok=False, ist reason eine kurze Begruendung.

    Prueft:
      1. Null-Byte im Pfad
      2. Blockierte Direkt-Pfade am Original-Pfad (plattformsicher: fängt
         Unix-Pfade wie /etc/shadow auf Windows ab, bevor abspath() sie umbiegt)
      3. Blockierte Pfade nach Aufloesung zu abs_path
      4. Realpath (Symlink-Ziel) ist nicht blockiert
      5. Alle Eltern-Komponenten sind keine Symlinks zu blockierten Zielen
    """
    if _has_null_byte(path):
        return False, "Null-Byte im Pfad"

    # Originalpath pruefen BEVOR os.path.abspath() ihn plattformspezifisch umbaut.
    # Auf Windows wuerde abspath('/etc/shadow') zu 'C:\etc\shadow' werden und
    # den nachfolgenden is_path_blocked()-Check umgehen.
    if is_path_blocked(path):
        return False, f"Pfad blockiert: {path}"

    try:
        abs_path = os.path.abspath(path)
    except Exception:
        return False, "Pfad konnte nicht aufgeloest werden"

    if is_path_blocked(abs_path):
        return False, f"Pfad blockiert: {path}"

    # Symlink-Ziel pruefen (auch wenn die Datei selbst kein Symlink ist,
    # koennte ein Elternteil ein Symlink sein -> realpath beruecksichtigt das)
    try:
        real_path = os.path.realpath(abs_path)
    except (OSError, ValueError):
        return False, "Realpath konnte nicht aufgeloest werden"

    if is_path_blocked(real_path):
        logger.warning(f"Symlink-Ziel zeigt auf blockierten Pfad: {path} -> {real_path}")
        return False, "Symlink-Ziel ist blockiert"

    # Wenn der Pfad selbst ein Symlink ist und das Ziel nicht existiert
    # oder ausserhalb der Root-Hierarchie liegt -> verdaechtig
    if os.path.islink(abs_path) and must_exist and not os.path.exists(real_path):
        return False, "Symlink zeigt auf nicht existierendes Ziel"

    return True, "OK"


def get_file_extension(path: str) -> str:
    """Gibt die Dateiendung zurueck (kleingeschrieben)."""
    return Path(path).suffix.lower()


def is_binary_file(path: str) -> bool:
    """Prueft, ob eine Datei binaer ist basierend auf der Erweiterung."""
    binary_extensions = {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp", ".svg",
        ".ico", ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".mkv",
        ".webm", ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
        ".exe", ".dll", ".so", ".dylib", ".app", ".dmg", ".iso", ".pdf",
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pyc", ".pyo",
        ".class", ".o", ".a", ".lib", ".db", ".sqlite", ".sqlite3",
        ".woff", ".woff2", ".ttf", ".otf", ".cr2", ".nef", ".arw", ".dng",
        ".heic", ".heif",
    }
    return get_file_extension(path) in binary_extensions


# ============================================================
# FastMCP Server-Instanz (eigenstaendig, kein Research-Coupling mehr).
# Internet-Recherche laeuft als eigener Server -> siehe internet_recherche.py
# ============================================================

mcp = FastMCP(SERVER_NAME)


# ============================================================
# Dateioperationen
# ============================================================


@mcp.tool()
def read_file(path: str) -> dict:
    """Liest den Inhalt einer Datei.

    Args:
        path: Absoluter oder relativer Pfad zur Datei.
    """
    ok, reason = is_path_safe(path, must_exist=True)
    if not ok:
        logger.warning(f"read_file abgelehnt: {reason} (Pfad: {path})")
        return {"error": f"Zugriff verweigert: {reason}"}

    abs_path = os.path.abspath(path)

    try:
        size = os.path.getsize(abs_path)
        if size > MAX_FILE_READ_SIZE:
            return {"error": f"Datei zu gross: {size} Bytes (Limit: {MAX_FILE_READ_SIZE})"}

        with open(abs_path, encoding="utf-8") as f:
            content = f.read()
        return {
            "success": True,
            "path": path,
            "content": content,
            "size_bytes": size,
            "lines": len(content.splitlines()),
        }
    except FileNotFoundError:
        return {"error": f"Datei nicht gefunden: {path}"}
    except PermissionError:
        return {"error": f"Keine Berechtigung: {path}"}
    except IsADirectoryError:
        return {"error": f"Pfad ist ein Verzeichnis: {path}"}
    except UnicodeDecodeError:
        try:
            with open(abs_path, "rb") as f:
                data = f.read()
            b64 = base64.b64encode(data).decode()
            return {
                "success": True,
                "path": path,
                "content": b64,
                "binary": True,
                "size_bytes": len(data),
            }
        except Exception as e:
            return {"error": f"Fehler beim Lesen: {e!s}"}


@mcp.tool()
def read_file_binary(path: str) -> dict:
    """Liest eine Datei als Binaerdaten und gibt sie als Base64-codierten String zurueck.

    Args:
        path: Absoluter oder relativer Pfad zur Datei.
    """
    ok, reason = is_path_safe(path, must_exist=True)
    if not ok:
        logger.warning(f"read_file_binary abgelehnt: {reason} (Pfad: {path})")
        return {"error": f"Zugriff verweigert: {reason}"}

    abs_path = os.path.abspath(path)

    try:
        size = os.path.getsize(abs_path)
        if size > MAX_FILE_READ_SIZE:
            return {"error": f"Datei zu gross: {size} Bytes (Limit: {MAX_FILE_READ_SIZE})"}

        with open(abs_path, "rb") as f:
            data = f.read()
        b64 = base64.b64encode(data).decode("ascii")
        return {
            "success": True,
            "path": path,
            "content": b64,
            "binary": True,
            "size_bytes": len(data),
            "encoding": "base64",
            "extension": get_file_extension(path),
        }
    except FileNotFoundError:
        return {"error": f"Datei nicht gefunden: {path}"}
    except PermissionError:
        return {"error": f"Keine Berechtigung: {path}"}
    except IsADirectoryError:
        return {"error": f"Pfad ist ein Verzeichnis: {path}"}
    except Exception as e:
        return {"error": f"Fehler beim Lesen: {e!s}"}


@mcp.tool()
def write_file(path: str, content: str, append: bool = False, encoding: str = "utf-8") -> dict:
    """Schreibt Text in eine Datei.

    Args:
        path: Zielpfad fuer die Datei.
        content: Inhalt, der geschrieben werden soll.
        append: True um anzuhaengen, False zum Ueberschreiben.
        encoding: Zeichencodierung (Default: utf-8).
    """
    ok, reason = is_path_safe(path)
    if not ok:
        logger.warning(f"write_file abgelehnt: {reason} (Pfad: {path})")
        return {"error": f"Zugriff verweigert: {reason}"}

    abs_path = os.path.abspath(path)

    try:
        # Limit pruefen bevor wir schreiben
        encoded_size = len(content.encode(encoding))
        if encoded_size > MAX_FILE_WRITE_SIZE:
            return {"error": f"Inhalt zu gross: {encoded_size} Bytes (Limit: {MAX_FILE_WRITE_SIZE})"}

        mode = "a" if append else "w"
        with open(abs_path, mode, encoding=encoding) as f:
            f.write(content)
        return {
            "success": True,
            "path": path,
            "bytes_written": encoded_size,
            "mode": "append" if append else "write",
            "encoding": encoding,
        }
    except PermissionError:
        return {"error": f"Keine Berechtigung: {path}"}
    except LookupError:
        return {"error": f"Unbekanntes Encoding: {encoding}"}
    except Exception as e:
        return {"error": f"Fehler beim Schreiben: {e!s}"}


@mcp.tool()
def write_file_binary(path: str, content: str, encoding: str = "base64") -> dict:
    """Schreibt Binaerdaten in eine Datei (Base64-codiert).

    Args:
        path: Zielpfad fuer die Datei.
        content: Base64-codierte Binaerdaten.
        encoding: Encoding der Eingabe (Default: base64).
    """
    ok, reason = is_path_safe(path)
    if not ok:
        logger.warning(f"write_file_binary abgelehnt: {reason} (Pfad: {path})")
        return {"error": f"Zugriff verweigert: {reason}"}

    abs_path = os.path.abspath(path)

    try:
        # Frueher Limit-Check auf der Base64-Eingabe (4/3-Verhaeltnis)
        if encoding == "base64":
            estimated_size = (len(content) * 3) // 4
            if estimated_size > MAX_BINARY_BASE64_SIZE:
                return {"error": f"Inhalt zu gross: ~{estimated_size} Bytes (Limit: {MAX_BINARY_BASE64_SIZE})"}
            try:
                data = base64.b64decode(content, validate=True)
            except binascii.Error:
                return {"error": "Ungueltige Base64-Eingabe"}
        else:
            data = content.encode(encoding)

        if len(data) > MAX_BINARY_BASE64_SIZE:
            return {"error": f"Decodierte Groesse zu gross: {len(data)} Bytes"}

        with open(abs_path, "wb") as f:
            f.write(data)
        return {"success": True, "path": path, "bytes_written": len(data)}
    except PermissionError:
        return {"error": f"Keine Berechtigung: {path}"}
    except LookupError:
        return {"error": f"Unbekanntes Encoding: {encoding}"}
    except Exception as e:
        return {"error": f"Fehler beim Schreiben: {e!s}"}


# ============================================================
# Verzeichnisoperationen
# ============================================================


@mcp.tool()
def list_directory(
    path: str,
    recursive: bool = False,
    hidden: bool = False,
    max_entries: int = MAX_RECURSIVE_ENTRIES,
) -> dict:
    """Listet Dateien und Unterverzeichnisse eines Verzeichnisses auf.

    Args:
        path: Pfad zum Verzeichnis.
        recursive: True um Unterverzeichnisse rekursiv zu durchsuchen.
        hidden: True um versteckte Dateien (.dotfiles) anzuzeigen.
        max_entries: Hartes Limit fuer die Anzahl zurueckgegebener Eintraege (DoS-Schutz).
    """
    ok, reason = is_path_safe(path, must_exist=True)
    if not ok:
        return {"error": f"Zugriff verweigert: {reason}"}

    abs_path = os.path.abspath(path)
    max_entries = max(1, min(max_entries, MAX_RECURSIVE_ENTRIES))

    try:
        entries: list[dict] = []
        truncated = False

        if recursive:
            for root, dirs, files in os.walk(abs_path, followlinks=False):
                # Versteckte filtern + blockierte Pfade ueberspringen
                if not hidden:
                    dirs[:] = [d for d in dirs if not d.startswith(".")]
                    files = [f for f in files if not f.startswith(".")]
                dirs[:] = [d for d in dirs if not is_path_blocked(os.path.join(root, d))]

                for d in dirs:
                    if len(entries) >= max_entries:
                        truncated = True
                        break
                    full = os.path.join(root, d)
                    try:
                        st = os.stat(full, follow_symlinks=False)
                        entries.append({
                            "name": os.path.relpath(full, abs_path),
                            "is_directory": True,
                            "size": 0,
                            "modified": datetime.fromtimestamp(st.st_mtime).isoformat(),
                        })
                    except (PermissionError, FileNotFoundError, OSError):
                        pass

                if truncated:
                    break

                for f in files:
                    if len(entries) >= max_entries:
                        truncated = True
                        break
                    full = os.path.join(root, f)
                    try:
                        st = os.stat(full, follow_symlinks=False)
                        entries.append({
                            "name": os.path.relpath(full, abs_path),
                            "is_directory": False,
                            "size": st.st_size,
                            "modified": datetime.fromtimestamp(st.st_mtime).isoformat(),
                        })
                    except (PermissionError, FileNotFoundError, OSError):
                        pass

                if truncated:
                    break
        else:
            for entry in sorted(os.scandir(abs_path), key=lambda e: (not e.is_dir(), e.name)):
                if not hidden and entry.name.startswith("."):
                    continue
                if len(entries) >= max_entries:
                    truncated = True
                    break
                try:
                    st = entry.stat(follow_symlinks=False)
                    entries.append({
                        "name": entry.name,
                        "is_directory": entry.is_dir(),
                        "size": st.st_size,
                        "modified": datetime.fromtimestamp(st.st_mtime).isoformat(),
                    })
                except (PermissionError, FileNotFoundError, OSError):
                    pass

        return {
            "success": True,
            "path": path,
            "recursive": recursive,
            "hidden": hidden,
            "entries": entries,
            "count": len(entries),
            "truncated": truncated,
            "max_entries": max_entries,
        }
    except FileNotFoundError:
        return {"error": f"Verzeichnis nicht gefunden: {path}"}
    except NotADirectoryError:
        return {"error": f"Kein Verzeichnis: {path}"}
    except PermissionError:
        return {"error": f"Keine Berechtigung: {path}"}


@mcp.tool()
def get_tree(path: str, max_depth: int = 5, hidden: bool = False) -> dict:
    """Gibt einen Verzeichnisbaum mit Einrueckung zurueck.

    Args:
        path: Startverzeichnis.
        max_depth: Maximale Tiefe (Default: 5).
        hidden: True um versteckte Dateien anzuzeigen.
    """
    ok, reason = is_path_safe(path, must_exist=True)
    if not ok:
        return {"error": f"Zugriff verweigert: {reason}"}

    abs_path = os.path.abspath(path)
    max_depth = max(1, min(max_depth, 10))  # Tiefe-Limit erzwingen

    try:
        lines = []
        base_depth = abs_path.rstrip(os.sep) + os.sep
        truncated = False
        entry_count = 0

        for root, dirs, files in os.walk(abs_path, followlinks=False):
            current_depth = root[len(base_depth):].count(os.sep) if root.startswith(base_depth) else 0
            if current_depth >= max_depth:
                dirs.clear()
                continue

            if not hidden:
                dirs[:] = sorted([d for d in dirs if not d.startswith(".")])
                files = sorted([f for f in files if not f.startswith(".")])
            else:
                dirs[:] = sorted(dirs)
                files = sorted(files)

            # Blockierte Pfade nicht weiterverfolgen
            dirs[:] = [d for d in dirs if not is_path_blocked(os.path.join(root, d))]

            indent = "  " * current_depth
            lines.append(f"{indent}📁 {os.path.basename(root) or root}/")
            entry_count += 1

            for d in dirs:
                if entry_count >= MAX_TREE_ENTRIES:
                    truncated = True
                    break
                child_indent = "  " * (current_depth + 1)
                lines.append(f"{child_indent}📁 {d}/")
                entry_count += 1

            if truncated:
                break

            for f in files:
                if entry_count >= MAX_TREE_ENTRIES:
                    truncated = True
                    break
                child_indent = "  " * (current_depth + 1)
                full = os.path.join(root, f)
                try:
                    size = os.path.getsize(full)
                    lines.append(f"{child_indent}📄 {f} ({size} Bytes)")
                except (PermissionError, FileNotFoundError, OSError):
                    lines.append(f"{child_indent}📄 {f}")
                entry_count += 1

            if truncated:
                break

        return {
            "success": True,
            "path": path,
            "max_depth": max_depth,
            "hidden": hidden,
            "tree": "\n".join(lines),
            "entry_count": entry_count,
            "truncated": truncated,
        }
    except Exception as e:
        return {"error": f"Fehler: {e!s}"}


@mcp.tool()
def create_directory(path: str, parents: bool = True) -> dict:
    """Erstellt ein neues Verzeichnis.

    Args:
        path: Pfad zum neuen Verzeichnis.
        parents: True um Eltern-Verzeichnisse automatisch anzulegen.
    """
    ok, reason = is_path_safe(path)
    if not ok:
        return {"error": f"Zugriff verweigert: {reason}"}

    abs_path = os.path.abspath(path)

    try:
        if parents:
            os.makedirs(abs_path, exist_ok=True)
        else:
            os.mkdir(abs_path)
        return {"success": True, "path": path, "created": True, "parents": parents}
    except FileExistsError:
        return {"success": True, "path": path, "created": False, "note": "existierte bereits"}
    except FileNotFoundError:
        return {"error": f"Eltern-Verzeichnis fehlt (parents=False): {path}"}
    except Exception as e:
        return {"error": f"Fehler: {e!s}"}


@mcp.tool()
def delete_file(path: str) -> dict:
    """Loescht eine Datei oder ein Verzeichnis (rekursiv).

    Args:
        path: Pfad zur zu loeschenden Datei oder zum Ordner.
    """
    ok, reason = is_path_safe(path, must_exist=True)
    if not ok:
        return {"error": f"Zugriff verweigert: {reason}"}

    abs_path = os.path.abspath(path)

    try:
        # Nicht durch Symlinks loeschen - lstat statt stat
        if os.path.islink(abs_path):
            # Symlink selbst loeschen, NICHT das Ziel
            os.unlink(abs_path)
            return {"success": True, "path": path, "type": "symlink"}

        was_dir = os.path.isdir(abs_path)
        if was_dir:
            shutil.rmtree(abs_path)
        else:
            os.remove(abs_path)
        return {"success": True, "path": path, "type": "directory" if was_dir else "file"}
    except FileNotFoundError:
        return {"error": f"Nicht gefunden: {path}"}
    except PermissionError:
        return {"error": f"Keine Berechtigung: {path}"}
    except Exception as e:
        return {"error": f"Fehler beim Loeschen: {e!s}"}


@mcp.tool()
def count_entries(path: str, recursive: bool = False) -> dict:
    """Zaehlt Dateien und Verzeichnisse in einem Verzeichnis.

    Args:
        path: Pfad zum Verzeichnis.
        recursive: True um Unterverzeichnisse rekursiv zu zaehlen.
    """
    ok, reason = is_path_safe(path, must_exist=True)
    if not ok:
        return {"error": f"Zugriff verweigert: {reason}"}

    abs_path = os.path.abspath(path)

    try:
        file_count = 0
        dir_count = 0
        total_size = 0
        truncated = False
        total_seen = 0

        if recursive:
            for root, dirs, files in os.walk(abs_path, followlinks=False):
                dirs[:] = [d for d in dirs if not is_path_blocked(os.path.join(root, d))]
                dir_count += len(dirs)
                for f in files:
                    total_seen += 1
                    if total_seen > MAX_RECURSIVE_ENTRIES:
                        truncated = True
                        break
                    file_count += 1
                    full = os.path.join(root, f)
                    with contextlib.suppress(PermissionError, FileNotFoundError, OSError):
                        total_size += os.path.getsize(full)
                if truncated:
                    break
        else:
            for entry in os.listdir(abs_path):
                full = os.path.join(abs_path, entry)
                if os.path.isdir(full):
                    dir_count += 1
                else:
                    file_count += 1
                    with contextlib.suppress(PermissionError, FileNotFoundError, OSError):
                        total_size += os.path.getsize(full)

        return {
            "success": True,
            "path": path,
            "recursive": recursive,
            "file_count": file_count,
            "dir_count": dir_count,
            "total_count": file_count + dir_count,
            "total_size_bytes": total_size,
            "truncated": truncated,
        }
    except FileNotFoundError:
        return {"error": f"Verzeichnis nicht gefunden: {path}"}
    except NotADirectoryError:
        return {"error": f"Kein Verzeichnis: {path}"}
    except PermissionError:
        return {"error": f"Keine Berechtigung: {path}"}


@mcp.tool()
def empty_directory(path: str, keep_structure: bool = True) -> dict:
    """Leert ein Verzeichnis (loescht alle Dateien und Unterordner).

    Args:
        path: Pfad zum zu leerenden Verzeichnis.
        keep_structure: True um leere Ordnerstrukturen zu behalten.
    """
    ok, reason = is_path_safe(path, must_exist=True)
    if not ok:
        return {"error": f"Zugriff verweigert: {reason}"}

    abs_path = os.path.abspath(path)

    try:
        if not os.path.isdir(abs_path):
            return {"error": f"Kein Verzeichnis: {path}"}

        deleted_files = 0
        deleted_dirs = 0

        if keep_structure:
            for root, _dirs, files in os.walk(abs_path, topdown=False, followlinks=False):
                for f in files:
                    try:
                        os.remove(os.path.join(root, f))
                        deleted_files += 1
                    except Exception:
                        pass
        else:
            for root, dirs, files in os.walk(abs_path, topdown=False, followlinks=False):
                for f in files:
                    try:
                        os.remove(os.path.join(root, f))
                        deleted_files += 1
                    except Exception:
                        pass
                for d in dirs:
                    try:
                        os.rmdir(os.path.join(root, d))
                        deleted_dirs += 1
                    except Exception:
                        pass
            os.makedirs(abs_path, exist_ok=True)

        return {
            "success": True,
            "path": path,
            "deleted_files": deleted_files,
            "deleted_dirs": deleted_dirs if not keep_structure else 0,
            "keep_structure": keep_structure,
        }
    except PermissionError:
        return {"error": f"Keine Berechtigung: {path}"}
    except Exception as e:
        return {"error": f"Fehler: {e!s}"}


@mcp.tool()
def move_directory(source: str, destination: str) -> dict:
    """Verschiebt ein gesamtes Verzeichnis.

    Args:
        source: Quellverzeichnis.
        destination: Zielverzeichnis.
    """
    ok_s, reason_s = is_path_safe(source, must_exist=True)
    if not ok_s:
        return {"error": f"Quelle: {reason_s}"}
    ok_d, reason_d = is_path_safe(destination)
    if not ok_d:
        return {"error": f"Ziel: {reason_d}"}

    abs_src = os.path.abspath(source)
    abs_dst = os.path.abspath(destination)

    try:
        if not os.path.isdir(abs_src):
            return {"error": f"Quelle ist kein Verzeichnis: {source}"}
        shutil.move(abs_src, abs_dst)
        return {"success": True, "source": source, "destination": destination,
                "absolute_destination": abs_dst}
    except Exception as e:
        return {"error": f"Fehler: {e!s}"}


# ============================================================
# Kopieren & Verschieben
# ============================================================


@mcp.tool()
def copy_file(source: str, destination: str) -> dict:
    """Kopiert eine Datei.

    Args:
        source: Quellpfad.
        destination: Zielpfad.
    """
    ok_s, reason_s = is_path_safe(source, must_exist=True)
    if not ok_s:
        return {"error": f"Quelle: {reason_s}"}
    ok_d, reason_d = is_path_safe(destination)
    if not ok_d:
        return {"error": f"Ziel: {reason_d}"}

    abs_src = os.path.abspath(source)
    abs_dst = os.path.abspath(destination)

    try:
        shutil.copy2(abs_src, abs_dst)
        return {"success": True, "source": source, "destination": destination,
                "bytes_copied": os.path.getsize(abs_dst)}
    except Exception as e:
        return {"error": f"Kopierfehler: {e!s}"}


@mcp.tool()
def copy_directory(source: str, destination: str, preserve_times: bool = True) -> dict:
    """Kopiert ein Verzeichnis rekursiv.

    Args:
        source: Quellverzeichnis.
        destination: Zielverzeichnis.
        preserve_times: True um Zeitstempel zu behalten.
    """
    ok_s, reason_s = is_path_safe(source, must_exist=True)
    if not ok_s:
        return {"error": f"Quelle: {reason_s}"}
    ok_d, reason_d = is_path_safe(destination)
    if not ok_d:
        return {"error": f"Ziel: {reason_d}"}

    abs_src = os.path.abspath(source)
    abs_dst = os.path.abspath(destination)

    try:
        if not os.path.isdir(abs_src):
            return {"error": f"Quelle ist eine Datei, kein Verzeichnis: {source}"}

        if preserve_times:
            # symlinks=False ist Default - aufgeloeste Pfade werden kopiert,
            # was bei diesem Tool gewuenscht ist (kein Symlink-Replication)
            shutil.copytree(abs_src, abs_dst, dirs_exist_ok=True)
        else:
            os.makedirs(abs_dst, exist_ok=True)
            for item in os.listdir(abs_src):
                s = os.path.join(abs_src, item)
                d = os.path.join(abs_dst, item)
                if os.path.isdir(s):
                    copy_directory(s, d, preserve_times=False)
                else:
                    shutil.copy2(s, d)

        return {"success": True, "source": source, "destination": destination}
    except Exception as e:
        return {"error": f"Kopierfehler: {e!s}"}


@mcp.tool()
def move_file(source: str, destination: str) -> dict:
    """Verschiebt oder benennt eine Datei um.

    Args:
        source: Quellpfad.
        destination: Zielpfad.
    """
    ok_s, reason_s = is_path_safe(source, must_exist=True)
    if not ok_s:
        return {"error": f"Quelle: {reason_s}"}
    ok_d, reason_d = is_path_safe(destination)
    if not ok_d:
        return {"error": f"Ziel: {reason_d}"}

    abs_src = os.path.abspath(source)
    abs_dst = os.path.abspath(destination)

    try:
        shutil.move(abs_src, abs_dst)
        return {"success": True, "source": source, "destination": destination}
    except Exception as e:
        return {"error": f"Verschiebefehler: {e!s}"}


@mcp.tool()
def rename_file(path: str, new_name: str) -> dict:
    """Benennt eine Datei oder ein Verzeichnis um.

    Args:
        path: Aktueller Pfad.
        new_name: Neuer Name (nur Dateiname, kein Pfad).
    """
    # new_name darf keine Pfad-Trennzeichen enthalten
    if any(sep in new_name for sep in ("/", "\\", "\x00")):
        return {"error": "new_name darf keine Pfad-Trennzeichen oder Null-Bytes enthalten"}
    if new_name in (".", "..", ""):
        return {"error": "Ungueltiger Name"}

    ok, reason = is_path_safe(path, must_exist=True)
    if not ok:
        return {"error": f"Zugriff verweigert: {reason}"}

    abs_path = os.path.abspath(path)

    try:
        parent = os.path.dirname(abs_path)
        new_path = os.path.join(parent, new_name)
        # Auch Zielpfad pruefen
        ok2, reason2 = is_path_safe(new_path)
        if not ok2:
            return {"error": f"Zielpfad: {reason2}"}

        os.rename(abs_path, new_path)
        return {"success": True, "old_path": path, "new_path": new_name,
                "absolute_new_path": new_path}
    except FileExistsError:
        return {"error": f"Ziel existiert bereits: {new_name}"}
    except Exception as e:
        return {"error": f"Umbenennungsfehler: {e!s}"}


# ============================================================
# Archivoperationen (ZIP) - mit ZIP-Slip-Schutz
# ============================================================


@mcp.tool()
def compress_archive(path: str, archive_path: str, compression: str = "DEFLATED") -> dict:
    """Komprimiert eine Datei oder ein Verzeichnis als ZIP-Archiv.

    Args:
        path: Zu komprimierende Datei oder Verzeichnis.
        archive_path: Pfad fuer das ZIP-Archiv.
        compression: "STORED" oder "DEFLATED" (Default).
    """
    ok_s, reason_s = is_path_safe(path, must_exist=True)
    if not ok_s:
        return {"error": f"Quelle: {reason_s}"}
    ok_d, reason_d = is_path_safe(archive_path)
    if not ok_d:
        return {"error": f"Archiv-Ziel: {reason_d}"}

    abs_path = os.path.abspath(path)
    abs_archive = os.path.abspath(archive_path)

    try:
        compress_type = zipfile.ZIP_DEFLATED if compression == "DEFLATED" else zipfile.ZIP_STORED
        file_count = 0

        with zipfile.ZipFile(abs_archive, "w", compression=compress_type) as zipf:
            if os.path.isdir(abs_path):
                for root, _dirs, files in os.walk(abs_path, followlinks=False):
                    for file in files:
                        if file_count >= MAX_ZIP_FILES:
                            return {"error": f"Zu viele Dateien (Limit: {MAX_ZIP_FILES})"}
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, os.path.dirname(abs_path))
                        zipf.write(file_path, arcname)
                        file_count += 1
            else:
                arcname = os.path.basename(abs_path)
                zipf.write(abs_path, arcname)
                file_count = 1

        return {
            "success": True,
            "source": path,
            "archive": archive_path,
            "archive_size": os.path.getsize(abs_archive),
            "compression": compression,
            "file_count": file_count,
        }
    except Exception as e:
        return {"error": f"Komprimierungsfehler: {e!s}"}


def _is_safe_zip_member(member: zipfile.ZipInfo, dest_dir: str) -> tuple[bool, str]:
    """Prueft, ob ein ZIP-Eintrag sicher entpackt werden kann (ZIP-Slip-Schutz)."""
    name = member.filename

    # Null-Byte
    if "\x00" in name:
        return False, "Null-Byte im Dateinamen"

    # Absoluter Pfad - verboten
    if os.path.isabs(name) or name.startswith("/") or name.startswith("\\"):
        return False, f"Absoluter Pfad nicht erlaubt: {name}"

    # Windows-Drive-Letter
    if len(name) >= 2 and name[1] == ":":
        return False, f"Drive-Letter nicht erlaubt: {name}"

    # Normalisierten Zielpfad berechnen
    target_path = os.path.normpath(os.path.join(dest_dir, name))
    dest_dir_norm = os.path.normpath(dest_dir) + os.sep

    # Sicherstellen, dass das Ziel innerhalb des Zielverzeichnisses bleibt
    if not (target_path + os.sep).startswith(dest_dir_norm) and target_path != os.path.normpath(dest_dir):
        return False, f"Path-Traversal-Versuch: {name}"

    # Symlinks im ZIP - verboten (koennten ausserhalb zeigen)
    # External attr 0xA1ED0000 = Symlink in Unix-ZIP
    if (member.external_attr >> 16) & 0o170000 == 0o120000:
        return False, f"Symlink im Archiv nicht erlaubt: {name}"

    return True, "OK"


@mcp.tool()
def decompress_archive(archive_path: str, destination: str) -> dict:
    """Entpackt ein ZIP-Archiv in ein Zielverzeichnis.

    Mit ZIP-Slip-Schutz, ZIP-Bomb-Schutz und Eintragslimit.

    Args:
        archive_path: Pfad zum ZIP-Archiv.
        destination: Zielverzeichnis.
    """
    ok_a, reason_a = is_path_safe(archive_path, must_exist=True)
    if not ok_a:
        return {"error": f"Archiv: {reason_a}"}
    ok_d, reason_d = is_path_safe(destination)
    if not ok_d:
        return {"error": f"Ziel: {reason_d}"}

    abs_archive = os.path.abspath(archive_path)
    abs_dest = os.path.abspath(destination)

    try:
        if not zipfile.is_zipfile(abs_archive):
            return {"error": f"Keine gueltige ZIP-Datei: {archive_path}"}

        os.makedirs(abs_dest, exist_ok=True)

        # Auf real existierendes Zielverzeichnis aufloesen (nach makedirs)
        real_dest = os.path.realpath(abs_dest)
        if is_path_blocked(real_dest):
            return {"error": "Zielverzeichnis-Realpath blockiert"}

        extracted: list[str] = []
        total_size = 0
        rejected: list[dict] = []

        with zipfile.ZipFile(abs_archive, "r") as zipf:
            members = zipf.infolist()

            # Pre-Check: Anzahl Dateien
            if len(members) > MAX_ZIP_FILES:
                return {"error": f"Zu viele Dateien im Archiv: {len(members)} (Limit: {MAX_ZIP_FILES})"}

            # Pre-Check: Gesamtgroesse (decompression bomb)
            total_uncompressed = sum(m.file_size for m in members)
            if total_uncompressed > MAX_ZIP_TOTAL_SIZE:
                return {"error": f"Entpacktes Volumen zu gross: {total_uncompressed} (Limit: {MAX_ZIP_TOTAL_SIZE})"}

            # Compression-Ratio gegen ZIP-Bombs
            total_compressed = sum(m.compress_size for m in members) or 1
            ratio = total_uncompressed / total_compressed
            if ratio > MAX_ZIP_COMPRESSION_RATIO and total_uncompressed > 10 * 1024 * 1024:
                logger.warning(f"Verdaechtige Compression-Ratio: {ratio:.1f} ({archive_path})")
                return {"error": f"Verdaechtige Compression-Ratio ({ratio:.1f}x), Archiv abgelehnt"}

            # Pro-Eintrag Validierung und Extraktion
            for member in members:
                safe, why = _is_safe_zip_member(member, real_dest)
                if not safe:
                    logger.warning(f"ZIP-Member abgelehnt: {member.filename} - {why}")
                    rejected.append({"name": member.filename, "reason": why})
                    continue

                # Sicher entpacken: zipfile.extract() ist auf modernen Pythons
                # selbst Slip-resistent, aber wir haben zusaetzlich vorgeprueft
                zipf.extract(member, real_dest)
                extracted.append(member.filename)
                total_size += member.file_size

        result = {
            "success": True,
            "archive": archive_path,
            "destination": destination,
            "extracted_count": len(extracted),
            "rejected_count": len(rejected),
            "total_size_bytes": total_size,
            "files": extracted[:100],  # nicht alles ausgeben
        }
        if rejected:
            result["rejected"] = rejected[:20]
            result["warning"] = f"{len(rejected)} Eintraege abgelehnt (siehe rejected)"
        return result
    except Exception as e:
        return {"error": f"Entpackfehler: {e!s}"}


# ============================================================
# Suche
# ============================================================


@mcp.tool()
def search_files(path: str, pattern: str = "*", max_results: int = 100,
                 case_sensitive: bool = False) -> dict:
    """Durchsucht Dateien rekursiv mit einem Glob-Muster.

    Args:
        path: Startverzeichnis.
        pattern: Glob-Muster (z.B. '*.txt').
        max_results: Maximale Anzahl Ergebnisse.
        case_sensitive: Case-sensitiv vergleichen.
    """
    ok, reason = is_path_safe(path, must_exist=True)
    if not ok:
        return {"error": f"Zugriff verweigert: {reason}"}

    abs_path = os.path.abspath(path)
    max_results = max(1, min(max_results, 1000))

    try:
        results = []
        scanned = 0
        for root, dirs, files in os.walk(abs_path, followlinks=False):
            dirs[:] = [d for d in dirs if not is_path_blocked(os.path.join(root, d))]
            for name in files:
                scanned += 1
                if scanned > MAX_RECURSIVE_ENTRIES:
                    break
                if case_sensitive:
                    match = fnmatch.fnmatch(name, pattern)
                else:
                    match = fnmatch.fnmatch(name.lower(), pattern.lower())
                if match:
                    full = os.path.join(root, name)
                    try:
                        results.append({
                            "path": os.path.relpath(full, abs_path),
                            "absolute_path": full,
                            "size": os.path.getsize(full),
                            "modified": datetime.fromtimestamp(os.path.getmtime(full)).isoformat(),
                        })
                        if len(results) >= max_results:
                            break
                    except (PermissionError, FileNotFoundError, OSError):
                        pass
            if len(results) >= max_results or scanned > MAX_RECURSIVE_ENTRIES:
                break

        return {
            "success": True,
            "path": path,
            "pattern": pattern,
            "case_sensitive": case_sensitive,
            "results": results,
            "count": len(results),
            "files_scanned": scanned,
        }
    except Exception as e:
        return {"error": f"Fehler: {e!s}"}


@mcp.tool()
def get_recent_files(path: str, max_results: int = 20, time_range_days: int = 7) -> dict:
    """Gibt die zuletzt geaenderten Dateien zurueck.

    Args:
        path: Startverzeichnis.
        max_results: Maximale Anzahl Ergebnisse.
        time_range_days: Nur Dateien der letzten N Tage.
    """
    ok, reason = is_path_safe(path, must_exist=True)
    if not ok:
        return {"error": f"Zugriff verweigert: {reason}"}

    abs_path = os.path.abspath(path)
    max_results = max(1, min(max_results, 500))

    try:
        cutoff = time.time() - (time_range_days * 86400)
        recent = []
        scanned = 0

        for root, dirs, files in os.walk(abs_path, followlinks=False):
            dirs[:] = [d for d in dirs if not is_path_blocked(os.path.join(root, d))]
            for name in files:
                scanned += 1
                if scanned > MAX_RECURSIVE_ENTRIES:
                    break
                full = os.path.join(root, name)
                try:
                    mtime = os.path.getmtime(full)
                    if mtime >= cutoff:
                        recent.append({
                            "path": os.path.relpath(full, abs_path),
                            "absolute_path": full,
                            "size": os.path.getsize(full),
                            "modified": datetime.fromtimestamp(mtime).isoformat(),
                            "age_days": round((time.time() - mtime) / 86400, 1),
                        })
                except (PermissionError, FileNotFoundError, OSError):
                    pass
            if scanned > MAX_RECURSIVE_ENTRIES:
                break

        recent.sort(key=lambda x: str(x["modified"]), reverse=True)
        recent = recent[:max_results]

        return {
            "success": True,
            "path": path,
            "time_range_days": time_range_days,
            "results": recent,
            "count": len(recent),
            "files_scanned": scanned,
        }
    except Exception as e:
        return {"error": f"Fehler: {e!s}"}


# ============================================================
# Informationen
# ============================================================


@mcp.tool()
def get_file_info(path: str) -> dict:
    """Gibt Details ueber eine Datei oder einen Ordner zurueck.

    Args:
        path: Pfad zur Datei/Ordner.
    """
    ok, reason = is_path_safe(path)
    if not ok:
        return {"error": f"Zugriff verweigert: {reason}"}

    abs_path = os.path.abspath(path)

    try:
        stat = os.stat(abs_path, follow_symlinks=False)
        info: dict = {
            "success": True,
            "path": path,
            "absolute_path": abs_path,
            "is_directory": os.path.isdir(abs_path),
            "is_file": os.path.isfile(abs_path),
            "is_symlink": os.path.islink(abs_path),
            "size_bytes": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
            "extension": get_file_extension(abs_path),
        }
        if os.path.islink(abs_path):
            with contextlib.suppress(OSError):
                info["symlink_target"] = os.readlink(abs_path)
                info["realpath"] = os.path.realpath(abs_path)
        return info
    except FileNotFoundError:
        return {"error": f"Nicht gefunden: {path}"}
    except Exception as e:
        return {"error": f"Fehler: {e!s}"}


@mcp.tool()
def get_disk_usage(path: str = ".") -> dict:
    """Gibt die Festplattenauslastung zurueck.

    Args:
        path: Pfad fuer das zu pruefende Laufwerk.
    """
    ok, reason = is_path_safe(path)
    if not ok:
        return {"error": f"Zugriff verweigert: {reason}"}

    abs_path = os.path.abspath(path)

    try:
        _, total_bytes, free_bytes = shutil.disk_usage(abs_path)
        used_bytes = total_bytes - free_bytes
        percent_used = (used_bytes / total_bytes * 100) if total_bytes > 0 else 0

        def format_size(size_bytes: float) -> str:
            size = float(size_bytes)
            for unit in ["B", "KB", "MB", "GB", "TB"]:
                if size < 1024.0:
                    return f"{size:.2f} {unit}"
                size /= 1024.0
            return f"{size:.2f} PB"

        return {
            "success": True,
            "path": path,
            "total": format_size(total_bytes),
            "used": format_size(used_bytes),
            "free": format_size(free_bytes),
            "used_percent": f"{percent_used:.1f}%",
            "total_bytes": total_bytes,
            "used_bytes": used_bytes,
            "free_bytes": free_bytes,
        }
    except Exception as e:
        return {"error": f"Fehler: {e!s}"}


@mcp.tool()
def get_allowed_roots() -> dict:
    """Gibt die konfigurierten Root-Pfade und blockierten Pfade zurueck."""
    return {
        "success": True,
        "default_root": DEFAULT_ROOT,
        "allowed_roots": ALLOWED_ROOTS,
        "blocked_paths": list(BLOCKED_PATHS),
        "environment_root": os.environ.get("MCP_FILESYSTEM_ROOT", "nicht gesetzt"),
    }


@mcp.tool()
def get_working_directory() -> dict:
    """Gibt das aktuelle Arbeitsverzeichnis und Systeminformationen zurueck."""
    return {
        "success": True,
        "cwd": os.getcwd(),
        "home": str(Path.home()),
        "system": platform.system(),
        "python_version": platform.python_version(),
    }


@mcp.tool()
def get_file_hash(path: str, algorithm: str = "sha256") -> dict:
    """Berechnet den Hash-Wert einer Datei.

    Args:
        path: Pfad zur Datei.
        algorithm: "md5", "sha1", "sha256", "sha512".
    """
    ok, reason = is_path_safe(path, must_exist=True)
    if not ok:
        return {"error": f"Zugriff verweigert: {reason}"}

    abs_path = os.path.abspath(path)

    try:
        if os.path.isdir(abs_path):
            return {"error": f"Keine Datei (Verzeichnis): {path}"}

        size = os.path.getsize(abs_path)
        if size > MAX_FILE_READ_SIZE:
            return {"error": f"Datei zu gross fuer Hash: {size} Bytes"}

        h = hashlib.new(algorithm)
        with open(abs_path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)

        return {
            "success": True,
            "path": path,
            "algorithm": algorithm,
            "hash": h.hexdigest(),
            "size_bytes": size,
        }
    except ValueError:
        return {"error": f"Unbekannter Algorithmus: {algorithm}. Verwende: md5, sha1, sha256, sha512"}
    except Exception as e:
        return {"error": f"Fehler: {e!s}"}


@mcp.tool()
def get_file_permissions(path: str) -> dict:
    """Gibt die Dateiberechtigungen zurueck.

    Args:
        path: Pfad zur Datei oder zum Verzeichnis.
    """
    ok, reason = is_path_safe(path, must_exist=True)
    if not ok:
        return {"error": f"Zugriff verweigert: {reason}"}

    abs_path = os.path.abspath(path)

    try:
        stat = os.stat(abs_path, follow_symlinks=False)
        mode = stat.st_mode

        def format_perms(mode_val, flag):
            r = "r" if mode_val & flag else "-"
            w = "w" if mode_val & (flag >> 1) else "-"
            x = "x" if mode_val & (flag >> 2) else "-"
            return f"{r}{w}{x}"

        user = format_perms(mode, 0o400) + format_perms(mode, 0o200) + format_perms(mode, 0o100)
        group = format_perms(mode, 0o040) + format_perms(mode, 0o020) + format_perms(mode, 0o010)
        other = format_perms(mode, 0o004) + format_perms(mode, 0o002) + format_perms(mode, 0o001)

        result: dict = {
            "success": True,
            "path": path,
            "octal": oct(mode & 0o777),
            "human": f"{user}{group}{other}",
            "user": user,
            "group": group,
            "other": other,
        }
        if IS_WINDOWS:
            result["windows_acl"] = True
            result["note"] = "Windows verwendet ACL statt Unix-Berechtigungen"
        return result
    except Exception as e:
        return {"error": f"Fehler: {e!s}"}


# Restriktive chmod-Maske: verbietet setuid, setgid, sticky und world-writable
_CHMOD_FORBIDDEN_BITS = 0o4000 | 0o2000 | 0o002  # setuid, setgid, world-writable
_CHMOD_MAX_MODE = 0o755  # Nichts darueber zulassen (kein 777, kein 666)


@mcp.tool()
def chmod_file(path: str, mode: str) -> dict:
    """Aendert die Dateiberechtigungen (restriktiv: max. 0o755, kein setuid/setgid/world-writable).

    Args:
        path: Pfad zur Datei/Ordner.
        mode: Octal-Modus, z.B. "755", "644", "700".
    """
    ok, reason = is_path_safe(path, must_exist=True)
    if not ok:
        return {"error": f"Zugriff verweigert: {reason}"}

    abs_path = os.path.abspath(path)

    try:
        mode_int = int(mode, 8)

        # Restriktive Validierung (Patch)
        if mode_int & _CHMOD_FORBIDDEN_BITS:
            return {"error": "Verbotene Bits: setuid/setgid/world-writable sind nicht erlaubt"}
        if mode_int > _CHMOD_MAX_MODE:
            return {"error": f"Modus {oct(mode_int)} ueberschreitet erlaubtes Maximum {oct(_CHMOD_MAX_MODE)}"}
        if mode_int < 0:
            return {"error": "Negativer Modus nicht erlaubt"}

        os.chmod(abs_path, mode_int)
        return {
            "success": True,
            "path": path,
            "new_mode": oct(mode_int),
            "note": "Berechtigungen geaendert (restriktiv: max 0o755)",
        }
    except ValueError:
        return {"error": f"Ungueltiger Octal-Modus: {mode}. Verwende z.B. 755, 644, 700"}
    except PermissionError:
        return {"error": f"Keine Berechtigung zum Aendern: {path}"}
    except Exception as e:
        return {"error": f"Fehler: {e!s}"}


@mcp.tool()
def list_drives() -> dict:
    """Gibt alle Laufwerke mit Kapazitaet zurueck."""
    try:
        drives = []
        if IS_WINDOWS:
            for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                path = f"{letter}:\\"
                if os.path.exists(path):
                    try:
                        _, total, free = shutil.disk_usage(path)
                        drives.append({
                            "drive": f"{letter}:",
                            "path": path,
                            "total": f"{total / (1024**3):.2f} GB",
                            "free": f"{free / (1024**3):.2f} GB",
                            "used_percent": round((1 - free / total) * 100, 1) if total > 0 else 0,
                        })
                    except Exception:
                        pass
        else:
            import subprocess
            try:
                result = subprocess.run(["df", "-h"], capture_output=True, text=True, timeout=5)
                for line in result.stdout.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 6:
                        drives.append({
                            "device": parts[0],
                            "mountpoint": parts[5],
                            "size": parts[1],
                            "used": parts[2],
                            "available": parts[3],
                            "use_percent": parts[4],
                        })
            except Exception:
                _, total, free = shutil.disk_usage("/")
                drives.append({
                    "device": "/",
                    "mountpoint": "/",
                    "total": f"{total / (1024**3):.2f} GB",
                    "free": f"{free / (1024**3):.2f} GB",
                })

        return {"success": True, "system": platform.system(), "drives": drives, "count": len(drives)}
    except Exception as e:
        return {"error": f"Fehler: {e!s}"}


@mcp.tool()
def get_user_directories() -> dict:
    """Gibt die Standard-Benutzerordner zurueck (Desktop, Dokumente, Downloads, etc.)."""
    try:
        home = Path.home()
        result: dict = {"success": True, "home": str(home)}

        if IS_WINDOWS:
            import ctypes
            # SHGetFolderPathW(hwnd, nFolder, hToken, dwFlags, pszPath(LPWSTR-Buffer)).
            # Der pszPath-Buffer (5. Argument) ist PFLICHT - ohne ihn schreibt die
            # Funktion nach NULL -> Access Violation (interpreter crash).
            folders_map = {
                "Desktop": 0x0010, "Documents": 0x0005, "Downloads": 0x001E,
                "Music": 0x000B, "Pictures": 0x000C, "Videos": 0x000E,
                "Favorites": 0x0006, "Startup": 0x0007, "Programs": 0x0002,
                "AppData_Roaming": 0x001A, "AppData_Local": 0x001C,
            }
            for folder_name, folder_id in folders_map.items():
                try:
                    buf = ctypes.create_unicode_buffer(260)  # MAX_PATH
                    # Rueckgabe 0 == S_OK
                    if ctypes.windll.shell32.SHGetFolderPathW(None, folder_id, None, 0, buf) == 0:  # type: ignore[attr-defined]
                        result[folder_name] = buf.value
                    else:
                        result[folder_name] = str(home / folder_name.replace("_", "/"))
                except Exception:
                    result[folder_name] = str(home / folder_name.replace("_", "/"))
        else:
            xdg_dirs = {
                "Desktop": ("XDG_DESKTOP_DIR", "Desktop"),
                "Documents": ("XDG_DOCUMENTS_DIR", "Documents"),
                "Downloads": ("XDG_DOWNLOAD_DIR", "Downloads"),
                "Music": ("XDG_MUSIC_DIR", "Music"),
                "Pictures": ("XDG_PICTURES_DIR", "Pictures"),
                "Videos": ("XDG_VIDEOS_DIR", "Videos"),
            }
            for name, default in xdg_dirs.items():
                xdg = os.environ.get(default[0])
                if xdg and os.path.isdir(xdg):
                    result[name] = xdg
                else:
                    result[name] = str(home / default[1])
        return result
    except Exception as e:
        return {"error": f"Fehler: {e!s}"}


@mcp.tool()
def get_temp_directory() -> dict:
    """Gibt das temporaere Verzeichnis und dessen Belegung zurueck."""
    try:
        temp_dir = tempfile.gettempdir()
        abs_temp = os.path.abspath(temp_dir)

        temp_files = []
        total_temp_size = 0
        file_count = 0
        dir_count = 0
        scanned = 0

        if os.path.exists(abs_temp):
            for entry in os.scandir(abs_temp):
                scanned += 1
                if scanned > MAX_TREE_ENTRIES:
                    break
                try:
                    size = entry.stat(follow_symlinks=False).st_size
                    total_temp_size += size
                    if entry.is_file():
                        file_count += 1
                        temp_files.append({
                            "name": entry.name,
                            "size": size,
                            "modified": datetime.fromtimestamp(entry.stat().st_mtime).isoformat(),
                        })
                    else:
                        dir_count += 1
                except Exception:
                    pass

        def get_size_for_sort(x: dict[str, object]) -> int:
            size = x.get("size", 0)
            return size if isinstance(size, int) else 0

        temp_files.sort(key=get_size_for_sort, reverse=True)

        _, total_bytes, free_bytes = shutil.disk_usage(abs_temp)
        used_bytes = total_bytes - free_bytes

        def format_size(size_bytes):
            for unit in ["B", "KB", "MB", "GB", "TB"]:
                if size_bytes < 1024.0:
                    return f"{size_bytes:.2f} {unit}"
                size_bytes /= 1024.0
            return f"{size_bytes:.2f} PB"

        return {
            "success": True,
            "temp_directory": temp_dir,
            "absolute_path": abs_temp,
            "system": platform.system(),
            "file_count": file_count,
            "directory_count": dir_count,
            "total_size": format_size(total_temp_size),
            "total_size_bytes": total_temp_size,
            "disk_total": format_size(total_bytes),
            "disk_free": format_size(free_bytes),
            "disk_used_percent": round((used_bytes / total_bytes * 100), 1) if total_bytes > 0 else 0,
            "top_files": temp_files[:10],
        }
    except Exception as e:
        return {"error": f"Fehler: {e!s}"}


@mcp.tool()
def path_exists(path: str) -> dict:
    """Prueft, ob ein Pfad existiert, und gibt den Typ zurueck.

    Args:
        path: Zu pruefender Pfad.
    """
    if _has_null_byte(path):
        return {"error": "Null-Byte im Pfad"}

    abs_path = os.path.abspath(path)
    return {
        "success": True,
        "path": path,
        "absolute_path": abs_path,
        "exists": os.path.exists(abs_path),
        "is_file": os.path.isfile(abs_path),
        "is_directory": os.path.isdir(abs_path),
        "is_symlink": os.path.islink(abs_path),
        "is_absolute": os.path.isabs(path),
    }


@mcp.tool()
def touch_file(path: str, times: list[float] | None = None) -> dict:
    """Aktualisiert den Zeitstempel einer Datei oder erstellt sie.

    Args:
        path: Pfad zur Datei.
        times: [mtime, atime] als Unix-Timestamps. None = aktuelle Zeit.
    """
    ok, reason = is_path_safe(path)
    if not ok:
        return {"error": f"Zugriff verweigert: {reason}"}

    abs_path = os.path.abspath(path)

    try:
        created = not os.path.exists(abs_path)
        if times and len(times) == 2:
            mtime, atime = times
            if not os.path.exists(abs_path):
                Path(abs_path).touch()
                created = True
            os.utime(abs_path, (atime, mtime))
        else:
            if not os.path.exists(abs_path):
                Path(abs_path).touch()
                created = True
            else:
                now = time.time()
                os.utime(abs_path, (now, now))

        return {
            "success": True,
            "path": path,
            "created": created,
            "new_mtime": datetime.fromtimestamp(os.path.getmtime(abs_path)).isoformat(),
        }
    except Exception as e:
        return {"error": f"Fehler: {e!s}"}


@mcp.tool()
def get_file_lines(path: str, start: int = 0, end: int | None = None) -> dict:
    """Liest einen Zeilenbereich einer Datei.

    Args:
        path: Pfad zur Datei.
        start: Erste Zeile (0-basiert).
        end: Letzte Zeile (exklusiv, None = bis Ende).
    """
    ok, reason = is_path_safe(path, must_exist=True)
    if not ok:
        return {"error": f"Zugriff verweigert: {reason}"}

    abs_path = os.path.abspath(path)

    try:
        if os.path.isdir(abs_path):
            return {"error": f"Keine Datei (Verzeichnis): {path}"}

        size = os.path.getsize(abs_path)
        if size > MAX_FILE_READ_SIZE:
            return {"error": f"Datei zu gross: {size} Bytes"}

        with open(abs_path, encoding="utf-8") as f:
            all_lines = f.readlines()

        total_lines = len(all_lines)
        selected = all_lines[start:end]

        return {
            "success": True,
            "path": path,
            "total_lines": total_lines,
            "start": start,
            "end": end if end else total_lines,
            "returned_lines": len(selected),
            "content": "".join(selected),
            "lines": [line.rstrip("\n") for line in selected],
        }
    except UnicodeDecodeError:
        return {"error": f"Binaerdatei (kann nicht zeilenweise gelesen werden): {path}"}
    except Exception as e:
        return {"error": f"Fehler: {e!s}"}


# ============================================================
# Symlinks & Hardlinks
# ============================================================


@mcp.tool()
def create_symlink(path: str, target: str, is_directory: bool = False) -> dict:
    """Erstellt einen Symlink.

    Args:
        path: Pfad fuer den neuen Symlink.
        target: Ziel, auf das der Symlink zeigt.
        is_directory: True wenn das Ziel ein Verzeichnis ist (Windows).
    """
    ok_p, reason_p = is_path_safe(path)
    if not ok_p:
        return {"error": f"Symlink-Pfad: {reason_p}"}
    ok_t, reason_t = is_path_safe(target)
    if not ok_t:
        return {"error": f"Ziel: {reason_t}"}

    abs_path = os.path.abspath(path)
    abs_target = os.path.abspath(target)

    try:
        if os.path.exists(abs_path) or os.path.islink(abs_path):
            return {"error": f"Symlink existiert bereits: {path}"}
        if IS_WINDOWS:
            os.symlink(abs_target, abs_path, target_is_directory=is_directory)
        else:
            os.symlink(abs_target, abs_path)
        return {"success": True, "symlink": path, "target": target, "absolute_target": abs_target}
    except PermissionError:
        return {"error": "Symlinks erfordern Administratorrechte auf Windows"}
    except Exception as e:
        return {"error": f"Symlink-Fehler: {e!s}"}


@mcp.tool()
def resolve_symlink(path: str) -> dict:
    """Loest einen Symlink auf und gibt das Ziel zurueck.

    Args:
        path: Pfad zum Symlink.
    """
    ok, reason = is_path_safe(path)
    if not ok:
        return {"error": f"Zugriff verweigert: {reason}"}

    abs_path = os.path.abspath(path)

    try:
        if not os.path.islink(abs_path):
            return {"error": f"Kein Symlink: {path}"}

        target = os.readlink(abs_path)
        real_path = os.path.realpath(abs_path)

        return {
            "success": True,
            "symlink": path,
            "target": target,
            "real_path": real_path,
            "target_exists": os.path.exists(real_path),
        }
    except Exception as e:
        return {"error": f"Fehler: {e!s}"}


@mcp.tool()
def create_hardlink(path: str, target: str) -> dict:
    """Erstellt einen Hardlink.

    Args:
        path: Pfad fuer den neuen Hardlink.
        target: Zieldatei, auf die der Hardlink zeigt.
    """
    ok_p, reason_p = is_path_safe(path)
    if not ok_p:
        return {"error": f"Hardlink-Pfad: {reason_p}"}
    ok_t, reason_t = is_path_safe(target, must_exist=True)
    if not ok_t:
        return {"error": f"Ziel: {reason_t}"}

    abs_path = os.path.abspath(path)
    abs_target = os.path.abspath(target)

    try:
        if os.path.exists(abs_path) or os.path.islink(abs_path):
            return {"error": f"Hardlink existiert bereits: {path}"}
        os.link(abs_target, abs_path)
        return {
            "success": True,
            "hardlink": path,
            "target": target,
            "inode": os.stat(abs_path).st_ino,
        }
    except PermissionError:
        return {"error": "Hardlinks erfordern spezielle Berechtigungen"}
    except Exception as e:
        return {"error": f"Hardlink-Fehler: {e!s}"}


# ============================================================
# Hauptprogramm
# ============================================================


def main() -> None:
    args = build_argparser(SERVER_NAME, default_port=8765).parse_args()

    logger.info("Filesystem Server starting...")
    logger.info("Root directory: %s", DEFAULT_ROOT)
    logger.info("OS: %s %s", platform.system(), platform.release())
    logger.info("Python: %s", platform.python_version())

    run_mcp_server(
        mcp=mcp,
        server_name=SERVER_NAME,
        host=args.host,
        port=args.port,
        transport=args.transport,
        streamable_http_app_factory=mcp.streamable_http_app,
        sse_app_factory=mcp.sse_app,
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Server gestoppt (KeyboardInterrupt).")
    except Exception as e:
        logger.error(f"FATAL: {type(e).__name__}: {e}")
        raise
