"""
Funktionale Tests fuer bisher weniger abgedeckte Dateisystem-Tools.
Schliesst die Luecken in der Tool-Abdeckung (Verifikation, dass alle Tools funktionieren):
get_tree, move_directory, write_file_binary (roundtrip), create_hardlink,
create_symlink, resolve_symlink, get_allowed_roots, get_file_permissions,
list_drives, get_user_directories, get_temp_directory.
"""

from __future__ import annotations

import base64
import io
import os
import sys
import tarfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import lokales_dateisystem as fs


class TestGetTree:
    def test_tree_contains_entries(self, tmp_path):
        (tmp_path / "a.txt").write_text("x")
        sub = tmp_path / "d"
        sub.mkdir()
        (sub / "b.txt").write_text("y")
        result = fs.get_tree(str(tmp_path), max_depth=3)
        assert result["success"] is True
        assert "a.txt" in result["tree"]
        assert "b.txt" in result["tree"]
        assert result["entry_count"] >= 2

    def test_tree_depth_limit(self, tmp_path):
        deep = tmp_path
        for i in range(5):
            deep = deep / f"lvl{i}"
            deep.mkdir()
        (deep / "deep.txt").write_text("z")
        result = fs.get_tree(str(tmp_path), max_depth=2)
        assert result["success"] is True
        # Tiefe begrenzt -> der tiefste Eintrag darf nicht auftauchen
        assert "deep.txt" not in result["tree"]

    def test_tree_hidden_excluded_by_default(self, tmp_path):
        (tmp_path / ".secret").write_text("x")
        (tmp_path / "visible.txt").write_text("y")
        result = fs.get_tree(str(tmp_path))
        assert ".secret" not in result["tree"]
        assert "visible.txt" in result["tree"]


class TestMoveDirectory:
    def test_move_dir(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "file.txt").write_text("content")
        dst = str(tmp_path / "dst")
        result = fs.move_directory(str(src), dst)
        assert result["success"] is True
        assert not src.exists()
        assert os.path.isfile(os.path.join(dst, "file.txt"))

    def test_move_nonexistent_returns_error(self, tmp_path):
        result = fs.move_directory(str(tmp_path / "nope"), str(tmp_path / "dst"))
        assert "error" in result

    def test_move_file_as_dir_returns_error(self, tmp_path):
        f = tmp_path / "notadir"
        f.write_text("x")
        result = fs.move_directory(str(f), str(tmp_path / "dst"))
        assert "error" in result


class TestWriteFileBinaryRoundtrip:
    def test_roundtrip_with_real_binary(self, tmp_path):
        # PNG-Header-artige Bytes
        data = b"\x89PNG\r\n\x1a\n" + bytes(range(256))
        encoded = base64.b64encode(data).decode()
        path = str(tmp_path / "img.bin")
        w = fs.write_file_binary(path, encoded)
        assert w["success"] is True
        assert w["bytes_written"] == len(data)
        r = fs.read_file_binary(path)
        assert r["success"] is True
        assert base64.b64decode(r["content"]) == data


class TestHardlink:
    def test_create_hardlink(self, tmp_path):
        target = tmp_path / "target.txt"
        target.write_text("hardlinked")
        link = str(tmp_path / "link.txt")
        try:
            result = fs.create_hardlink(link, str(target))
        except (PermissionError, OSError) as e:
            pytest.skip(f"Hardlinks nicht unterstuetzt: {e}")
        assert result["success"] is True
        assert os.path.exists(link)
        with open(link, encoding="utf-8") as fh:
            assert fh.read() == "hardlinked"

    def test_existing_target_rejected(self, tmp_path):
        target = tmp_path / "t.txt"
        target.write_text("x")
        link = tmp_path / "l.txt"
        link.write_text("existing")
        result = fs.create_hardlink(str(link), str(target))
        assert "error" in result


class TestSymlinks:
    def test_create_and_resolve_symlink(self, tmp_path):
        target = tmp_path / "real.txt"
        target.write_text("symlink target")
        link = str(tmp_path / "link.txt")
        try:
            r = fs.create_symlink(link, str(target))
        except (PermissionError, OSError) as e:
            pytest.skip(f"Symlinks erfordern Admin/DevMode: {e}")
        assert r["success"] is True
        resolved = fs.resolve_symlink(link)
        assert resolved["success"] is True
        assert resolved["target_exists"] is True

    def test_resolve_non_symlink_returns_error(self, tmp_path):
        f = tmp_path / "plain.txt"
        f.write_text("x")
        result = fs.resolve_symlink(str(f))
        assert "error" in result


class TestInfoTools:
    def test_get_allowed_roots(self):
        result = fs.get_allowed_roots()
        assert result["success"] is True
        assert "blocked_paths" in result
        assert isinstance(result["blocked_paths"], list)
        assert len(result["blocked_paths"]) > 0

    def test_get_file_permissions(self, tmp_path):
        f = tmp_path / "perm.txt"
        f.write_text("x")
        result = fs.get_file_permissions(str(f))
        assert result["success"] is True
        assert "octal" in result
        assert "human" in result

    def test_list_drives(self):
        result = fs.list_drives()
        assert result["success"] is True
        assert "drives" in result
        # Auf jedem echten System gibt es mind. ein Laufwerk
        assert result["count"] >= 1

    def test_get_user_directories(self):
        result = fs.get_user_directories()
        assert result["success"] is True
        assert "home" in result

    def test_get_temp_directory(self):
        result = fs.get_temp_directory()
        assert result["success"] is True
        assert "temp_directory" in result
        assert "disk_free" in result


# ---------------------------------------------------------------------------
# Neue Tools (v0.8): search_content, find_replace, tar.gz
# ---------------------------------------------------------------------------


class TestSearchContent:
    def test_finds_match_with_line_and_context(self, tmp_path):
        (tmp_path / "notes.txt").write_text("alpha\nBETA-gamma\ndelta\n", encoding="utf-8")
        r = fs.search_content(str(tmp_path), "beta", context_lines=1)
        assert r["success"] is True
        assert r["count"] == 1
        m = r["matches"][0]
        assert m["line"] == 2
        assert "BETA" in m["text"]
        assert "alpha" in m["context"] and "delta" in m["context"]

    def test_regex_search(self, tmp_path):
        (tmp_path / "d.txt").write_text("2026-07-01 and 2026-12-31\n", encoding="utf-8")
        r = fs.search_content(str(tmp_path), r"\d{4}-\d{2}-\d{2}")
        # regex.search pro Zeile -> 1 Treffer-Zeile (beide Daten stehen in einer Zeile)
        assert r["count"] == 1
        assert "2026-07-01" in r["matches"][0]["text"]

    def test_case_insensitive_default(self, tmp_path):
        (tmp_path / "c.txt").write_text("Hello World\n", encoding="utf-8")
        assert fs.search_content(str(tmp_path), "HELLO")["count"] == 1

    def test_file_pattern_filter(self, tmp_path):
        (tmp_path / "a.py").write_text("target\n", encoding="utf-8")
        (tmp_path / "b.md").write_text("target\n", encoding="utf-8")
        r = fs.search_content(str(tmp_path), "target", file_pattern="*.py")
        assert r["count"] == 1
        assert r["matches"][0]["file"].endswith("a.py")

    def test_binary_file_skipped(self, tmp_path):
        # .exe ist in binary_extensions -> wird nicht durchsucht
        (tmp_path / "prog.exe").write_bytes(b"secret\x00\x01binary")
        (tmp_path / "txt.txt").write_text("secret text\n", encoding="utf-8")
        r = fs.search_content(str(tmp_path), "secret")
        assert r["count"] == 1  # nur txt.txt

    def test_invalid_regex_returns_error(self, tmp_path):
        r = fs.search_content(str(tmp_path), "(unclosed")
        assert "error" in r

    def test_max_results_truncation(self, tmp_path):
        for i in range(10):
            (tmp_path / f"f{i}.txt").write_text("needle\n", encoding="utf-8")
        r = fs.search_content(str(tmp_path), "needle", max_results=3)
        assert r["count"] == 3
        assert r["truncated"] is True


class TestFindReplace:
    def test_literal_replace(self, tmp_path):
        f = tmp_path / "r.txt"
        f.write_text("foo bar foo baz\n", encoding="utf-8")
        r = fs.find_replace(str(f), "foo", "qux")
        assert r["success"] is True
        assert r["replacements"] == 2
        assert f.read_text() == "qux bar qux baz\n"

    def test_case_insensitive_replace(self, tmp_path):
        f = tmp_path / "r.txt"
        f.write_text("Hello HELLO hello\n", encoding="utf-8")
        r = fs.find_replace(str(f), "hello", "hi")
        assert r["replacements"] == 3

    def test_regex_replace_with_groups(self, tmp_path):
        f = tmp_path / "r.txt"
        f.write_text("2026-01-01\n", encoding="utf-8")
        r = fs.find_replace(str(f), r"(\d{4})-(\d{2})-(\d{2})", r"\3.\2.\1", use_regex=True)
        assert r["replacements"] == 1
        assert f.read_text() == "01.01.2026\n"

    def test_count_limits_replacements(self, tmp_path):
        f = tmp_path / "r.txt"
        f.write_text("x x x x\n", encoding="utf-8")
        r = fs.find_replace(str(f), "x", "y", count=2)
        assert r["replacements"] == 2
        assert f.read_text() == "y y x x\n"

    def test_backup_created(self, tmp_path):
        f = tmp_path / "r.txt"
        f.write_text("old\n", encoding="utf-8")
        fs.find_replace(str(f), "old", "new", backup=True)
        assert (tmp_path / "r.txt.bak").read_text() == "old\n"

    def test_no_match_returns_zero(self, tmp_path):
        f = tmp_path / "r.txt"
        f.write_text("nothing here\n", encoding="utf-8")
        r = fs.find_replace(str(f), "zzz", "y")
        assert r["success"] is True
        assert r["replacements"] == 0

    def test_invalid_regex_returns_error(self, tmp_path):
        f = tmp_path / "r.txt"
        f.write_text("x\n", encoding="utf-8")
        r = fs.find_replace(str(f), "[", "y", use_regex=True)
        assert "error" in r

    def test_directory_returns_error(self, tmp_path):
        r = fs.find_replace(str(tmp_path), "x", "y")
        assert "error" in r


class TestArchiveTarSupport:
    def test_tar_gz_roundtrip(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "a.txt").write_text("alpha", encoding="utf-8")
        (src / "b.txt").write_text("beta", encoding="utf-8")
        archive = str(tmp_path / "test.tar.gz")
        rc = fs.compress_archive(str(src), archive)
        assert rc["success"] is True
        assert rc["format"].startswith("tar")
        assert rc["file_count"] == 2
        # gzip-Magic Bytes
        with open(archive, "rb") as fh:
            assert fh.read(2) == b"\x1f\x8b"
        dst = tmp_path / "out"
        rd = fs.decompress_archive(archive, str(dst))
        assert rd.get("success") is True
        assert rd["extracted_count"] == 2
        # Dateien liegen unter src/ (arc_root = dirname(src))
        assert (dst / "src" / "a.txt").read_text() == "alpha"

    def test_tar_bz2_roundtrip(self, tmp_path):
        src = tmp_path / "s"
        src.mkdir()
        (src / "x.txt").write_text("content", encoding="utf-8")
        archive = str(tmp_path / "t.tar.bz2")
        assert fs.compress_archive(str(src), archive)["format"].startswith("tar")
        rd = fs.decompress_archive(archive, str(tmp_path / "o"))
        assert rd.get("success") is True

    def test_tar_slip_rejected(self, tmp_path):
        archive = tmp_path / "slip.tar"
        with tarfile.open(archive, "w") as t:
            info = tarfile.TarInfo(name="../../../../escaped.txt")
            info.size = 3
            t.addfile(info, io.BytesIO(b"pwn"))
        rd = fs.decompress_archive(str(archive), str(tmp_path / "out"))
        assert rd.get("rejected_count", 0) >= 1 or "error" in rd

    def test_tar_symlink_rejected(self, tmp_path):
        archive = tmp_path / "sym.tar"
        with tarfile.open(archive, "w") as t:
            info = tarfile.TarInfo(name="link.txt")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/shadow"
            t.addfile(info)
        rd = fs.decompress_archive(str(archive), str(tmp_path / "out"))
        assert rd.get("rejected_count", 0) >= 1

    def test_tar_bomb_too_many_files_rejected(self, tmp_path):
        archive = tmp_path / "bomb.tar"
        with tarfile.open(archive, "w") as t:
            for i in range(fs.MAX_ZIP_FILES + 1):
                data = b"x"
                info = tarfile.TarInfo(name=f"f{i:05d}.txt")
                info.size = len(data)
                t.addfile(info, io.BytesIO(data))
        rd = fs.decompress_archive(str(archive), str(tmp_path / "out"))
        assert "error" in rd

    def test_zip_still_works(self, tmp_path):
        """Regression: ZIP darf durch die tar-Erweiterung nicht kaputtgehen."""
        src = tmp_path / "z"
        src.mkdir()
        (src / "a.txt").write_text("hi", encoding="utf-8")
        archive = str(tmp_path / "r.zip")
        assert fs.compress_archive(str(src), archive)["format"] == "zip"
        rd = fs.decompress_archive(archive, str(tmp_path / "zo"))
        assert rd.get("success") is True
