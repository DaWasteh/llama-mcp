"""
Funktionale Tests fuer bisher weniger abgedeckte Dateisystem-Tools.
Schliesst die Luecken in der Tool-Abdeckung (Verifikation, dass alle Tools funktionieren):
get_tree, move_directory, write_file_binary (roundtrip), create_hardlink,
create_symlink, resolve_symlink, get_allowed_roots, get_file_permissions,
list_drives, get_user_directories, get_temp_directory.
"""

from __future__ import annotations

import base64
import os
import sys

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
