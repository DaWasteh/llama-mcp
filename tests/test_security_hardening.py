"""
Tests fuer die Security-Haertung (Juli 2026) und Server-Split.

Deckt:
- IP-Encoding-Erkennung (_decode_ip_hostname): dezimal/hex/oktal SSRF-Bypass
- Erweiterte Blockliste (.onion/.i2p, weitere Paste-Hoster, RFC2606)
- URL-Userinfo-Block (Daten-Exfiltration)
- Content-Disposition-Attachment-Block (SafeHttpClient._check_response)
- SafeHttpClient.fetch_json
- Server-Split: beide Server eigenstaendig, kein Cross-Import
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import internet_recherche as ir

# ---------------------------------------------------------------------------
# _decode_ip_hostname - dezimale/hex/oktale IPv4-Codierungen (SSRF-Bypass)
# ---------------------------------------------------------------------------


class TestDecodeIpHostname:
    @pytest.mark.parametrize(
        "host,expected",
        [
            ("2130706433", "127.0.0.1"),      # dezimal -> loopback
            ("0x7f000001", "127.0.0.1"),      # hex     -> loopback
            ("0177.0.0.1", "127.0.0.1"),      # oktal-dotted -> loopback
            ("3232235521", "192.168.0.1"),    # dezimal -> private
            ("2852039166", "169.254.169.254"),# dezimal -> AWS metadata (link-local)
        ],
    )
    def test_encoded_ip_decoded(self, host, expected):
        assert ir._decode_ip_hostname(host) == expected

    @pytest.mark.parametrize(
        "host",
        [
            "8.8.8.8",            # dotted-dezimal (kein Encoding) -> None
            "example.com",
            "0177.0.0",           # kein 4-Oktett
            "0xZZZZ",             # kein gueltiges Hex
            "4294967296",         # > 32-bit Bereich
        ],
    )
    def test_non_encoded_or_invalid_returns_none(self, host):
        assert ir._decode_ip_hostname(host) is None

    def test_dotted_decimal_not_treated_as_encoded(self):
        # 8.8.8.8 ist eine gueltige dotted IP, aber KEIN Encoding -> None
        assert ir._decode_ip_hostname("8.8.8.8") is None


class TestIsSafeUrlEncodedIp:
    """Alle codierten IPs, die auf private Netze zeigen, muessen blockiert werden."""

    @pytest.mark.parametrize(
        "url",
        [
            "http://2130706433/",            # dezimal 127.0.0.1
            "http://0x7f000001/",            # hex 127.0.0.1
            "http://0177.0.0.1/",            # oktal 127.0.0.1
            "http://3232235521/",            # dezimal 192.168.0.1
            "http://2852039166/",            # dezimal 169.254.169.254 (metadata)
        ],
    )
    def test_encoded_private_ip_rejected(self, url):
        assert ir.is_safe_url(url) is False

    def test_encoded_public_ip_still_allowed(self):
        # 134744072 = 8.8.8.8 (oeffentlich) - darf durchkommen
        assert ir.is_safe_url("http://134744072/") is True


# ---------------------------------------------------------------------------
# Erweiterte Blockliste
# ---------------------------------------------------------------------------


class TestExtendedBlocklist:
    @pytest.mark.parametrize(
        "domain",
        [
            "rentry.co", "rentry.org", "paste.rs", "ix.io",
            "gist.githubusercontent.com", "codepen.io",
        ],
    )
    def test_new_paste_domains_blocked(self, domain):
        assert ir.is_safe_url(f"https://{domain}/x") is False

    @pytest.mark.parametrize(
        "suffix",
        [".onion", ".i2p", ".localhost", ".test", ".example", ".invalid"],
    )
    def test_new_suffixes_blocked(self, suffix):
        assert ir.is_safe_url(f"https://service{suffix}/api") is False

    def test_existing_blocked_domains_still_blocked(self):
        assert ir.is_safe_url("https://pastebin.com/abc") is False
        assert ir.is_safe_url("https://huggingface.co/model") is False


# ---------------------------------------------------------------------------
# URL-Userinfo-Block (Daten-Exfiltration / Basic-Auth-Verschleierung)
# ---------------------------------------------------------------------------


class TestUserinfoBlocked:
    def test_userinfo_rejected(self):
        assert ir.is_safe_url("http://user:pass@example.com/") is False

    def test_user_only_rejected(self):
        assert ir.is_safe_url("http://leaked-data@evil.com/x") is False

    def test_no_userinfo_still_ok(self):
        assert ir.is_safe_url("https://example.com/path") is True


# ---------------------------------------------------------------------------
# SafeHttpClient._check_response - Content-Disposition Attachment
# ---------------------------------------------------------------------------


def _make_response(content_type="text/html", content=b"hello",
                   content_disposition=None, host="example.com"):
    """Baut einen Mock-Response fuer _check_response."""
    resp = MagicMock()
    resp.url.host = host
    resp.content = content
    headers = {"content-type": content_type}
    if content_disposition is not None:
        headers["content-disposition"] = content_disposition
    resp.headers = headers
    return resp


class TestCheckResponse:
    def _client(self):
        return ir.SafeHttpClient()

    def test_clean_response_passes(self):
        c = self._client()
        assert c._check_response(_make_response(), "https://example.com/", 500_000) is True

    def test_oversize_rejected(self):
        c = self._client()
        resp = _make_response(content=b"x" * 10)
        assert c._check_response(resp, "https://example.com/", 5) is False

    def test_binary_content_type_rejected(self):
        c = self._client()
        resp = _make_response(content_type="application/octet-stream")
        assert c._check_response(resp, "https://example.com/", 500_000) is False

    def test_attachment_with_dangerous_ext_rejected(self):
        c = self._client()
        resp = _make_response(content_disposition='attachment; filename="malware.exe"')
        assert c._check_response(resp, "https://example.com/", 500_000) is False

    def test_attachment_with_safe_filename_allowed(self):
        c = self._client()
        # attachment mit .txt ist in Ordnung (nur gefaehrliche Endungen blocken)
        resp = _make_response(content_disposition='attachment; filename="report.txt"')
        assert c._check_response(resp, "https://example.com/", 500_000) is True

    def test_response_from_private_ip_rejected(self):
        c = self._client()
        resp = _make_response(host="10.0.0.1")
        assert c._check_response(resp, "https://example.com/", 500_000) is False


class TestFetchJson:
    def test_returns_none_for_unsafe_url(self):
        c = ir.SafeHttpClient()
        assert c.fetch_json("http://localhost/x") is None

    def test_returns_none_for_blocked_domain(self):
        c = ir.SafeHttpClient()
        assert c.fetch_json("https://pastebin.com/raw/x") is None


# ---------------------------------------------------------------------------
# Server-Split: keine gegenseitige Abhaengigkeit
# ---------------------------------------------------------------------------


class TestServerSplit:
    def test_filesystem_does_not_import_research(self):
        """lokales_dateisystem darf internet_recherche NICHT importieren."""
        import importlib
        fs = importlib.import_module("lokales_dateisystem")
        # Kein Attribut aus internet_recherche auf dem Dateisystem-Server
        assert not hasattr(fs, "internet_research")
        assert not hasattr(fs, "register_research_tools")

    def test_research_server_has_own_main(self):
        assert callable(ir.main)
        assert ir.RESEARCH_DEFAULT_PORT == 8766

    def test_research_tools_registered_on_own_server(self):
        import asyncio
        async def names():
            tools = await ir.mcp_research.list_tools()
            return {t.name for t in tools}
        got = asyncio.run(names())
        expected = {
            "internet_research", "internet_research_detailed", "read_webpage",
            "search_wikipedia", "search_arxiv", "search_gesti", "safe_web_scrape",
        }
        assert expected.issubset(got)
