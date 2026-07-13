"""Tests fuer die v0.9 Security-Fixes und neuen Tools.

Abgedeckt:
- _hostname_matches (Anti-Spoofing, kein Substring-Match)
- explain_url_block / check_url_safety (Blockgrund-Diagnose)
- safe_parse_xml (DOCTYPE/ENTITY-Guard, Billion-Laughs)
- SafeHttpClient._read_capped (Streaming-Byte-Cap)
- Content-Disposition: Endungs-Check auf Dateinamen (.shtml != .sh)
- Prozessweiter Rate-Limiter (geteilt ueber Engine-Instanzen)
- RateLimiter.remaining()
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

import internet_recherche as ir

# ---------------------------------------------------------------------------
# _hostname_matches - Anti-Spoofing
# ---------------------------------------------------------------------------


class TestHostnameMatches:
    def test_exact_domain(self):
        assert ir._hostname_matches("https://gesti.bgba.de/stoff/1", "gesti.bgba.de") is True

    def test_subdomain(self):
        assert ir._hostname_matches("https://de.wikipedia.org/wiki/X", "wikipedia.org") is True

    def test_spoofed_suffix_domain(self):
        # gesti.bgba.de.evil.com darf NICHT matchen
        assert ir._hostname_matches("https://gesti.bgba.de.evil.com/x", "gesti.bgba.de") is False

    def test_domain_in_path_only(self):
        # evil.com/wikipedia.org darf NICHT matchen
        assert ir._hostname_matches("https://evil.com/wikipedia.org", "wikipedia.org") is False

    def test_domain_in_query(self):
        assert ir._hostname_matches("https://evil.com/?u=arxiv.org", "arxiv.org") is False

    def test_trailing_dot_hostname(self):
        assert ir._hostname_matches("https://de.wikipedia.org./wiki/X", "wikipedia.org") is True

    def test_invalid_url(self):
        assert ir._hostname_matches("nicht-eine-url", "wikipedia.org") is False


# ---------------------------------------------------------------------------
# explain_url_block - Diagnose ohne Request
# ---------------------------------------------------------------------------


class TestExplainUrlBlock:
    def test_bad_scheme(self):
        reasons = ir.explain_url_block("ftp://example.com/file")
        assert any("Schema" in r for r in reasons)

    def test_userinfo(self):
        reasons = ir.explain_url_block("https://user:pass@example.com/")
        assert any("Userinfo" in r for r in reasons)

    def test_localhost(self):
        reasons = ir.explain_url_block("http://localhost/x")
        assert any("Localhost" in r for r in reasons)

    def test_private_ip(self):
        reasons = ir.explain_url_block("http://192.168.1.1/")
        assert any("Private" in r or "IP" in r for r in reasons)

    def test_encoded_ip(self):
        reasons = ir.explain_url_block("http://2130706433/")
        assert any("Codierte" in r for r in reasons)

    def test_blocked_domain(self):
        reasons = ir.explain_url_block("https://pastebin.com/raw/x")
        assert any("Blockliste" in r for r in reasons)

    def test_blocked_suffix(self):
        reasons = ir.explain_url_block("https://server.internal/x")
        assert any("Suffix" in r for r in reasons)

    def test_blocked_extension(self):
        reasons = ir.explain_url_block("https://example.com/setup.exe")
        assert any("Endung" in r for r in reasons)

    def test_no_hostname(self):
        reasons = ir.explain_url_block("https:///pfad")
        assert any("Hostname" in r for r in reasons)

    def test_consistent_with_is_safe_url(self):
        # Jede URL, die explain_url_block (ohne DNS) ablehnt, muss auch
        # is_safe_url ablehnen - und umgekehrt fuer statische Regeln.
        urls = [
            "ftp://example.com/x", "http://localhost/", "http://10.0.0.1/",
            "https://pastebin.com/x", "https://a.internal/", "https://e.com/x.exe",
            "https://user:pw@e.com/",
        ]
        for url in urls:
            assert ir.is_safe_url(url) is False
            assert ir.explain_url_block(url), f"Kein Blockgrund fuer {url}"


# ---------------------------------------------------------------------------
# safe_parse_xml - Entity-Guard
# ---------------------------------------------------------------------------


class TestSafeParseXml:
    def test_valid_xml(self):
        root = ir.safe_parse_xml("<feed><entry>x</entry></feed>")
        assert root is not None
        assert root.tag == "feed"

    def test_doctype_rejected(self):
        xml = '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">]><a>&lol;</a>'
        assert ir.safe_parse_xml(xml) is None

    def test_entity_rejected(self):
        xml = '<?xml version="1.0"?><!ENTITY x "y"><a/>'
        assert ir.safe_parse_xml(xml) is None

    def test_broken_xml_returns_none(self):
        assert ir.safe_parse_xml("<a><b></a>") is None

    def test_empty_returns_none(self):
        assert ir.safe_parse_xml("") is None


# ---------------------------------------------------------------------------
# SafeHttpClient._read_capped - Streaming-Byte-Cap
# ---------------------------------------------------------------------------


def _mock_streaming_response(chunks):
    resp = MagicMock()
    resp.iter_bytes = lambda chunk_size=65536: iter(chunks)
    return resp


class TestReadCapped:
    def test_small_body_ok(self):
        resp = _mock_streaming_response([b"hello", b"world"])
        assert ir.SafeHttpClient._read_capped(resp, 100) == b"helloworld"

    def test_oversize_aborts_with_none(self):
        resp = _mock_streaming_response([b"x" * 60, b"y" * 60])
        assert ir.SafeHttpClient._read_capped(resp, 100) is None

    def test_exact_limit_ok(self):
        resp = _mock_streaming_response([b"x" * 100])
        assert ir.SafeHttpClient._read_capped(resp, 100) == b"x" * 100

    def test_aborts_before_reading_rest(self):
        # Nach Ueberschreitung darf NICHT weitergelesen werden
        read_count = {"n": 0}

        def gen():
            for _ in range(1000):
                read_count["n"] += 1
                yield b"z" * 1024

        resp = MagicMock()
        resp.iter_bytes = lambda chunk_size=65536: gen()
        assert ir.SafeHttpClient._read_capped(resp, 2048) is None
        assert read_count["n"] <= 3


# ---------------------------------------------------------------------------
# Content-Disposition: Endungs-Check auf Dateinamen
# ---------------------------------------------------------------------------


def _make_response(content_type="text/html", content=b"hello",
                   content_disposition=None, host="example.com"):
    resp = MagicMock()
    resp.url.host = host
    resp.content = content
    headers = {"content-type": content_type}
    if content_disposition is not None:
        headers["content-disposition"] = content_disposition
    resp.headers = headers
    return resp


class TestDispositionFilenameCheck:
    def test_shtml_not_false_positive(self):
        # .shtml enthaelt ".sh" als Substring, ist aber harmlos
        c = ir.SafeHttpClient()
        resp = _make_response(content_disposition='attachment; filename="seite.shtml"')
        assert c._check_response(resp, "https://example.com/", 500_000) is True

    def test_exe_still_blocked(self):
        c = ir.SafeHttpClient()
        resp = _make_response(content_disposition='attachment; filename="malware.exe"')
        assert c._check_response(resp, "https://example.com/", 500_000) is False

    def test_ps1_blocked_without_quotes(self):
        c = ir.SafeHttpClient()
        resp = _make_response(content_disposition="attachment; filename=script.ps1")
        assert c._check_response(resp, "https://example.com/", 500_000) is False


# ---------------------------------------------------------------------------
# Prozessweiter Rate-Limiter
# ---------------------------------------------------------------------------


class TestGlobalRateLimiter:
    def test_engines_share_limiter(self):
        e1 = ir.InternetResearchEngine()
        e2 = ir.InternetResearchEngine()
        assert e1.rate_limiter is e2.rate_limiter
        assert e1.rate_limiter is ir._GLOBAL_RATE_LIMITER

    def test_remaining_counts_down(self):
        rl = ir.RateLimiter(max_requests=3, window_seconds=60)
        assert rl.remaining() == 3
        assert rl.allow() is True
        assert rl.remaining() == 2
        rl.allow()
        rl.allow()
        assert rl.remaining() == 0
        assert rl.allow() is False

    def test_remaining_does_not_consume(self):
        rl = ir.RateLimiter(max_requests=2, window_seconds=60)
        for _ in range(10):
            rl.remaining()
        assert rl.remaining() == 2


# ---------------------------------------------------------------------------
# Redirect-Verfolgung: jeder Hop wird validiert
# ---------------------------------------------------------------------------


class TestRedirectValidation:
    def _client_with_responses(self, responses):
        """SafeHttpClient, dessen Session vorgefertigte Responses streamt."""
        import contextlib as _ctx

        c = ir.SafeHttpClient()
        c._verify_host_fresh = lambda hostname: True  # DNS im Test ueberspringen
        it = iter(responses)

        @_ctx.contextmanager
        def fake_stream(method, url, params=None, headers=None):
            yield next(it)

        c.session = MagicMock()
        c.session.stream = fake_stream
        return c

    def _resp(self, status=200, headers=None, body=b"<p>ok</p>"):
        resp = MagicMock()
        resp.status_code = status
        resp.headers = {"content-type": "text/html", **(headers or {})}
        resp.url.host = "example.com"
        resp.iter_bytes = lambda chunk_size=65536: iter([body])
        resp.extensions = {}
        # _content-Zuweisung im Code setzt echtes Attribut auf dem Mock
        return resp

    def test_redirect_to_private_ip_blocked(self):
        redirect = self._resp(status=302, headers={"location": "http://127.0.0.1/admin"})
        c = self._client_with_responses([redirect])
        assert c._safe_get("https://example.com/") is None

    def test_redirect_to_blocked_domain_blocked(self):
        redirect = self._resp(status=301, headers={"location": "https://pastebin.com/raw/x"})
        c = self._client_with_responses([redirect])
        assert c._safe_get("https://example.com/") is None

    def test_safe_redirect_followed(self):
        redirect = self._resp(status=301, headers={"location": "https://example.com/neu"})
        final = self._resp(status=200)
        final.content = b"<p>ok</p>"
        c = self._client_with_responses([redirect, final])
        result = c._safe_get("https://example.com/")
        assert result is not None

    def test_redirect_loop_hits_limit(self):
        loops = [
            self._resp(status=302, headers={"location": "https://example.com/loop"})
            for _ in range(ir.MAX_REDIRECTS + 2)
        ]
        c = self._client_with_responses(loops)
        assert c._safe_get("https://example.com/") is None

    def test_error_status_rejected(self):
        c = self._client_with_responses([self._resp(status=404)])
        assert c._safe_get("https://example.com/") is None

    def test_content_length_precheck(self):
        big = self._resp(status=200, headers={"content-length": str(ir.MAX_RESPONSE_SIZE + 1)})
        c = self._client_with_responses([big])
        assert c._safe_get("https://example.com/") is None


# ---------------------------------------------------------------------------
# Neue Tools registriert
# ---------------------------------------------------------------------------


class TestNewToolsRegistered:
    def test_tools_on_research_server(self):
        import asyncio

        async def names():
            tools = await ir.mcp_research.list_tools()
            return {t.name for t in tools}

        tool_names = asyncio.run(names())
        assert "check_url_safety" in tool_names
        assert "get_server_status" in tool_names

    def test_status_tool_on_filesystem_server(self):
        import asyncio

        import lokales_dateisystem as fs

        async def names():
            tools = await fs.mcp.list_tools()
            return {t.name for t in tools}

        tool_names = asyncio.run(names())
        assert "get_server_status" in tool_names
