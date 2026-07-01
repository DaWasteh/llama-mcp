"""
Geteiltes Server-Bootstrap fuer beide eigenstaendigen MCP-Server
(lokales_dateisystem + internet_recherche).

Zweck: Den identischen HTTP/CORS/Transport-Setup-Code nur EINMAL zu pflegen
(lean / DRY), OHNE die Server logisch zu koppeln. Beide Module importieren
nur diesen Helfer, nicht einander.

Bietet:
  - parse_allowed_origins()   CORS-Origins aus Umgebungsvariable
  - run_mcp_server()          Startet FastMCP via uvicorn mit gehaertetem Setup

Sicherheit:
  - Default-Bind auf 127.0.0.1 (nur lokal erreichbar)
  - CORS restriktiv (kein "*" als Default)
  - Warnung bei Bind auf 0.0.0.0/::
"""

from __future__ import annotations

import argparse
import logging
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from starlette.requests import Request

logger = logging.getLogger("mcp_server_common")


# Llama.cpp WebUI/Server-Ports, die per Default CORS erhalten duerfen.
# Diese Liste bewusst klein halten; Produktion sollte MCP_ALLOWED_ORIGINS setzen.
DEFAULT_CORS_ORIGINS = (
    "http://127.0.0.1:8080,http://localhost:8080,"
    "http://127.0.0.1:8765,http://localhost:8765,"
    "http://127.0.0.1:8766,http://localhost:8766,"
    "http://127.0.0.1:1234,http://localhost:1234"
)

TRANSPORT_CHOICES = ("streamable-http", "sse", "stdio")


def parse_allowed_origins(env_value: str) -> list[str]:
    """Parst die MCP_ALLOWED_ORIGINS Umgebungsvariable.

    Komma-getrennte Liste. Leerstring oder "*" erlauben alle Origins (warnt).
    """
    if not env_value or env_value.strip() == "*":
        logger.warning(
            "MCP_ALLOWED_ORIGINS ist '*' oder leer - jede Website kann den Server aufrufen. "
            "Setze MCP_ALLOWED_ORIGINS auf eine kommagetrennte Liste fuer Produktion."
        )
        return ["*"]
    origins = [o.strip() for o in env_value.split(",") if o.strip()]
    return origins or ["*"]


def build_argparser(server_name: str, default_port: int) -> argparse.ArgumentParser:
    """Standard-Argumentparser fuer einen MCP-Server."""
    parser = argparse.ArgumentParser(description=f"MCP Server: {server_name}")
    parser.add_argument("--host", default="127.0.0.1", help="Host (Default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=default_port, help=f"Port (Default: {default_port})")
    parser.add_argument(
        "--transport",
        default="streamable-http",
        choices=TRANSPORT_CHOICES,
        help="MCP Transport (Default: streamable-http fuer llama.cpp WebUI)",
    )
    return parser


def run_mcp_server(
    mcp,
    server_name: str,
    host: str,
    port: int,
    transport: str,
    streamable_http_app_factory: Callable,
    sse_app_factory: Callable | None = None,
    cors_env_default: str = DEFAULT_CORS_ORIGINS,
) -> None:
    """Startet einen FastMCP-Server mit gehaertetem Setup.

    Args:
        mcp: FastMCP-Instanz (fuer stdio-Transport).
        server_name: Anzeigename fuer Logging/Root-Route.
        host/port/transport: Siehe build_argparser().
        streamable_http_app_factory: callable() -> Starlette-App (mcp.streamable_http_app).
        sse_app_factory: callable() -> Starlette-App (mcp.sse_app) oder None.
        cors_env_default: Default fuer MCP_ALLOWED_ORIGINS.
    """
    logger.info("%s starting...", server_name)
    logger.info("Host: %s  Port: %s  Transport: %s", host, port, transport)

    if host in ("0.0.0.0", "::"):
        logger.warning(
            "SICHERHEITSWARNUNG: Server bindet auf alle Interfaces (%s). "
            "Im Netzwerk ist er damit von aussen erreichbar. Empfehlung: --host 127.0.0.1",
            host,
        )

    if transport == "stdio":
        logger.info("Waiting for stdio connection...")
        mcp.run(transport="stdio")
        return

    import uvicorn
    from starlette.middleware.cors import CORSMiddleware
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    if transport == "streamable-http":
        app = streamable_http_app_factory()
        endpoint = "/mcp"
    else:
        if sse_app_factory is None:
            raise ValueError("sse-Transport benoetigt sse_app_factory")
        app = sse_app_factory()
        endpoint = "/sse"

    # CORS konfigurierbar (Default: nur Localhost-Origins)
    allowed_origins = parse_allowed_origins(os.environ.get("MCP_ALLOWED_ORIGINS", cors_env_default))
    logger.info("CORS allowed_origins: %s", allowed_origins)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["mcp-session-id", "mcp-protocol-version", "Content-Type", "Authorization"],
        expose_headers=["mcp-session-id", "mcp-protocol-version"],
    )

    async def root(_request: Request) -> JSONResponse:
        return JSONResponse({
            "server": server_name,
            "transport": transport,
            "endpoint": endpoint,
            "hint": f"MCP-URL fuer Clients: http://{host}:{port}{endpoint}",
        })

    app.routes.append(Route("/", root, methods=["GET"]))

    url = f"http://{host}:{port}{endpoint}"
    logger.info("URL: %s", url)
    logger.info("Trage genau diese URL (mit Pfad!) in der llama.cpp WebUI ein.")

    uvicorn.run(app, host=host, port=port, log_level="info")
