"""Standalone Streamable HTTP transport for BlenderMCP."""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import threading
from collections.abc import Sequence
from typing import Any

import uvicorn
from starlette.requests import Request
from starlette.responses import JSONResponse

from . import server as blender_server

logger = logging.getLogger("BlenderMCPHTTPServer")

DEFAULT_HTTP_HOST = "127.0.0.1"
DEFAULT_HTTP_PORT = 1985
MCP_PATH = "/mcp"
HEALTH_PATH = "/healthz"


def _is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True

    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _install_blender_command_serialization() -> None:
    """Serialize access to the add-on's single request/response TCP connection."""
    if getattr(blender_server, "_http_serialization_installed", False):
        return

    command_lock = threading.RLock()
    original_send_command = blender_server.BlenderConnection.send_command
    original_get_connection = blender_server.get_blender_connection

    def locked_send_command(
        self: blender_server.BlenderConnection,
        command_type: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        with command_lock:
            return original_send_command(self, command_type, params)

    def locked_get_connection() -> blender_server.BlenderConnection:
        with command_lock:
            return original_get_connection()

    blender_server.BlenderConnection.send_command = locked_send_command
    blender_server.get_blender_connection = locked_get_connection
    blender_server._http_serialization_installed = True


def create_app():
    """Create the ASGI application exposing MCP and health endpoints."""
    _install_blender_command_serialization()

    # FastMCP's Streamable HTTP application exposes the MCP endpoint at /mcp.
    app = blender_server.mcp.streamable_http_app()

    async def healthz(_: Request) -> JSONResponse:
        connection = blender_server._blender_connection
        blender_connected = bool(connection is not None and connection.sock is not None)
        return JSONResponse(
            {
                "status": "ok",
                "mcp_path": MCP_PATH,
                "blender_connected": blender_connected,
                "blender_host": os.getenv("BLENDER_HOST", blender_server.DEFAULT_HOST),
                "blender_port": int(os.getenv("BLENDER_PORT", str(blender_server.DEFAULT_PORT))),
            }
        )

    app.router.add_route(HEALTH_PATH, healthz, methods=["GET"])
    return app


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blender-mcp serve",
        description="Run BlenderMCP as a standalone local Streamable HTTP server.",
    )
    parser.add_argument(
        "--host",
        default=os.getenv("BLENDER_MCP_HTTP_HOST", DEFAULT_HTTP_HOST),
        help=f"HTTP bind host (default: {DEFAULT_HTTP_HOST})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("BLENDER_MCP_HTTP_PORT", str(DEFAULT_HTTP_PORT))),
        help=f"HTTP bind port (default: {DEFAULT_HTTP_PORT})",
    )
    parser.add_argument(
        "--log-level",
        choices=("critical", "error", "warning", "info", "debug", "trace"),
        default=os.getenv("BLENDER_MCP_HTTP_LOG_LEVEL", "info").lower(),
        help="Uvicorn log level (default: info)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    args = _build_parser().parse_args(argv)

    if not 1 <= args.port <= 65535:
        raise SystemExit("--port must be between 1 and 65535")

    if not _is_loopback_host(args.host):
        logger.warning(
            "BlenderMCP is binding to non-loopback host %s. "
            "The execute_blender_code tool can run arbitrary Python code; "
            "do not expose this server without authentication and network controls.",
            args.host,
        )

    app = create_app()
    logger.info("BlenderMCP HTTP endpoint: http://%s:%s%s", args.host, args.port, MCP_PATH)
    logger.info("BlenderMCP health endpoint: http://%s:%s%s", args.host, args.port, HEALTH_PATH)

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_level=args.log_level,
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()
