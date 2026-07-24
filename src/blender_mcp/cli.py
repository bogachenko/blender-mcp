"""Command-line entry point for BlenderMCP."""

from __future__ import annotations

import sys
from collections.abc import Sequence


def main(argv: Sequence[str] | None = None) -> None:
    """Run BlenderMCP using stdio or the standalone HTTP transport.

    The existing no-argument behaviour remains unchanged so upstream MCP client
    configurations that launch ``blender-mcp`` continue to use stdio.
    """
    args = list(sys.argv[1:] if argv is None else argv)

    if args and args[0] == "serve":
        from .http_server import main as http_main

        http_main(args[1:])
        return

    from .server import main as stdio_main

    stdio_main()


if __name__ == "__main__":
    main()
