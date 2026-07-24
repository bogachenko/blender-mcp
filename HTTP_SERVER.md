# Standalone HTTP server

The fork keeps the original stdio mode and adds a standalone Streamable HTTP mode.

## Install

The HTTP mode requires a newer stable MCP Python SDK than the lockfile inherited from upstream. Regenerate the lockfile once, then install:

```bash
uv lock
uv sync
```

Commit the resulting `uv.lock` after the first successful local installation.

## Run

Start Blender, enable the BlenderMCP add-on, and click **Connect to Claude** so the add-on listens on its local TCP port.

Then run:

```bash
uv run blender-mcp serve
```

Endpoints:

- MCP: `http://127.0.0.1:1985/mcp`
- Health: `http://127.0.0.1:1985/healthz`

The original stdio mode is unchanged:

```bash
uv run blender-mcp
```

## Options

```bash
uv run blender-mcp serve --host 127.0.0.1 --port 1985 --log-level info
```

Environment variables:

- `BLENDER_MCP_HTTP_HOST` — HTTP bind host, default `127.0.0.1`
- `BLENDER_MCP_HTTP_PORT` — HTTP bind port, default `1985`
- `BLENDER_MCP_HTTP_LOG_LEVEL` — Uvicorn log level, default `info`
- `BLENDER_HOST` — Blender add-on host, default `localhost`
- `BLENDER_PORT` — Blender add-on port, default `9876`

## MCP client configuration

Configure the client as a Streamable HTTP server using:

```text
http://127.0.0.1:1985/mcp
```

Only one BlenderMCP HTTP process should control a Blender add-on instance.

## Security

Keep the default loopback bind address. BlenderMCP exposes `execute_blender_code`, which can execute arbitrary Python code in Blender and access the local user environment. Do not bind to `0.0.0.0` or expose the endpoint to a network without authentication and network-level access controls.
