import asyncio
from contextlib import asynccontextmanager
import json
import os
import subprocess
import sys

from aiohttp import web
from aiohttp.test_utils import TestServer
import httpx2
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
import uvicorn

from conftest import data
from litellm_admin_mcp.config import Config
from litellm_admin_mcp.gateway import Gateway, HELPERS
from litellm_admin_mcp.server import create_http_app


@asynccontextmanager
async def serve(app):
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning", access_log=False))
    task = asyncio.create_task(server.serve())
    try:
        async with asyncio.timeout(10):
            while not server.started:
                if task.done():
                    await task
                await asyncio.sleep(.01)
        port = server.servers[0].sockets[0].getsockname()[1]
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        await task


@pytest.mark.parametrize("schema_mode", ["full", "discovery"])
async def test_streamable_http_rejects_anonymous_and_keeps_callers_separate(stub, schema_mode):
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(stub.handle)) as upstream:
        app = create_http_app(Gateway(Config("https://gateway.example.com", schema_mode=schema_mode), upstream))
        async with serve(app) as base:
            async with httpx2.AsyncClient() as anonymous:
                assert (await anonymous.get(base + "/healthz")).status_code == 200
                assert (await anonymous.post(base + "/mcp", json={})).status_code == 401
                assert (await anonymous.post(base + "/mcp", json={}, headers={"Authorization": "Bearer viewer"})).status_code == 403
                assert (await anonymous.post(base + "/mcp", json={}, headers={"Authorization": "Bearer team-key"})).status_code == 403
            for credential in ("alice-admin", "bob-admin"):
                async with httpx2.AsyncClient(headers={"Authorization": "Bearer " + credential}) as client:
                    async with streamable_http_client(base + "/mcp", http_client=client) as (read, write):
                        async with ClientSession(read, write) as session:
                            await session.initialize()
                            assert "create_key" in {t.name for t in (await session.list_tools()).tools}
                            result = data(await session.call_tool("create_key", {"body": {"key_alias": credential}}))
                            assert result["key"] == "sk-created-for-[credential redacted]"
                            if credential == "alice-admin":
                                stub.keys = [{"metadata": "x" * 25000}]
                                saved = data(await session.call_tool("list_keys", {}))
                                assert data(await session.call_tool("read_admin_result", saved["full_read"])) == {"keys": stub.keys}
                            else:
                                assert (await session.call_tool("read_admin_result", saved["full_read"])).is_error
    assert [r.headers["Authorization"] for r in stub.writes] == ["Bearer alice-admin", "Bearer bob-admin"]


async def test_packaged_stdio_process_uses_only_explicit_gateway_credential(stub, monkeypatch):
    async def handler(request):
        body = await request.read()
        incoming = httpx2.Request(request.method, "https://gateway.example.com" + str(request.rel_url),
                                  headers=dict(request.headers), content=body)
        result = stub.handle(incoming)
        return web.Response(status=result.status_code, body=result.content, content_type="application/json")
    app = web.Application()
    app.router.add_route("*", "/{path:.*}", handler)
    monkeypatch.setenv("SLACK_BOT_TOKEN", "unrelated-slack-secret")
    async with TestServer(app) as gateway:
        params = StdioServerParameters(command=sys.executable, args=["-m", "litellm_admin_mcp"], env={
            "LITELLM_BASE_URL": str(gateway.make_url("/")).rstrip("/"), "LITELLM_API_KEY": "alice-admin",
            "LITELLM_ADMIN_TOOLS": "list_keys,create_key",
        })
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                assert {t.name for t in (await session.list_tools()).tools} == {"list_keys", "create_key"} | HELPERS.keys()
                created = data(await session.call_tool("create_key", {"body": {"key_alias": "stdio"}}))
                assert created["key_alias"] == "stdio"
                stub.keys = [{"metadata": "x" * 25000}]
                saved = data(await session.call_tool("list_keys", {}))
                assert data(await session.call_tool("read_admin_result", saved["full_read"])) == {"keys": stub.keys}
    assert len(stub.writes) == 1
    assert "unrelated-slack-secret" not in json.dumps([dict(r.headers) for r in stub.requests])


def test_stdio_start_with_a_malformed_key_says_why():
    started = subprocess.run([sys.executable, "-m", "litellm_admin_mcp"], capture_output=True, text=True, timeout=30, env={
        **os.environ, "LITELLM_BASE_URL": "https://gateway.example.com", "LITELLM_API_KEY": "pasted with spaces"})
    assert started.returncode == 1
    assert "A personal LiteLLM admin credential is required." in started.stderr
    assert "pasted with spaces" not in started.stderr
