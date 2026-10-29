import asyncio
import base64
from contextlib import asynccontextmanager
import hashlib
import json
import re
import stat
import sys
import time
from urllib.parse import parse_qs, urlencode, urlsplit

from aiohttp import web
from aiohttp.test_utils import TestServer
import httpx2
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import MCPError
import pytest

from conftest import StubGateway, connected, data
from litellm_admin_mcp.config import Config
from litellm_admin_mcp.gateway import Gateway
from litellm_admin_mcp.signin import BrowserSignIn, CredentialStore


GATEWAY = "https://gateway.example.com"


class SignInGateway(StubGateway):
    """A gateway whose admin API also runs the proxy's native-client sign-in."""

    def __init__(self):
        super().__init__()
        self.contract = {}
        self.clients = {}
        self.codes = {}
        self.refresh_tokens = {}
        self.rejected = set()
        self.issued = 0

    def handle(self, request):
        base = str(request.url.join("/")).rstrip("/")
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        if request.url.path == "/.well-known/litellm-cli-auth":
            self.requests.append(request)
            return httpx2.Response(200, json={
                "contract_version": 1, "issuer": base, "authorization_endpoint": base + "/authorize",
                "token_endpoint": base + "/token", "registration_endpoint": base + "/register",
                "revocation_endpoint": base + "/revoke", "resource": base,
                "code_challenge_methods_supported": ["S256"], **self.contract})
        if request.url.path == "/register":
            self.requests.append(request)
            body = json.loads(request.content)
            assert body["token_endpoint_auth_method"] == "none"
            assert all(urlsplit(uri).hostname == "127.0.0.1" for uri in body["redirect_uris"])
            client_id = f"client-{len(self.clients) + 1}"
            self.clients[client_id] = body["redirect_uris"]
            return httpx2.Response(201, json={"client_id": client_id, **body})
        if request.url.path == "/authorize":
            self.requests.append(request)
            return httpx2.Response(302, headers={"Location": self.approve(str(request.url))})
        if request.url.path == "/token":
            self.requests.append(request)
            return self.token({k: v[0] for k, v in parse_qs(request.content.decode()).items()}, base)
        if request.url.path == "/user/info" and token in self.rejected:
            self.requests.append(request)
            return httpx2.Response(401, json={"error": {"message": "Authentication Error"}})
        return super().handle(request)

    def approve(self, url, error=None):
        params = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
        assert params["response_type"] == "code" and params["code_challenge_method"] == "S256"
        assert params["redirect_uri"] in self.clients[params["client_id"]]
        assert params["resource"] == str(httpx2.URL(url).join("/")).rstrip("/")
        if error:
            return params["redirect_uri"] + "?" + urlencode({"error": error, "state": params["state"]})
        code = f"code-{len(self.codes) + 1}"
        self.codes[code] = params
        return params["redirect_uri"] + "?" + urlencode({"code": code, "state": params["state"]})

    def token(self, form, base):
        assert form["resource"] == base
        if form["grant_type"] == "refresh_token":
            if self.refresh_tokens.pop(form["refresh_token"], None) != form["client_id"]:
                return httpx2.Response(400, json={"error": "invalid_grant"})
            return self.issue(form["client_id"])
        granted = self.codes.pop(form["code"], None)
        if granted is None:
            return httpx2.Response(400, json={"error": "invalid_grant"})
        challenge = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest()).rstrip(b"=").decode()
        assert (form["client_id"], form["redirect_uri"], challenge) == (
            granted["client_id"], granted["redirect_uri"], granted["code_challenge"])
        return self.issue(form["client_id"])

    def issue(self, client_id):
        self.issued += 1
        access, refresh = f"signed-in-admin-{self.issued}", f"refresh-{self.issued}"
        self.admins.add(access)
        self.refresh_tokens[refresh] = client_id
        return httpx2.Response(200, json={
            "access_token": access, "refresh_token": refresh, "token_type": "Bearer", "expires_in": 3600})


class Browser:
    """Stands in for the person at the keyboard: approves (or declines) whatever sign-in page opens."""

    def __init__(self, gateway, *, opens=True, error=None):
        self.gateway, self.opens, self.error = gateway, opens, error
        self.loop = asyncio.get_running_loop()
        self.urls = []
        self.pages = []

    def open(self, url):
        self.urls.append(url)
        if self.opens:
            asyncio.run_coroutine_threadsafe(self.visit(url), self.loop)
        return self.opens

    async def visit(self, url):
        async with httpx2.AsyncClient() as browser:
            page = await browser.get(self.gateway.approve(url, self.error))
        self.pages.append(page.text)
        return page


@asynccontextmanager
async def signed_in_session(gateway, store, browser, message_handler=None, handler=None, **options):
    config = Config(GATEWAY)
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler or gateway.handle)) as client:
        sign_in = BrowserSignIn(config.base_url, client, store, **{"open_browser": browser.open, "timeout": 5, **options})
        async with connected(Gateway(config, client), message_handler, sign_in=sign_in) as session:
            yield session


def text(result):
    assert result.is_error
    return result.content[0].text


def authorizations(gateway):
    return [r.headers["Authorization"] for r in gateway.writes]


async def test_first_tool_call_signs_in_through_the_browser_and_later_runs_reuse_it(tmp_path):
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "config" / "credentials.json")
    browser = Browser(gateway)
    async with signed_in_session(gateway, store, browser) as session:
        created = data(await session.call_tool("create_key", {"body": {"key_alias": "first"}}))
    assert created["key_alias"] == "first"
    assert len(browser.urls) == 1 and browser.pages == ["Signed in to LiteLLM. You can close this window and return to your agent."]
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(store.path.parent.stat().st_mode) == 0o700
    later = Browser(gateway, opens=False)
    async with signed_in_session(gateway, store, later) as session:
        data(await session.call_tool("create_key", {"body": {"key_alias": "later"}}))
    assert later.urls == []
    assert authorizations(gateway) == ["Bearer signed-in-admin-1"] * 2
    assert len(gateway.clients) == 1


async def test_expiring_sign_in_is_renewed_and_an_unrenewable_one_signs_in_again(tmp_path):
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "credentials.json")
    async with signed_in_session(gateway, store, Browser(gateway)) as session:
        data(await session.call_tool("create_key", {"body": {"key_alias": "first"}}))
    nearly_expired = Browser(gateway, opens=False)
    for alias in ("renewed", "kept"):
        async with signed_in_session(gateway, store, nearly_expired, now=lambda: time.time() + 3600 - 60) as session:
            data(await session.call_tool("create_key", {"body": {"key_alias": alias}}))
    assert nearly_expired.urls == []
    assert authorizations(gateway)[1:] == ["Bearer signed-in-admin-2"] * 2
    assert set(gateway.refresh_tokens) == {"refresh-2"}
    gateway.refresh_tokens.clear()
    expired = Browser(gateway)
    async with signed_in_session(gateway, store, expired, now=lambda: time.time() + 2 * 3600) as session:
        data(await session.call_tool("create_key", {"body": {"key_alias": "again"}}))
    assert len(expired.urls) == 1
    assert authorizations(gateway)[-1] == "Bearer signed-in-admin-3"


async def test_failed_renewal_keeps_using_the_sign_in_until_it_expires(tmp_path):
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "credentials.json")
    async with signed_in_session(gateway, store, Browser(gateway)) as session:
        data(await session.call_tool("create_key", {"body": {"key_alias": "first"}}))
    gateway.refresh_tokens.clear()
    browser = Browser(gateway, opens=False)
    async with signed_in_session(gateway, store, browser, now=lambda: time.time() + 3600 - 60) as session:
        data(await session.call_tool("create_key", {"body": {"key_alias": "still-valid"}}))
    assert browser.urls == []
    assert authorizations(gateway) == ["Bearer signed-in-admin-1"] * 2


async def test_abandoned_sign_in_times_out_and_the_next_request_starts_a_new_one(tmp_path):
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "credentials.json")
    abandoned = []
    browser = Browser(gateway)
    async with signed_in_session(gateway, store, browser, timeout=.2,
                                 open_browser=lambda url: abandoned.append(url) or True) as session:
        assert "not completed in the browser in time" in text(await session.call_tool("list_keys", {}))
        callback = parse_qs(urlsplit(abandoned[0]).query)["redirect_uri"][0]
        async with httpx2.AsyncClient() as late:
            with pytest.raises(httpx2.ConnectError):
                await late.get(callback, params={"code": "late"})
        assert "not completed in the browser in time" in text(await session.call_tool("list_keys", {}))
    assert len(abandoned) == 2 and len(gateway.clients) == 2
    assert not store.path.exists()


async def test_without_a_browser_the_error_carries_the_sign_in_link_and_tools_are_announced_once_done(tmp_path):
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "credentials.json")
    browser = Browser(gateway, opens=False)
    announced = asyncio.Event()

    async def notices(message):
        if isinstance(message, types.ToolListChangedNotification):
            announced.set()

    async with signed_in_session(gateway, store, browser, notices) as session:
        with pytest.raises(MCPError) as listing:
            await session.list_tools()
        link = re.search(r"https://gateway\.example\.com/authorize\?\S+", str(listing.value)).group()
        assert browser.urls == [link]
        assert link in text(await session.call_tool("list_keys", {}))
        await browser.visit(link)
        async with asyncio.timeout(5):
            await announced.wait()
        assert "create_key" in {tool.name for tool in (await session.list_tools()).tools}
        data(await session.call_tool("create_key", {"body": {"key_alias": "after"}}))
    assert browser.urls == [link]
    assert authorizations(gateway) == ["Bearer signed-in-admin-1"]


async def test_request_repeated_right_after_approving_waits_for_the_sign_in_to_finish(tmp_path):
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "credentials.json")
    browser, exchanging = Browser(gateway, opens=False), asyncio.Event()

    async def slow_token_endpoint(request):
        if request.url.path == "/token":
            await exchanging.wait()
        return gateway.handle(request)

    async with signed_in_session(gateway, store, browser, handler=slow_token_endpoint) as session:
        assert (await session.call_tool("list_keys", {})).is_error
        await browser.visit(browser.urls[0])
        repeated = asyncio.create_task(session.call_tool("create_key", {"body": {"key_alias": "repeated"}}))
        finished, _ = await asyncio.wait({repeated}, timeout=.3)
        assert not finished
        exchanging.set()
        data(await repeated)
    assert authorizations(gateway) == ["Bearer signed-in-admin-1"]


async def test_declined_sign_in_saves_nothing_and_the_next_request_asks_again(tmp_path):
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "credentials.json")
    browser = Browser(gateway, error="access_denied")
    async with signed_in_session(gateway, store, browser) as session:
        assert "not approved (access_denied)" in text(await session.call_tool("create_key", {"body": {"key_alias": "no"}}))
        assert not store.path.exists()
        browser.error = None
        data(await session.call_tool("create_key", {"body": {"key_alias": "yes"}}))
    assert len(browser.urls) == 2
    assert authorizations(gateway) == ["Bearer signed-in-admin-1"]


async def test_loopback_listener_accepts_only_the_pending_sign_ins_response(tmp_path):
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "credentials.json")
    browser = Browser(gateway, opens=False)
    async with signed_in_session(gateway, store, browser) as session:
        assert (await session.call_tool("list_keys", {})).is_error
        callback = parse_qs(urlsplit(browser.urls[0]).query)["redirect_uri"][0]
        async with httpx2.AsyncClient() as attacker:
            assert (await attacker.get(callback, params={"code": "stolen", "state": "forged"})).status_code == 400
            assert (await attacker.get(callback, params={"code": "stolen"})).status_code == 400
            assert (await attacker.post(callback, params={"code": "stolen"})).status_code == 404
        assert (await browser.visit(browser.urls[0])).status_code == 200
        data(await session.call_tool("create_key", {"body": {"key_alias": "mine"}}))
        async with httpx2.AsyncClient() as attacker:
            with pytest.raises(httpx2.ConnectError):
                await attacker.get(callback, params={"code": "late"})
    assert authorizations(gateway) == ["Bearer signed-in-admin-1"]


@pytest.mark.parametrize("contract", [
    {"authorization_endpoint": "https://attacker.example/authorize"},
    {"token_endpoint": "https://attacker.example/token"},
    {"registration_endpoint": "http://gateway.example.com/register"},
    {"resource": "https://gateway.example.com:8443"},
    {"issuer": "https://attacker.example"},
    {"contract_version": 2},
    {"code_challenge_methods_supported": ["plain"]},
])
async def test_unsupported_or_foreign_sign_in_discovery_is_refused_before_anything_is_sent(tmp_path, contract):
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "credentials.json")
    gateway.contract = contract
    browser = Browser(gateway)
    async with signed_in_session(gateway, store, browser) as session:
        assert "unsupported or names another server" in text(await session.call_tool("list_keys", {}))
    assert browser.urls == [] and gateway.clients == {}
    assert [r.url.path for r in gateway.requests] == ["/.well-known/litellm-cli-auth"]


async def test_gateway_without_browser_sign_in_says_to_upgrade_or_set_a_key(tmp_path):
    async def handle(request):
        return httpx2.Response(404, json={"detail": "Not Found"})
    store = CredentialStore(tmp_path / "credentials.json")
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handle)) as client:
        sign_in = BrowserSignIn(GATEWAY, client, store, open_browser=lambda url: pytest.fail("browser opened"))
        async with connected(Gateway(Config(GATEWAY), client), sign_in=sign_in) as session:
            assert "set LITELLM_API_KEY" in text(await session.call_tool("list_keys", {}))


async def test_saved_sign_in_the_gateway_rejects_is_dropped_and_replaced_by_a_new_one(tmp_path):
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "credentials.json")
    async with signed_in_session(gateway, store, Browser(gateway)) as session:
        data(await session.call_tool("create_key", {"body": {"key_alias": "first"}}))
    gateway.rejected.add("signed-in-admin-1")
    browser = Browser(gateway)
    async with signed_in_session(gateway, store, browser) as session:
        assert "next request opens a new browser sign-in" in text(await session.call_tool("list_keys", {}))
        assert browser.urls == []
        data(await session.call_tool("create_key", {"body": {"key_alias": "second"}}))
    assert len(browser.urls) == 1
    assert authorizations(gateway) == ["Bearer signed-in-admin-1", "Bearer signed-in-admin-2"]


async def test_sign_ins_for_different_gateways_are_kept_apart(tmp_path):
    store = CredentialStore(tmp_path / "credentials.json")
    first, second = SignInGateway(), SignInGateway()
    async with signed_in_session(first, store, Browser(first)) as session:
        data(await session.call_tool("list_keys", {}))
    other = "https://other-gateway.example.com"
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(second.handle)) as client:
        browser = Browser(second)
        sign_in = BrowserSignIn(other, client, store, open_browser=browser.open)
        async with connected(Gateway(Config(other), client), sign_in=sign_in) as session:
            data(await session.call_tool("create_key", {"body": {"key_alias": "other"}}))
    assert len(browser.urls) == 1
    later = Browser(first, opens=False)
    async with signed_in_session(first, store, later) as session:
        data(await session.call_tool("create_key", {"body": {"key_alias": "first-again"}}))
    assert later.urls == []
    assert authorizations(first) == ["Bearer signed-in-admin-1"]


async def test_packaged_stdio_process_without_a_key_signs_in_through_the_system_browser(tmp_path):
    gateway = SignInGateway()

    async def handler(request):
        incoming = httpx2.Request(request.method, str(request.url), headers=dict(request.headers), content=await request.read())
        result = gateway.handle(incoming)
        return web.Response(status=result.status_code, body=result.content, headers={
            k: v for k, v in result.headers.items() if k.lower() in {"content-type", "location"}})

    app = web.Application()
    app.router.add_route("*", "/{path:.*}", handler)
    browser = tmp_path / "browser"
    browser.write_text(f"#!{sys.executable}\nimport sys, urllib.request\n"
                       "print('browser output on stdout')\nprint('browser output on stderr', file=sys.stderr)\n"
                       "urllib.request.urlopen(sys.argv[1]).read()\n")
    browser.chmod(0o755)
    async with TestServer(app) as server:
        params = StdioServerParameters(command=sys.executable, args=["-m", "litellm_admin_mcp"], env={
            "LITELLM_BASE_URL": str(server.make_url("/")).rstrip("/"), "XDG_CONFIG_HOME": str(tmp_path / "config"),
            "BROWSER": str(browser), "LITELLM_ADMIN_TOOLS": "list_keys,create_key"})
        stream_errors = []

        async def notices(message):
            if isinstance(message, Exception):
                stream_errors.append(message)

        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write, message_handler=notices) as session:
                initialized = await session.initialize()
                assert initialized.capabilities.tools.list_changed
                created = data(await session.call_tool("create_key", {"body": {"key_alias": "stdio"}}))
                assert created["key_alias"] == "stdio"
                assert "create_key" in {tool.name for tool in (await session.list_tools()).tools}
    assert stream_errors == []
    assert authorizations(gateway) == ["Bearer signed-in-admin-1"]
    saved = tmp_path / "config" / "litellm-admin-mcp" / "credentials.json"
    assert stat.S_IMODE(saved.stat().st_mode) == 0o600
    assert "signed-in-admin-1" in saved.read_text()
