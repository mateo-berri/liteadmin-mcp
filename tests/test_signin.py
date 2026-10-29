import asyncio
import base64
from contextlib import asynccontextmanager
import hashlib
import json
import re
import os
import stat
import sys
import time
from urllib.parse import parse_qs, quote, urlencode, urlsplit

from aiohttp import web
from aiohttp.test_utils import TestServer
import httpx2
from mcp import Client, ClientSession, StdioServerParameters, types
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
        self.revocations = []
        self.revocation_status = 200
        self.non_admin_sign_ins = 0
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
        if request.url.path == "/revoke":
            self.requests.append(request)
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            self.revocations.append(form)
            if self.revocation_status == 200 and self.refresh_tokens.get(form["token"]) == form["client_id"]:
                del self.refresh_tokens[form["token"]]
            return httpx2.Response(self.revocation_status, json={})
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
        if self.non_admin_sign_ins:
            self.non_admin_sign_ins -= 1
        else:
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
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "config" / "sign-ins")
    browser = Browser(gateway)
    async with signed_in_session(gateway, store, browser) as session:
        created = data(await session.call_tool("create_key", {"body": {"key_alias": "first"}}))
    assert created["key_alias"] == "first"
    assert len(browser.urls) == 1 and browser.pages == ["Signed in to LiteLLM. You can close this window and return to your agent."]
    assert stat.S_IMODE(store.path(GATEWAY).stat().st_mode) == 0o600
    assert stat.S_IMODE(store.directory.stat().st_mode) == 0o700
    later = Browser(gateway, opens=False)
    async with signed_in_session(gateway, store, later) as session:
        data(await session.call_tool("create_key", {"body": {"key_alias": "later"}}))
    assert later.urls == []
    assert authorizations(gateway) == ["Bearer signed-in-admin-1"] * 2
    assert len(gateway.clients) == 1


async def test_expiring_sign_in_is_renewed_and_an_unrenewable_one_signs_in_again(tmp_path):
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "sign-ins")
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
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "sign-ins")
    async with signed_in_session(gateway, store, Browser(gateway)) as session:
        data(await session.call_tool("create_key", {"body": {"key_alias": "first"}}))
    gateway.refresh_tokens.clear()
    browser = Browser(gateway, opens=False)
    async with signed_in_session(gateway, store, browser, now=lambda: time.time() + 3600 - 60) as session:
        data(await session.call_tool("create_key", {"body": {"key_alias": "still-valid"}}))
    assert browser.urls == []
    assert authorizations(gateway) == ["Bearer signed-in-admin-1"] * 2


async def test_abandoned_sign_in_times_out_and_the_next_request_starts_a_new_one(tmp_path):
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "sign-ins")
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
    assert not store.path(GATEWAY).exists()


def sign_in_link(message):
    return re.search(r"https?://[^/\s]+/authorize\?[^\s,]+", message).group()


async def test_without_a_browser_only_sign_in_is_listed_and_shows_the_link_until_tools_are_announced(tmp_path):
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "sign-ins")
    browser = Browser(gateway, opens=False)
    announced = asyncio.Event()

    async def notices(message):
        if isinstance(message, types.ToolListChangedNotification):
            announced.set()

    async with signed_in_session(gateway, store, browser, notices) as session:
        assert [tool.name for tool in (await session.list_tools()).tools] == ["sign_in"]
        assert gateway.clients == {}
        signing_in = await session.call_tool("sign_in", {})
        assert not signing_in.is_error
        link = sign_in_link(signing_in.content[0].text)
        assert browser.urls == [link]
        assert link in text(await session.call_tool("list_keys", {}))
        await browser.visit(link)
        async with asyncio.timeout(5):
            await announced.wait()
        assert "create_key" in {tool.name for tool in (await session.list_tools()).tools}
        data(await session.call_tool("create_key", {"body": {"key_alias": "after"}}))
        signed_in = await session.call_tool("sign_in", {})
        assert not signed_in.is_error and "Signed in to LiteLLM as signed-in-admin-1" in signed_in.content[0].text
    assert browser.urls == [link]
    assert authorizations(gateway) == ["Bearer signed-in-admin-1"]


async def test_sign_in_tool_waits_for_approval_and_loads_the_admin_tools_before_answering_or_links_a_slow_one(tmp_path):
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "sign-ins")
    opened = []
    browser = Browser(gateway)
    async with signed_in_session(gateway, store, browser, link_after=.2,
                                 open_browser=lambda url: opened.append(url) or True) as session:
        assert [tool.name for tool in (await session.list_tools()).tools] == ["sign_in"]
        assert gateway.clients == {}
        slow = await session.call_tool("sign_in", {})
        assert not slow.is_error and sign_in_link(slow.content[0].text) == opened[0]
        waiting = asyncio.create_task(session.call_tool("sign_in", {}))
        await asyncio.sleep(.05)
        await browser.visit(opened[0])
        assert "Signed in to LiteLLM as signed-in-admin-1" in (await waiting).content[0].text
        assert "/openapi.json" in [request.url.path for request in gateway.requests]
    assert len(opened) == 1


async def test_admin_tool_call_returns_the_sign_in_link_instead_of_waiting_for_the_whole_sign_in(tmp_path):
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "sign-ins")
    opened = []
    async with signed_in_session(gateway, store, Browser(gateway), link_after=.2, timeout=30,
                                 open_browser=lambda url: opened.append(url) or True) as session:
        async with asyncio.timeout(5):
            waiting = text(await session.call_tool("list_keys", {}))
    assert sign_in_link(waiting) == opened[0] and waiting.endswith(", then repeat the request.")


async def test_sign_in_finds_a_sign_in_saved_by_another_session_and_lists_the_admin_tools(tmp_path):
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "sign-ins")
    browser = Browser(gateway, opens=False)
    announced = asyncio.Event()

    async def notices(message):
        if isinstance(message, types.ToolListChangedNotification):
            announced.set()

    async with signed_in_session(gateway, store, browser, notices) as session:
        assert [tool.name for tool in (await session.list_tools()).tools] == ["sign_in"]
        async with signed_in_session(gateway, store, Browser(gateway)) as other:
            assert not (await other.call_tool("sign_in", {})).is_error
        signed_in = await session.call_tool("sign_in", {})
        assert "Signed in to LiteLLM as signed-in-admin-1" in signed_in.content[0].text
        async with asyncio.timeout(5):
            await announced.wait()
        assert "create_key" in {tool.name for tool in (await session.list_tools()).tools}
    assert browser.urls == []


async def test_request_repeated_right_after_approving_waits_for_the_sign_in_to_finish(tmp_path):
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "sign-ins")
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
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "sign-ins")
    browser = Browser(gateway, error="access_denied")
    async with signed_in_session(gateway, store, browser) as session:
        assert "not approved (access_denied)" in text(await session.call_tool("create_key", {"body": {"key_alias": "no"}}))
        assert not store.path(GATEWAY).exists()
        browser.error = None
        data(await session.call_tool("create_key", {"body": {"key_alias": "yes"}}))
    assert len(browser.urls) == 2
    assert authorizations(gateway) == ["Bearer signed-in-admin-1"]


async def test_loopback_listener_accepts_only_the_pending_sign_ins_response(tmp_path):
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "sign-ins")
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


@pytest.mark.parametrize("contract, refusal", [
    ({"authorization_endpoint": "https://attacker.example/authorize"}, "names https://attacker.example:443 instead of"),
    ({"token_endpoint": "https://attacker.example/token"}, "names https://attacker.example:443 instead of"),
    ({"revocation_endpoint": "https://attacker.example/revoke"}, "names https://attacker.example:443 instead of"),
    ({"registration_endpoint": "http://gateway.example.com/register"}, "names http://gateway.example.com:80 instead of"),
    ({"resource": "https://gateway.example.com:8443"}, "names https://gateway.example.com:8443 instead of"),
    ({"issuer": "https://attacker.example"}, "names https://attacker.example:443 instead of"),
    ({"revocation_endpoint": None}, "discovery document is unsupported"),
    ({"contract_version": 2}, "discovery document is unsupported"),
    ({"code_challenge_methods_supported": ["plain"]}, "discovery document is unsupported"),
])
async def test_unsupported_or_foreign_sign_in_discovery_is_refused_before_anything_is_sent(tmp_path, contract, refusal):
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "sign-ins")
    gateway.contract = contract
    browser = Browser(gateway)
    async with signed_in_session(gateway, store, browser) as session:
        assert refusal in text(await session.call_tool("list_keys", {}))
    assert browser.urls == [] and gateway.clients == {}
    assert [r.url.path for r in gateway.requests] == ["/.well-known/litellm-cli-auth"]


@pytest.mark.parametrize("contract, advice", [
    ({"registration_endpoint": "http://gateway.example.com/register"},
     "Set PROXY_BASE_URL on the gateway to https://gateway.example.com."),
    ({"issuer": "https://gateway.internal.example"},
     "Set PROXY_BASE_URL on the gateway to https://gateway.example.com, or set LITELLM_BASE_URL to "
     "https://gateway.internal.example:443 if that is this gateway's own address."),
])
async def test_discovery_naming_another_address_says_which_setting_fixes_it(tmp_path, contract, advice):
    gateway = SignInGateway()
    gateway.contract = contract
    async with signed_in_session(gateway, CredentialStore(tmp_path / "sign-ins"), Browser(gateway)) as session:
        assert text(await session.call_tool("list_keys", {})).endswith(advice)


async def test_gateway_without_browser_sign_in_says_to_upgrade_or_set_a_key(tmp_path):
    async def handle(request):
        return httpx2.Response(404, json={"detail": "Not Found"})
    store = CredentialStore(tmp_path / "sign-ins")
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handle)) as client:
        sign_in = BrowserSignIn(GATEWAY, client, store, open_browser=lambda url: pytest.fail("browser opened"))
        async with connected(Gateway(Config(GATEWAY), client), sign_in=sign_in) as session:
            assert "set LITELLM_API_KEY" in text(await session.call_tool("list_keys", {}))


async def test_rejected_access_token_is_renewed_and_the_read_repeated_without_signing_anyone_out(tmp_path):
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "sign-ins")
    async with signed_in_session(gateway, store, Browser(gateway)) as session:
        data(await session.call_tool("list_keys", {}))
    gateway.rejected.add("signed-in-admin-1")
    browser = Browser(gateway, opens=False)
    async with signed_in_session(gateway, store, browser) as session:
        data(await session.call_tool("list_keys", {}))
        assert "create_key" in {tool.name for tool in (await session.list_tools()).tools}
    assert browser.urls == [] and gateway.revocations == []
    assert store.load(GATEWAY)["access_token"] == "signed-in-admin-2"


async def test_write_rejected_after_it_ran_is_not_repeated_and_the_next_one_uses_the_renewed_sign_in(tmp_path):
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "sign-ins")

    def rejected_after_writing(request):
        response = gateway.handle(request)
        if request.url.path == "/key/generate":
            gateway.rejected.add("signed-in-admin-1")
        return response

    async with signed_in_session(gateway, store, Browser(gateway), handler=rejected_after_writing) as session:
        refused = text(await session.call_tool("create_key", {"body": {"key_alias": "once"}}))
        assert "sign-in was renewed; check gateway state before repeating" in refused
        assert len(gateway.writes) == 1
        data(await session.call_tool("create_key", {"body": {"key_alias": "next"}}))
    assert authorizations(gateway) == ["Bearer signed-in-admin-1", "Bearer signed-in-admin-2"]
    assert gateway.revocations == []


async def test_gateway_outage_while_renewing_a_rejected_sign_in_keeps_it(tmp_path):
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "sign-ins")
    async with signed_in_session(gateway, store, Browser(gateway)) as session:
        data(await session.call_tool("list_keys", {}))
    gateway.rejected.add("signed-in-admin-1")

    def token_endpoint_down(request):
        if request.url.path == "/token":
            return httpx2.Response(503, json={})
        return gateway.handle(request)

    async with signed_in_session(gateway, store, Browser(gateway, opens=False), handler=token_endpoint_down) as session:
        assert "token request failed with HTTP 503" in text(await session.call_tool("list_keys", {}))
    assert store.load(GATEWAY)["access_token"] == "signed-in-admin-1" and gateway.revocations == []


async def test_rejected_sign_in_that_cannot_be_renewed_is_revoked_and_only_sign_in_is_listed(tmp_path):
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "sign-ins")
    async with signed_in_session(gateway, store, Browser(gateway)) as session:
        data(await session.call_tool("list_keys", {}))
    gateway.rejected.add("signed-in-admin-1")
    gateway.refresh_tokens.clear()
    announced = asyncio.Event()

    async def notices(message):
        if isinstance(message, types.ToolListChangedNotification):
            announced.set()

    browser = Browser(gateway)
    async with signed_in_session(gateway, store, browser, notices) as session:
        assert "sign-in was removed; call sign_in to sign in again" in text(await session.call_tool("list_keys", {}))
        async with asyncio.timeout(5):
            await announced.wait()
        assert [tool.name for tool in (await session.list_tools()).tools] == ["sign_in"]
        assert browser.urls == [] and [r["token"] for r in gateway.revocations] == ["refresh-1"]
        assert "Signed in to LiteLLM as signed-in-admin-2" in (await session.call_tool("sign_in", {})).content[0].text
    assert len(browser.urls) == 1


async def test_sign_in_as_a_non_admin_is_revoked_and_removed_so_an_admin_can_sign_in(tmp_path):
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "sign-ins")
    gateway.non_admin_sign_ins = 1
    browser = Browser(gateway)
    async with signed_in_session(gateway, store, browser) as session:
        refused = text(await session.call_tool("create_key", {"body": {"key_alias": "member"}}))
        assert refused.startswith("Only current LiteLLM proxy admins") and "sign-in was removed" in refused
        assert not store.path(GATEWAY).exists() and "refresh-1" not in gateway.refresh_tokens
        data(await session.call_tool("create_key", {"body": {"key_alias": "admin"}}))
    assert len(browser.urls) == 2
    assert authorizations(gateway) == ["Bearer signed-in-admin-2"]


async def test_every_spelling_of_the_gateway_origin_shares_one_sign_in(tmp_path):
    gateway, store = SignInGateway(), CredentialStore(tmp_path / "sign-ins")
    async with signed_in_session(gateway, store, Browser(gateway)) as session:
        data(await session.call_tool("list_keys", {}))
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(gateway.handle)) as client:
        sign_in = BrowserSignIn("https://Gateway.Example.com:443", client, store,
                                open_browser=lambda url: pytest.fail("browser opened"))
        assert await sign_in.saved() == "signed-in-admin-1"


async def test_sign_ins_for_different_gateways_are_kept_apart(tmp_path):
    store = CredentialStore(tmp_path / "sign-ins")
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


@asynccontextmanager
async def served(gateway):
    async def handler(request):
        incoming = httpx2.Request(request.method, str(request.url), headers=dict(request.headers), content=await request.read())
        result = gateway.handle(incoming)
        return web.Response(status=result.status_code, body=result.content, headers={
            k: v for k, v in result.headers.items() if k.lower() in {"content-type", "location"}})

    app = web.Application()
    app.router.add_route("*", "/{path:.*}", handler)
    async with TestServer(app) as server:
        yield str(server.make_url("/")).rstrip("/")


def launcher(tmp_path, body):
    browser = tmp_path / "browser"
    browser.write_text(f"#!{sys.executable}\nimport sys, urllib.request\n" + body)
    browser.chmod(0o755)
    return browser


def stdio(url, tmp_path, browser):
    return StdioServerParameters(command=sys.executable, args=["-m", "litellm_admin_mcp"], env={
        "LITELLM_BASE_URL": url, "XDG_CONFIG_HOME": str(tmp_path / "config"),
        "BROWSER": str(browser), "LITELLM_ADMIN_TOOLS": "list_keys,create_key"})


def saved(tmp_path, url):
    return tmp_path / "config" / "litellm-admin-mcp" / "sign-ins" / f"{quote(url, safe='')}.json"


async def test_packaged_stdio_process_without_a_key_signs_in_through_the_system_browser(tmp_path):
    gateway = SignInGateway()
    browser = launcher(tmp_path, "print('browser output on stdout')\nprint('browser output on stderr', file=sys.stderr)\n"
                                 "urllib.request.urlopen(sys.argv[1]).read()\n")
    async with served(gateway) as url:
        stream_errors = []

        async def notices(message):
            if isinstance(message, Exception):
                stream_errors.append(message)

        async with stdio_client(stdio(url, tmp_path, browser)) as (read, write):
            async with ClientSession(read, write, message_handler=notices) as session:
                initialized = await session.initialize()
                assert initialized.capabilities.tools.list_changed
                created = data(await session.call_tool("create_key", {"body": {"key_alias": "stdio"}}))
                assert created["key_alias"] == "stdio"
                assert "create_key" in {tool.name for tool in (await session.list_tools()).tools}
    assert stream_errors == []
    assert authorizations(gateway) == ["Bearer signed-in-admin-1"]
    assert stat.S_IMODE(saved(tmp_path, url).stat().st_mode) == 0o600
    assert "signed-in-admin-1" in saved(tmp_path, url).read_text()


async def test_current_protocol_client_gets_the_admin_tools_once_a_slow_browser_sign_in_finishes(tmp_path):
    gateway = SignInGateway()
    opened = tmp_path / "opened"
    browser = launcher(tmp_path, f"open({str(opened)!r}, 'w').write(sys.argv[1])\n")
    async with served(gateway) as url:
        async with Client(stdio(url, tmp_path, browser)) as client:
            assert client.protocol_version == "2026-07-28"
            async with client.listen(tools_list_changed=True) as changes:
                assert [tool.name for tool in (await client.list_tools()).tools] == ["sign_in"]
                signing_in = asyncio.create_task(client.call_tool("sign_in", {}))
                async with asyncio.timeout(10):
                    while not opened.exists():
                        await asyncio.sleep(.05)
                await asyncio.sleep(.5)
                async with httpx2.AsyncClient() as person:
                    assert (await person.get(gateway.approve(opened.read_text()))).status_code == 200
                async with asyncio.timeout(10):
                    await anext(aiter(changes))
                assert "Signed in to LiteLLM as signed-in-admin-1" in (await signing_in).content[0].text
            assert "create_key" in {tool.name for tool in (await client.list_tools()).tools}
            data(await client.call_tool("create_key", {"body": {"key_alias": "slow"}}))
    assert authorizations(gateway) == ["Bearer signed-in-admin-1"]


async def logout(url, tmp_path):
    process = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "litellm_admin_mcp", "logout", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        env={**os.environ, "LITELLM_BASE_URL": url, "XDG_CONFIG_HOME": str(tmp_path / "config")})
    out, err = await process.communicate()
    return process.returncode, (out + err).decode()


@pytest.mark.parametrize("revocation_status, exit_code, said, kept", [
    (200, 0, "The gateway revoked the sign-in's refresh token", False),
    (503, 1, "could not sign out: The gateway could not record the sign-out right now. Nothing was removed", True),
    (500, 0, "did not confirm revoking its refresh token (HTTP 500)", False),
])
async def test_logout_revokes_the_refresh_token_removes_the_sign_in_and_says_how_long_its_access_token_lasts(
        tmp_path, revocation_status, exit_code, said, kept):
    gateway = SignInGateway()
    async with served(gateway) as url:
        browser = Browser(gateway)
        async with httpx2.AsyncClient() as client:
            store = CredentialStore(tmp_path / "config" / "litellm-admin-mcp" / "sign-ins")
            assert await BrowserSignIn(url, client, store, open_browser=browser.open).credential() == "signed-in-admin-1"
        gateway.revocation_status = revocation_status
        returncode, output = await logout(url, tmp_path)
        assert (returncode, said in output) == (exit_code, True), output
        assert ("access token it last issued stays valid at the gateway until" in output) == (not kept), output
        assert saved(tmp_path, url).exists() == kept
        assert ("refresh-1" in gateway.refresh_tokens) == (revocation_status != 200)
        assert [r["client_id"] for r in gateway.revocations] == ["client-1"]
        if not kept:
            assert "No saved LiteLLM sign-in" in (await logout(url, tmp_path))[1]
