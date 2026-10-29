"""Browser sign-in for local stdio runs that have no configured gateway credential.

The gateway publishes its native-client contract at /.well-known/litellm-cli-auth (the
same one `lite login --pkce` uses): register a public client with a loopback redirect,
send the user's browser to /authorize with PKCE S256, then redeem the code at /token for
a self-renewing gateway credential issued for the proxy API. Signing out, or a credential the
gateway still rejects after renewal, revokes its refresh token at the gateway's revocation endpoint."""
import asyncio
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
from typing import Awaitable, Callable
from urllib.parse import parse_qs, quote, urlencode, urlsplit

import httpx2

from .config import gateway_origin
from .gateway import AdminError


DISCOVERY_PATH = "/.well-known/litellm-cli-auth"
SIGN_IN_SECONDS = 300
LINK_AFTER_SECONDS = 40
ANSWER_WITHIN_SECONDS = 55
REFRESH_MARGIN_SECONDS = 360
CLIENT_NAME = "litellm-admin-mcp"
RECORD_FIELDS = ("access_token", "refresh_token", "client_id", "token_endpoint", "revocation_endpoint", "resource")
OPEN_BROWSER = "import sys, webbrowser; sys.exit(not webbrowser.open(sys.argv[1]))"
REJECTED_GRANTS = ("invalid_grant", "invalid_client", "unauthorized_client")
ELSEWHERE = (" If that browser runs on another computer, the page it opens after approval will not load. Copy that page's "
             "full address from the address bar and call sign_in with it as callback_url.")


def default_store_directory() -> Path:
    return Path(os.getenv("XDG_CONFIG_HOME") or Path.home() / ".config") / "litellm-admin-mcp" / "sign-ins"


def open_browser(url: str) -> bool:
    try:
        return subprocess.run([sys.executable, "-I", "-c", OPEN_BROWSER, url], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, start_new_session=True).returncode == 0
    except subprocess.TimeoutExpired:
        return True
    except OSError:
        return False


def connectable(url: str) -> bool:
    try:
        gateway_origin(url)
    except ValueError:
        return False
    return True


def origin(url: object) -> str | None:
    if not isinstance(url, str):
        return None
    parsed = urlsplit(url)
    try:
        port = parsed.port or {"https": 443, "http": 80}.get(parsed.scheme)
    except ValueError:
        return None
    if port is None or not parsed.hostname:
        return None
    return f"{parsed.scheme}://{parsed.hostname}:{port}"


class CredentialStore:
    """Owner-only JSON files, one per gateway origin, so runs against different gateways never
    overwrite each other's sign-in."""

    def __init__(self, directory: Path):
        self.directory = directory

    def path(self, gateway: str) -> Path:
        return self.directory / f"{quote(origin(gateway), safe='')}.json"

    def load(self, gateway: str) -> dict | None:
        try:
            record = json.loads(self.path(gateway).read_text())
        except (OSError, ValueError):
            return None
        if (not isinstance(record, dict) or any(not isinstance(record.get(f), str) or not record[f] for f in RECORD_FIELDS)
                or not isinstance(record.get("expires_at"), (int, float))):
            return None
        return record

    def save(self, gateway: str, record: dict | None):
        path = self.path(gateway)
        if record is None:
            path.unlink(missing_ok=True)
            return
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory.chmod(0o700)
        staged = path.with_name(f".{path.name}.{secrets.token_hex(8)}")
        with os.fdopen(os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as file:
            json.dump(record, file)
        os.replace(staged, path)


class Callback:
    """The loopback listener the browser returns to; only the pending sign-in's state settles it."""

    def __init__(self, state: str):
        self.state = state
        self.outcome: asyncio.Future[str] = asyncio.get_running_loop().create_future()

    async def open(self) -> "Callback":
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.redirect_uri = f"http://127.0.0.1:{self.server.sockets[0].getsockname()[1]}/callback"
        return self

    async def close(self):
        self.server.close()
        await self.server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            async with asyncio.timeout(5):
                head = await reader.readuntil(b"\r\n\r\n")
            status, text = self._settle(head.split(b"\r\n", 1)[0].decode("ascii"))
        except (TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, UnicodeDecodeError, ConnectionError):
            status, text = 400, "Bad request."
        body = text.encode()
        writer.write(f"HTTP/1.1 {status} {'OK' if status == 200 else 'Error'}\r\nContent-Type: text/plain; charset=utf-8\r\n"
                     f"Content-Length: {len(body)}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n".encode() + body)
        try:
            await writer.drain()
        except ConnectionError:
            pass
        writer.close()

    def _settle(self, request_line: str) -> tuple[int, str]:
        method, _, rest = request_line.partition(" ")
        target = urlsplit(rest.rpartition(" ")[0])
        if method != "GET" or target.path != "/callback":
            return 404, "Not found."
        return self.resolve(target.query)

    def resolve(self, query: str) -> tuple[int, str]:
        params = {k: v[0] for k, v in parse_qs(query).items()}
        if self.outcome.done() or not secrets.compare_digest(params.get("state", ""), self.state):
            return 400, "This response does not belong to the pending LiteLLM sign-in."
        if "error" in params:
            self.outcome.set_exception(AdminError(f"LiteLLM sign-in was not approved ({params['error']}).", 401))
            return 200, "LiteLLM sign-in was not approved. You can close this window."
        if not params.get("code"):
            return 400, "The sign-in response carried no authorization code."
        self.outcome.set_result(params["code"])
        return 200, "Signed in to LiteLLM. You can close this window and return to your agent."


@dataclass(frozen=True)
class Pending:
    url: str
    opened: asyncio.Task
    callback: Callback
    task: asyncio.Task

    @property
    def link(self) -> str:
        return f"Sign in to LiteLLM as a proxy admin by opening {self.url} in a browser"


class BrowserSignIn:
    """Supplies the stored gateway credential, renewing it before it expires, and starts one
    browser sign-in at a time when there is none. A sign-in outlives the request that started
    it, so a client that stops waiting still gets the credential on its next request."""

    def __init__(self, gateway: str, client: httpx2.AsyncClient, store: CredentialStore, *,
                 open_browser: Callable[[str], bool] = open_browser, timeout: float = SIGN_IN_SECONDS,
                 link_after: float = LINK_AFTER_SECONDS, answer_within: float = ANSWER_WITHIN_SECONDS,
                 now: Callable[[], float] = time.time):
        self.gateway, self.client, self.store = gateway, client, store
        self.open_browser, self.timeout, self.link_after, self.now = open_browser, timeout, link_after, now
        self.answer_within = answer_within
        self._lock = asyncio.Lock()
        self._pending: Pending | None = None

    async def begin(self, signed_in: Callable[[], Awaitable[None]] | None = None) -> str | Pending:
        async with self._lock:
            stored = await self._stored()
            if stored is not None:
                return stored
            if self._pending is None or self._pending.task.done():
                self._pending = await self._start(signed_in)
            return self._pending

    async def saved(self) -> str | None:
        async with self._lock:
            return await self._stored()

    def signed_out(self) -> bool:
        return self.store.load(self.gateway) is None

    async def credential(self, signed_in: Callable[[], Awaitable[None]] | None = None) -> str:
        found = await self.begin(signed_in)
        key = found if isinstance(found, str) else await self.settled(found)
        if key is None:
            raise AdminError(f"{found.link}, then repeat the request.{ELSEWHERE}", 401)
        return key

    async def settled(self, pending: Pending) -> str | None:
        try:
            async with asyncio.timeout(self.link_after):
                if not await asyncio.shield(pending.opened) and not pending.callback.outcome.done():
                    return None
                return await asyncio.shield(pending.task)
        except TimeoutError:
            return None

    async def complete(self, callback_url: str) -> str:
        stored = await self.saved()
        if stored is not None:
            return stored
        pending = self._pending
        if pending is None or pending.task.done():
            raise AdminError("No LiteLLM sign-in is waiting for that address. Call sign_in without callback_url to start "
                             "a new one.", 400)
        status, text = pending.callback.resolve(urlsplit(callback_url).query)
        if status != 200:
            raise AdminError(text, 400)
        return await asyncio.shield(pending.task)

    async def renew(self, credential: str) -> str | None:
        async with self._lock:
            record = self.store.load(self.gateway)
            if record is None:
                return None
            if record["access_token"] != credential:
                return record["access_token"]
            return await self._refresh(record)

    async def forget(self, credential: str):
        record = self.store.load(self.gateway)
        if record is not None and record["access_token"] == credential:
            self.store.save(self.gateway, None)
            await self._revoke(record)

    async def sign_out(self) -> str:
        record = self.store.load(self.gateway)
        if record is None:
            return f"No saved LiteLLM sign-in for {self.gateway}."
        status = await self._revoke(record)
        if status == 503:
            raise AdminError("The gateway could not record the sign-out right now. Nothing was removed; "
                             "run logout again shortly.", 503)
        self.store.save(self.gateway, None)
        until = datetime.fromtimestamp(record["expires_at"], timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        lasting = (f" The access token it last issued stays valid at the gateway until {until}."
                   if self.now() < record["expires_at"] else "")
        if status is not None and 200 <= status < 300:
            return (f"Signed out of {self.gateway}. The gateway revoked the sign-in's refresh token, so it is no longer "
                    f"renewed, and its saved copy was removed.{lasting}")
        return (f"Removed the saved sign-in for {self.gateway}, but the gateway did not confirm revoking its refresh "
                f"token ({'no answer' if status is None else f'HTTP {status}'}).{lasting}")

    async def _stored(self) -> str | None:
        record = self.store.load(self.gateway)
        if record is None:
            return None
        if self.now() < record["expires_at"] - REFRESH_MARGIN_SECONDS:
            return record["access_token"]
        try:
            renewed = await self._refresh(record)
        except AdminError as exc:
            if self.now() < record["expires_at"]:
                return record["access_token"]
            raise AdminError(f"The saved LiteLLM sign-in has expired and could not be renewed: {exc} Try again shortly.",
                             503) from None
        if renewed is not None:
            return renewed
        return record["access_token"] if self.now() < record["expires_at"] else None

    async def _refresh(self, record: dict) -> str | None:
        try:
            renewed = await self._token(record, grant_type="refresh_token", refresh_token=record["refresh_token"])
        except AdminError as exc:
            latest = self.store.load(self.gateway)
            if latest is not None and latest["refresh_token"] != record["refresh_token"] and self.now() < latest["expires_at"]:
                return latest["access_token"]
            if exc.status != 401:
                raise
            return None
        self.store.save(self.gateway, renewed)
        return renewed["access_token"]

    async def _start(self, signed_in: Callable[[], Awaitable[None]] | None) -> Pending:
        contract = await self._discover()
        state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        callback = await Callback(state).open()
        try:
            client_id = await self._register(contract["registration_endpoint"], callback.redirect_uri)
        except BaseException:
            await callback.close()
            raise
        url = contract["authorization_endpoint"] + "?" + urlencode({
            "response_type": "code", "client_id": client_id, "redirect_uri": callback.redirect_uri, "state": state,
            "code_challenge": challenge, "code_challenge_method": "S256", "resource": contract["resource"]})
        task = asyncio.create_task(self._finish(contract, callback, client_id, verifier, signed_in))
        opened = asyncio.create_task(asyncio.to_thread(self.open_browser, url))
        for started in (task, opened):
            started.add_done_callback(lambda done: done.cancelled() or done.exception())
        return Pending(url, opened, callback, task)

    async def _finish(self, contract: dict, callback: Callback, client_id: str, verifier: str,
                      signed_in: Callable[[], Awaitable[None]] | None) -> str:
        try:
            async with asyncio.timeout(self.timeout):
                code = await callback.outcome
        except TimeoutError:
            raise AdminError("LiteLLM sign-in was not completed in the browser in time; repeat the request to "
                             "start a new one.", 401) from None
        finally:
            await callback.close()
        record = await self._token({**contract, "client_id": client_id}, grant_type="authorization_code", code=code,
                                   redirect_uri=callback.redirect_uri, code_verifier=verifier)
        self.store.save(self.gateway, record)
        if signed_in is not None:
            await signed_in()
        return record["access_token"]

    async def _discover(self) -> dict:
        contract = await self._json("GET", self.gateway + DISCOVERY_PATH, "sign-in discovery")
        endpoints = ("issuer", "authorization_endpoint", "token_endpoint", "registration_endpoint",
                     "revocation_endpoint", "resource")
        origins = {origin(contract.get(name)) for name in endpoints}
        if (contract.get("contract_version") != 1 or "S256" not in contract.get("code_challenge_methods_supported", ())
                or None in origins):
            raise AdminError("The gateway's sign-in discovery document is unsupported; upgrade LiteLLM or set LITELLM_API_KEY.", 502)
        elsewhere = sorted(origins - {origin(self.gateway)})
        if elsewhere:
            alternative = (f", or set LITELLM_BASE_URL to {elsewhere[0]} if that is this gateway's own address"
                           if len(elsewhere) == 1 and connectable(elsewhere[0]) else "")
            raise AdminError(f"The gateway's sign-in discovery names {', '.join(elsewhere)} instead of {origin(self.gateway)}. "
                             f"Set PROXY_BASE_URL on the gateway to {self.gateway}{alternative}.", 502)
        return contract

    async def _register(self, endpoint: str, redirect_uri: str) -> str:
        client = await self._json("POST", endpoint, "client registration", json={
            "client_name": CLIENT_NAME, "redirect_uris": [redirect_uri], "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"], "token_endpoint_auth_method": "none"})
        if not isinstance(client.get("client_id"), str) or not client["client_id"]:
            raise AdminError("The gateway's client registration returned no client_id.", 502)
        return client["client_id"]

    async def _token(self, endpoints: dict, **form: str) -> dict:
        token = await self._json("POST", endpoints["token_endpoint"], "token request",
                                 data={**form, "client_id": endpoints["client_id"], "resource": endpoints["resource"]})
        if (not isinstance(token.get("access_token"), str) or not token["access_token"]
                or not isinstance(token.get("refresh_token"), str) or not token["refresh_token"]
                or not isinstance(token.get("expires_in"), int) or token["expires_in"] <= 0):
            raise AdminError("The gateway's token response is unsupported.", 502)
        return {"access_token": token["access_token"], "refresh_token": token["refresh_token"],
                "expires_at": self.now() + token["expires_in"],
                **{name: endpoints[name] for name in ("client_id", "token_endpoint", "revocation_endpoint", "resource")}}

    async def _revoke(self, record: dict) -> int | None:
        try:
            response = await self.client.post(record["revocation_endpoint"], follow_redirects=False, data={
                "token": record["refresh_token"], "token_type_hint": "refresh_token", "client_id": record["client_id"]})
        except httpx2.RequestError:
            return None
        return response.status_code

    async def _json(self, method: str, url: str, purpose: str, **kwargs) -> dict:
        try:
            response = await self.client.request(method, url, follow_redirects=False, **kwargs)
        except httpx2.RequestError:
            raise AdminError(f"The gateway's {purpose} could not be completed.", 504) from None
        if response.status_code == 404 and purpose == "sign-in discovery":
            raise AdminError("This gateway does not offer browser sign-in; upgrade LiteLLM or set LITELLM_API_KEY.", 503)
        try:
            body = response.json()
        except ValueError:
            body = None
        if not 200 <= response.status_code < 300 or not isinstance(body, dict):
            error = body.get("error") if isinstance(body, dict) else None
            detail = body.get("error_description") or error if isinstance(body, dict) else None
            rejected = response.status_code == 401 or response.status_code == 400 and error in REJECTED_GRANTS
            raise AdminError(f"The gateway's {purpose} failed with HTTP {response.status_code}"
                             + (f": {str(detail)[:200]}" if detail else "") + ".", 401 if rejected else 502)
        return body
