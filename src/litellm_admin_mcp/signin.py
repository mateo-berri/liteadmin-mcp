"""Browser sign-in for local stdio runs that have no configured gateway credential.

The gateway publishes its native-client contract at /.well-known/litellm-cli-auth (the
same one `lite login --pkce` uses): register a public client with a loopback redirect,
send the user's browser to /authorize with PKCE S256, then redeem the code at /token for
a self-renewing gateway credential issued for the proxy API."""
import asyncio
import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
from typing import Awaitable, Callable
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx2

from .gateway import AdminError


DISCOVERY_PATH = "/.well-known/litellm-cli-auth"
SIGN_IN_SECONDS = 300
REFRESH_MARGIN_SECONDS = 360
CLIENT_NAME = "litellm-admin-mcp"
RECORD_FIELDS = ("access_token", "refresh_token", "client_id", "token_endpoint", "resource")
OPEN_BROWSER = "import sys, webbrowser; sys.exit(not webbrowser.open(sys.argv[1]))"


def default_store_path() -> Path:
    return Path(os.getenv("XDG_CONFIG_HOME") or Path.home() / ".config") / "litellm-admin-mcp" / "credentials.json"


def open_browser(url: str) -> bool:
    try:
        return subprocess.run([sys.executable, "-I", "-c", OPEN_BROWSER, url], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, start_new_session=True).returncode == 0
    except subprocess.TimeoutExpired:
        return True
    except OSError:
        return False


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
    """Owner-only JSON file holding one sign-in per gateway origin."""

    def __init__(self, path: Path):
        self.path = path

    def _records(self) -> dict:
        try:
            records = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {}
        return records if isinstance(records, dict) else {}

    def load(self, gateway: str) -> dict | None:
        record = self._records().get(gateway)
        if (not isinstance(record, dict) or any(not isinstance(record.get(f), str) or not record[f] for f in RECORD_FIELDS)
                or not isinstance(record.get("expires_at"), (int, float))):
            return None
        return record

    def save(self, gateway: str, record: dict | None):
        records = {k: v for k, v in self._records().items() if k != gateway} | ({gateway: record} if record else {})
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        staged = self.path.with_name(f".{self.path.name}.{secrets.token_hex(8)}")
        with os.fdopen(os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as file:
            json.dump(records, file)
        os.replace(staged, self.path)


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
        params = {k: v[0] for k, v in parse_qs(target.query).items()}
        if method != "GET" or target.path != "/callback":
            return 404, "Not found."
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
    opened: bool
    callback: Callback
    task: asyncio.Task


class BrowserSignIn:
    """Supplies the stored gateway credential, renewing it before it expires, and starts one
    browser sign-in at a time when there is none. A sign-in outlives the request that started
    it, so a client that stops waiting still gets the credential on its next request."""

    def __init__(self, gateway: str, client: httpx2.AsyncClient, store: CredentialStore, *,
                 open_browser: Callable[[str], bool] = open_browser, timeout: float = SIGN_IN_SECONDS,
                 now: Callable[[], float] = time.time):
        self.gateway, self.client, self.store = gateway, client, store
        self.open_browser, self.timeout, self.now = open_browser, timeout, now
        self._lock = asyncio.Lock()
        self._pending: Pending | None = None

    async def credential(self, signed_in: Callable[[], Awaitable[None]] | None = None) -> str:
        async with self._lock:
            stored = await self._stored()
            if stored is not None:
                return stored
            if self._pending is None or self._pending.task.done():
                self._pending = await self._start(signed_in)
            pending = self._pending
        if not pending.opened and not pending.callback.outcome.done():
            raise AdminError(f"Sign in to LiteLLM by opening {pending.url} in a browser on this computer, "
                             "then repeat the request.", 401)
        return await asyncio.shield(pending.task)

    def forget(self, credential: str):
        record = self.store.load(self.gateway)
        if record is not None and record["access_token"] == credential:
            self.store.save(self.gateway, None)

    async def _stored(self) -> str | None:
        record = self.store.load(self.gateway)
        if record is None:
            return None
        if self.now() < record["expires_at"] - REFRESH_MARGIN_SECONDS:
            return record["access_token"]
        try:
            renewed = await self._token(record["token_endpoint"], record["resource"], record["client_id"],
                                        grant_type="refresh_token", refresh_token=record["refresh_token"])
        except AdminError:
            latest = self.store.load(self.gateway)
            if latest is not None and latest["refresh_token"] != record["refresh_token"] and self.now() < latest["expires_at"]:
                return latest["access_token"]
            return record["access_token"] if self.now() < record["expires_at"] else None
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
        task.add_done_callback(lambda done: done.cancelled() or done.exception())
        return Pending(url, await asyncio.to_thread(self.open_browser, url), callback, task)

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
        record = await self._token(contract["token_endpoint"], contract["resource"], client_id,
                                   grant_type="authorization_code", code=code, redirect_uri=callback.redirect_uri,
                                   code_verifier=verifier)
        self.store.save(self.gateway, record)
        if signed_in is not None:
            try:
                await signed_in()
            except Exception:
                pass
        return record["access_token"]

    async def _discover(self) -> dict:
        contract = await self._json("GET", self.gateway + DISCOVERY_PATH, "sign-in discovery")
        endpoints = ("issuer", "authorization_endpoint", "token_endpoint", "registration_endpoint", "resource")
        if (contract.get("contract_version") != 1 or "S256" not in contract.get("code_challenge_methods_supported", ())
                or any(origin(contract.get(name)) != origin(self.gateway) for name in endpoints)):
            raise AdminError("The gateway's sign-in discovery document is unsupported or names another server.", 502)
        return contract

    async def _register(self, endpoint: str, redirect_uri: str) -> str:
        client = await self._json("POST", endpoint, "client registration", json={
            "client_name": CLIENT_NAME, "redirect_uris": [redirect_uri], "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"], "token_endpoint_auth_method": "none"})
        if not isinstance(client.get("client_id"), str) or not client["client_id"]:
            raise AdminError("The gateway's client registration returned no client_id.", 502)
        return client["client_id"]

    async def _token(self, endpoint: str, resource: str, client_id: str, **form: str) -> dict:
        token = await self._json("POST", endpoint, "token request",
                                 data={**form, "client_id": client_id, "resource": resource})
        if (not isinstance(token.get("access_token"), str) or not token["access_token"]
                or not isinstance(token.get("refresh_token"), str) or not token["refresh_token"]
                or not isinstance(token.get("expires_in"), int) or token["expires_in"] <= 0):
            raise AdminError("The gateway's token response is unsupported.", 502)
        return {"access_token": token["access_token"], "refresh_token": token["refresh_token"],
                "expires_at": self.now() + token["expires_in"], "client_id": client_id,
                "token_endpoint": endpoint, "resource": resource}

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
            detail = body.get("error_description") or body.get("error") if isinstance(body, dict) else None
            raise AdminError(f"The gateway's {purpose} failed with HTTP {response.status_code}"
                             + (f": {str(detail)[:200]}" if detail else "") + ".", 401 if 400 <= response.status_code < 500 else 502)
        return body
