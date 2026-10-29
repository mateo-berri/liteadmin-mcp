"""Authenticated, non-retrying calls to a fixed LiteLLM management API."""
import asyncio
from dataclasses import dataclass
import json
import re
import time
from typing import Any
from urllib.parse import quote

import httpx2
import jsonschema
from mcp import types

from .catalog import BY_NAME, OPERATIONS
from .config import Config
from .schema import SchemaError, discovery_schema, tool_schema
from .results import (MAX_RESULT_BYTES, PAGE_BYTES, READ_SCHEMA, RESPONSE_SCHEMA,
                      ResultError, ResultStore, encode, page, select)


DESCRIBE_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["name"],
    "properties": {"name": {"type": "string", "description": "Exact name of an enabled administrative tool."},
                   "response": RESPONSE_SCHEMA},
}
HELPERS = {
    "describe_admin_tool": (DESCRIBE_SCHEMA, "Read the complete input schema and annotations of an enabled tool, including all advanced arguments and referenced definitions. Required before using a tool in discovery schema mode. Returns full detail by default; response.view=compact pages unusually large schemas."),
    "read_admin_result": (READ_SCHEMA, "Read an exact saved result without re-executing its operation. Browse fields, array items and string chunks using returned paths/next arguments. view=full returns the entire selected value. Snapshots expire after five minutes; never repeat a write to recover its response."),
}


class AdminError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


class NotAdmin(AdminError):
    def __init__(self):
        super().__init__("Only current LiteLLM proxy admins may use these tools.", 403)


@dataclass(frozen=True)
class Authorization:
    principal: str
    tools: frozenset[str]


def valid_credential(value: str) -> str:
    if not value or len(value) > 8192 or any(not 33 <= ord(c) <= 126 for c in value):
        raise AdminError("A personal LiteLLM admin credential is required.", 401)
    return value


def safe_result(value: Any, credential: str) -> Any:
    """Keep new virtual keys usable, but never return provider/authentication secrets."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key.lower() == "litellm_params":
                if isinstance(item, str):
                    try:
                        item = json.loads(item)
                    except ValueError:
                        item = {}
                item = {k: v for k, v in item.items() if k in {"model", "litellm_credential_name"}} if isinstance(item, dict) else {}
            elif key.lower() in {"api_key", "token", "access_token", "refresh_token", "password", "secret",
                                 "client_secret", "authorization", "authentication_token", "credential_values"}:
                if not (key.lower() in {"api_key", "token"} and isinstance(item, str) and re.fullmatch(r"[a-f0-9]{64}", item)):
                    item = "[redacted]"
            result[key] = safe_result(item, credential)
        return result
    if isinstance(value, list):
        return [safe_result(item, credential) for item in value]
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except ValueError:
            decoded = None
        if isinstance(decoded, (dict, list)):
            return json.dumps(safe_result(decoded, credential))
        return value.replace(credential, "[credential redacted]")
    return value


class Gateway:
    def __init__(self, config: Config, client: httpx2.AsyncClient | None = None):
        self.config = config
        self.client = client
        self._owns_client = client is None
        self._tools: dict[str, types.Tool] | None = None
        self._loaded_at = 0.0
        self._schema_lock = asyncio.Lock()
        self.results = ResultStore()

    async def __aenter__(self):
        if self.client is None:
            self.client = httpx2.AsyncClient(timeout=httpx2.Timeout(30, read=120), follow_redirects=False)
        return self

    async def __aexit__(self, *args):
        self.results.clear()
        if self._owns_client and self.client is not None:
            await self.client.aclose()
            self.client = None

    async def _request(self, method: str, path: str, credential: str, *,
                       read_only: bool | None = None, max_bytes: int = 2_000_000, **kwargs) -> Any:
        assert self.client is not None
        write = method != "GET" if read_only is None else not read_only
        uncertain = " Check gateway state before retrying this change." if write else ""
        try:
            async with self.client.stream(method, self.config.base_url + path,
                    headers={"Authorization": "Bearer " + valid_credential(credential), "Cookie": "", **kwargs.pop("headers", {})},
                    follow_redirects=False, **kwargs) as result:
                if not 200 <= result.status_code < 300:
                    raise AdminError(f"Gateway returned HTTP {result.status_code}." + uncertain, result.status_code)
                chunks, size = [], 0
                async for chunk in result.aiter_bytes():
                    size += len(chunk)
                    if size > max_bytes:
                        raise AdminError("Result exceeds the upstream byte limit; use pagination or a narrower query." + uncertain)
                    chunks.append(chunk)
        except httpx2.RequestError:
            raise AdminError("Gateway request could not be completed." + uncertain, 504) from None
        try:
            return json.loads(b"".join(chunks))
        except ValueError:
            raise AdminError("Gateway returned an invalid JSON response." + uncertain, 502) from None

    async def authorize(self, credential: str) -> str:
        return (await self._authorization(credential)).principal

    async def _authorization(self, credential: str, *, tool: str | None = None,
                             path: str | None = None) -> Authorization:
        try:
            params = {"admin_mcp": "true"}
            if tool is not None:
                params["mcp_tool"] = tool
            if path is not None:
                params["mcp_path"] = path
            data = await self._request("GET", "/user/info", credential, params=params)
        except AdminError as exc:
            if exc.status != 404:
                raise
            data = None
        user = data.get("user_info") if isinstance(data, dict) else None
        if (not isinstance(user, dict) or user.get("user_role") != "proxy_admin"
                or not isinstance(user.get("user_id"), str) or not user["user_id"]
                or data.get("user_id") != user["user_id"] or user.get("blocked")
                or user.get("deleted") or user.get("is_active") is False):
            raise NotAdmin()
        permissions = data.get("admin_mcp_permissions")
        if (not isinstance(permissions, dict) or not isinstance(permissions.get("tools"), list)
                or any(not isinstance(name, str) for name in permissions["tools"])):
            raise AdminError("Gateway cannot verify this credential's admin permissions; upgrade LiteLLM.", 403)
        if tool is not None and permissions.get("action_allowed") is not True:
            raise AdminError("This credential is not allowed to use this admin tool.", 403)
        return Authorization(user["user_id"], frozenset(permissions["tools"]))

    async def tools(self, credential: str) -> dict[str, types.Tool]:
        authorization = await self._authorization(credential)
        canonical = await self._load_tools(credential)
        visible = {}
        for name, tool in canonical.items():
            if name not in authorization.tools:
                continue
            visible[name] = (tool.model_copy(update={"input_schema": discovery_schema(tool.input_schema, name),
                "description": tool.description + " Call describe_admin_tool for the complete argument schema before use."})
                if self.config.schema_mode == "discovery" else tool)
        for name, (schema, description) in HELPERS.items():
            visible[name] = types.Tool(name=name, description=description, inputSchema=schema,
                annotations=types.ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
        return visible

    async def _load_tools(self, credential: str) -> dict[str, types.Tool]:
        async with self._schema_lock:
            if self._tools is not None and time.monotonic() - self._loaded_at < 300:
                return self._tools
            spec = await self._request("GET", "/openapi.json", credential, max_bytes=64_000_000)
            if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
                raise AdminError("Gateway OpenAPI schema is unavailable.", 503)
            selected = {}
            for item in OPERATIONS:
                if self.config.allowed_tools and item.name not in self.config.allowed_tools:
                    continue
                if self.config.read_only and not item.read_only:
                    continue
                path = spec["paths"].get(item.path, {})
                operation = path.get(item.method.lower())
                if not operation:
                    continue
                if operation.get("operationId") != item.operation_id:
                    raise AdminError(f"Gateway operation changed for {item.name}; update the connector before using it.", 503)
                try:
                    schema = tool_schema(spec, path, operation)
                    schema["properties"]["response"] = RESPONSE_SCHEMA
                    jsonschema.Draft202012Validator.check_schema(schema)
                except (SchemaError, jsonschema.SchemaError, TypeError, KeyError):
                    raise AdminError(f"Gateway schema is unsupported for {item.name}.", 503) from None
                selected[item.name] = types.Tool(
                    name=item.name, description=f"{item.summary}. {item.method} {item.path}. "
                    + ("Read-only." if item.read_only else "Changes gateway state; execute only when requested. Never retry an uncertain write."),
                    inputSchema=schema, annotations=types.ToolAnnotations(
                        readOnlyHint=item.read_only, destructiveHint=not item.read_only,
                        idempotentHint=item.read_only, openWorldHint=True,
                    ),
                )
            if not selected:
                raise AdminError("No compatible, enabled admin tools were found on this gateway.", 503)
            self._tools = selected
            self._loaded_at = time.monotonic()
            return selected

    async def call(self, name: str, arguments: dict, credential: str) -> Any:
        # No redundant call to tools(): execution and disclosure each have a
        # fresh authorization check. Roles/identities are never cached.
        authorization = await self._authorization(credential)
        principal = authorization.principal
        loaded_at = self._loaded_at
        available = await self._load_tools(credential)
        if name not in available and name not in HELPERS:
            raise AdminError("This tool is not enabled for this connector.", 403)
        if name not in authorization.tools and name not in HELPERS:
            raise AdminError("This credential is not allowed to use this admin tool.", 403)
        try:
            schema = HELPERS[name][0] if name in HELPERS else available[name].input_schema
            jsonschema.Draft202012Validator(schema).validate(arguments)
        except jsonschema.ValidationError as exc:
            location = "/" + "/".join(str(p) for p in exc.absolute_path)
            raise AdminError(f"Arguments do not match the complete tool schema at {location}. Use describe_admin_tool for all accepted fields.") from None
        if name in HELPERS:
            return await self._helper(name, arguments, credential, principal, available)
        if loaded_at != self._loaded_at:
            # Discovery awaited upstream I/O; check the original principal
            # again before execution, without caching or rebinding identity.
            await self._verify(credential, principal)
        view = arguments.get("response", {}).get("view", self.config.response_view)
        return await self._execute(name, arguments, credential, principal, view)

    async def _verify(self, credential: str, principal: str, *, tool: str | None = None,
                      path: str | None = None):
        if (await self._authorization(credential, tool=tool, path=path)).principal != principal:
            raise AdminError("Admin identity changed during the request. Inspect gateway state before retrying.", 403)

    def _view(self, name: str, value: Any, credential: str, principal: str, view: str,
              path: str | None = None) -> Any:
        if view == "compact" and len(encode(value)) > PAGE_BYTES:
            token = self.results.put(name, value, credential, principal, route=path)
            if token is not None:
                return page(self.results.get(token, credential, principal), token)
        return value

    async def _helper(self, name, arguments, credential, principal, available):
        try:
            if name == "describe_admin_tool":
                target = arguments["name"]
                if target not in available:
                    raise AdminError("This tool is not enabled for this connector.", 403)
                result = available[target].model_dump(by_alias=True, exclude_none=True, mode="json")
                await self._verify(credential, principal, tool=target)
                return self._view("schema:" + target, result, credential, principal,
                                  arguments.get("response", {}).get("view", "full"))
            token = arguments["result_id"]
            item = self.results.get(token, credential, principal)
            if item.source.removeprefix("schema:") not in available:
                raise AdminError("The source operation is no longer enabled.", 403)
            if arguments.get("view", "page") == "full":
                if any(k in arguments for k in ("offset", "limit", "max_chars")):
                    raise AdminError("Full reads do not accept pagination arguments.")
                result = select(json.loads(item.raw), arguments.get("path", ""))
            else:
                result = page(item, token, **{k: v for k, v in arguments.items() if k not in {"result_id", "view"}})
            await self._verify(credential, principal, tool=item.source.removeprefix("schema:"), path=item.route)
            return result
        except ResultError as exc:
            raise AdminError(str(exc), 404) from None

    async def _execute(self, name, arguments, credential, principal, view):
        item = BY_NAME[name]
        path = item.path
        for field, value in arguments.get("path", {}).items():
            value = str(value)
            if value in {"", ".", ".."} or any(c in value for c in ("/", "\\", "%", "\r", "\n", "\x00")):
                raise AdminError("Invalid resource identifier.")
            path = path.replace("{" + field + "}", quote(value, safe=""))
        query = []
        for field, value in arguments.get("query", {}).items():
            if value is None:
                continue
            for part in value if isinstance(value, list) else [value]:
                query.append((field, json.dumps(part) if isinstance(part, (dict, bool)) else str(part)))
        body, headers = {}, {"litellm-changed-by": principal}
        if "body" in arguments:
            if arguments["body"] is None:
                # httpx's json=None means "no body", not the JSON value null.
                body = {"content": b"null"}
                headers["Content-Type"] = "application/json"
            else:
                body = {"json": arguments["body"]}
        await self._verify(credential, principal, tool=name, path=path)
        result = await self._request(item.method, path, credential, params=query, **body,
            read_only=item.read_only, max_bytes=MAX_RESULT_BYTES,
            headers=headers)
        await self._verify(credential, principal, tool=name, path=path)
        return self._view(name, safe_result(result, credential), credential, principal, view, path=path)
