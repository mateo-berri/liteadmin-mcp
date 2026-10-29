import copy
import json
import pickle

import httpx2
from mcp.shared.exceptions import MCPError
import pytest

from conftest import SPEC, data, session_for
from litellm_admin_mcp.catalog import OPERATIONS
from litellm_admin_mcp.config import Config
from litellm_admin_mcp.gateway import AdminError, Gateway, HELPERS
from litellm_admin_mcp.schema import tool_schema
from litellm_admin_mcp.server import create_http_app


async def test_real_mcp_create_key_and_read_back(stub):
    async with session_for(stub) as session:
        tools = (await session.list_tools()).tools
        assert {t.name for t in tools} == {"create_key", "list_keys", "add_model", "get_model", "reset_key_spend"} | HELPERS.keys()
        created = data(await session.call_tool("create_key", {"body": {"key_alias": "engineering", "max_budget": 100}}))
        assert created["key"].startswith("sk-created-for-")
        assert created["echo"] == "[credential redacted]"
        found = data(await session.call_tool("list_keys", {"query": {"page": 1, "size": 10}}))
        assert found["keys"][0]["key_alias"] == "engineering"
    assert len(stub.writes) == 1
    assert all(r.headers["Authorization"] == "Bearer alice-admin" for r in stub.requests)


async def test_real_mcp_add_model_verify_and_strip_provider_secrets(stub):
    body = {"model_name": "support", "litellm_params": {"model": "openai/gpt-4.1", "litellm_credential_name": "production"}, "model_info": {}}
    async with session_for(stub) as session:
        created = data(await session.call_tool("add_model", {"body": body}))
        assert created["model_id"] == "model-1"
        read = data(await session.call_tool("get_model", {"query": {"litellm_model_id": "model-1"}}))
        assert read["data"][0]["model_info"]["id"] == "model-1"
        assert read["data"][0]["litellm_params"] == body["litellm_params"]
        assert "secret" not in json.dumps([created, read])
    assert json.loads(stub.writes[0].content) == body


@pytest.mark.parametrize("options", [{"read_only": True}, {"allowed_tools": frozenset({"list_keys"})}])
async def test_policy_blocks_hidden_write_even_when_called_directly(stub, options):
    async with session_for(stub, **options) as session:
        assert "create_key" not in {t.name for t in (await session.list_tools()).tools}
        assert (await session.call_tool("create_key", {"body": {"key_alias": "forbidden"}})).is_error
    assert not stub.writes


async def test_unverified_user_cannot_discover_or_call(stub):
    async with session_for(stub, api_key="viewer") as session:
        with pytest.raises(MCPError):
            await session.list_tools()
        assert (await session.call_tool("create_key", {"body": {"key_alias": "forbidden"}})).is_error
    assert all(r.url.path == "/user/info" for r in stub.requests)


async def test_non_admin_rejection_survives_copy_and_pickle(stub):
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(stub.handle)) as client:
        with pytest.raises(AdminError) as raised:
            await Gateway(Config("https://gateway.example.com", api_key="viewer"), client).authorize("viewer")
    for rebuilt in (copy.copy(raised.value), pickle.loads(pickle.dumps(raised.value))):
        assert (type(rebuilt), str(rebuilt), rebuilt.status) == (type(raised.value), str(raised.value), 403)


@pytest.mark.parametrize("arguments", [{}, {"body": {}}, {"body": {"key_alias": 7}}, {"body": {"key_alias": "a"}, "headers": {"Authorization": "spoof"}}])
async def test_invalid_arguments_do_not_reach_management_api(stub, arguments):
    async with session_for(stub) as session:
        assert (await session.call_tool("create_key", arguments)).is_error
    assert not stub.writes


@pytest.mark.parametrize("identifier", ["..", "a/b", "a\\b", "a\n", "a%2Fb", ""])
async def test_path_parameters_cannot_escape_route(stub, identifier):
    async with session_for(stub) as session:
        assert (await session.call_tool("reset_key_spend", {"path": {"key": identifier}})).is_error
    assert not stub.writes


@pytest.mark.parametrize("status,timeout", [(307, False), (403, False), (500, False), (200, True)])
async def test_failed_write_is_not_retried_or_redirected_and_does_not_echo_body(stub, status, timeout):
    stub.status, stub.timeout = status, timeout
    async with session_for(stub) as session:
        result = await session.call_tool("create_key", {"body": {"key_alias": "one"}})
        assert result.is_error and "before retrying" in result.content[0].text
        assert "secret" not in result.content[0].text
    assert len(stub.writes) == 1


async def test_revocation_during_write_suppresses_returned_key(stub):
    stub.revoke = True
    async with session_for(stub) as session:
        result = await session.call_tool("create_key", {"body": {"key_alias": "one"}})
        assert result.is_error and "sk-created" not in str(result)
    assert len(stub.writes) == 1


async def test_operation_id_drift_fails_closed(stub):
    stub.spec = copy.deepcopy(SPEC)
    stub.spec["paths"]["/model/new"]["post"]["operationId"] = "changed"
    async with session_for(stub) as session:
        with pytest.raises(MCPError, match="changed"):
            await session.list_tools()
    assert not stub.writes


def test_catalog_has_unique_stable_tools_and_preserves_existing_surface():
    assert len(OPERATIONS) == 65
    assert len({o.name for o in OPERATIONS}) == len(OPERATIONS)
    assert len({(o.method, o.path) for o in OPERATIONS}) == len(OPERATIONS)


@pytest.mark.parametrize("url", ["https://user:secret@example.com", "https://example.com/path", "https://example.com?key=secret", "http://public.example.com", "https://example.com:bad"])
def test_gateway_must_be_a_fixed_trusted_origin(url):
    with pytest.raises(ValueError):
        Config(url)


def test_http_server_refuses_shared_process_credential():
    with pytest.raises(ValueError, match="Do not set"):
        create_http_app(Gateway(Config("https://gateway.example.com", api_key="shared")))


async def test_key_permissions_filter_discovery_and_block_direct_calls(stub):
    stub.denied_tools = {"create_key", "add_model"}
    async with session_for(stub) as session:
        assert {t.name for t in (await session.list_tools()).tools} == {
            "list_keys", "get_model", "reset_key_spend", *HELPERS,
        }
        assert (await session.call_tool("create_key", {"body": {"key_alias": "forbidden"}})).is_error
        assert (await session.call_tool("describe_admin_tool", {"name": "create_key"})).is_error
        assert data(await session.call_tool("list_keys", {})) == {"keys": []}
    assert not stub.writes


async def test_concrete_resource_permission_is_checked_before_write(stub):
    stub.denied_paths = {"/key/other-key/reset_spend"}
    async with session_for(stub) as session:
        assert data(await session.call_tool("reset_key_spend", {"path": {"key": "my-key"}})) == {"status": "ok"}
        assert (await session.call_tool("reset_key_spend", {"path": {"key": "other-key"}})).is_error
    assert [request.url.path for request in stub.writes] == ["/key/my-key/reset_spend"]


async def test_legacy_gateway_without_credential_permissions_fails_closed(stub):
    original = stub.handle
    def handle(request):
        response = original(request)
        if request.url.path == "/user/info":
            body = response.json()
            body.pop("admin_mcp_permissions")
            return httpx2.Response(200, json=body)
        return response
    stub.handle = handle
    async with session_for(stub) as session:
        with pytest.raises(MCPError, match="upgrade LiteLLM"):
            await session.list_tools()
        assert (await session.call_tool("create_key", {"body": {"key_alias": "forbidden"}})).is_error
    assert not stub.writes


def test_recursive_refs_and_overridden_parameters_have_valid_schema():
    import jsonschema
    spec = {"components": {"schemas": {"Node": {"type": "object", "properties": {
        "next": {"$ref": "#/components/schemas/Node", "nullable": True}}}}}}
    path = {"parameters": [{"in": "query", "name": "limit", "schema": {"type": "string"}}]}
    op = {"parameters": [{"in": "query", "name": "limit", "schema": {"type": "integer"}}],
          "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Node"}}}}}
    schema = tool_schema(spec, path, op)
    validator = jsonschema.Draft202012Validator(schema)
    validator.validate({"query": {"limit": 3}, "body": {"next": {"next": None}}})
    with pytest.raises(jsonschema.ValidationError):
        validator.validate({"query": {"limit": "wrong"}, "body": {}})


def test_schema_names_with_json_pointer_escapes():
    import jsonschema
    spec = {"components": {"schemas": {"A/B~C": {"type": "integer"}}}}
    op = {"requestBody": {"required": True, "content": {"application/json": {
        "schema": {"$ref": "#/components/schemas/A~1B~0C"}}}}}
    schema = tool_schema(spec, {}, op)
    jsonschema.Draft202012Validator(schema).validate({"body": 3})
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate({"body": "wrong"})


async def test_shared_http_client_never_replays_another_callers_gateway_cookie(stub):
    from litellm_admin_mcp.gateway import Gateway
    original = stub.handle
    def handle(request):
        assert not request.headers.get("cookie")
        result = original(request)
        result.headers["set-cookie"] = "gateway-session=first-caller; Path=/"
        return result
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handle)) as client:
        gateway = Gateway(Config("https://gateway.example.com"), client)
        for key in ("alice-admin", "bob-admin"):
            await gateway.call("create_key", {"body": {"key_alias": key}}, key)
    assert len(stub.writes) == 2
