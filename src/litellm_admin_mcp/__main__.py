import argparse
import asyncio
import logging
import sys

from mcp.server.lowlevel import NotificationOptions
from mcp.server.stdio import stdio_server
import uvicorn

from .config import Config
from .gateway import AdminError, Gateway, valid_credential
from .server import create_http_app, create_server
from .signin import BrowserSignIn, CredentialStore, default_store_directory


async def run_stdio(config: Config):
    if config.api_key:
        valid_credential(config.api_key)
    async with Gateway(config) as gateway, stdio_server() as (read, write):
        sign_in = None if config.api_key else BrowserSignIn(config.base_url, gateway.client, CredentialStore(default_store_directory()))
        server = create_server(gateway, sign_in=sign_in)
        await server.run(read, write, server.create_initialization_options(NotificationOptions(tools_changed=sign_in is not None)))


async def sign_out(config: Config) -> str:
    async with Gateway(config) as gateway:
        return await BrowserSignIn(config.base_url, gateway.client, CredentialStore(default_store_directory())).sign_out()


def main():
    parser = argparse.ArgumentParser(description="LiteLLM Admin MCP connector")
    parser.add_argument("command", nargs="?", choices=["logout"],
                        help="logout revokes and removes the saved browser sign-in for LITELLM_BASE_URL")
    parser.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    try:
        config = Config.read()
        if args.command == "logout":
            print(asyncio.run(sign_out(config)))
        elif args.transport == "stdio":
            asyncio.run(run_stdio(config))
        else:
            uvicorn.run(create_http_app(Gateway(config)), host=args.host, port=args.port,
                        log_level="warning", access_log=False)
    except KeyboardInterrupt:
        pass
    except AdminError as exc:
        parser.exit(1, f"LiteLLM Admin MCP could not {'sign out' if args.command else 'start'}: {exc}\n")
    except Exception as exc:
        # Transport exceptions can include response bodies/headers. Do not print them.
        parser.exit(1, f"LiteLLM Admin MCP could not start ({type(exc).__name__}). Check its configuration and gateway connection.\n")


if __name__ == "__main__":
    main()
