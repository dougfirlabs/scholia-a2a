"""Shared demo plumbing: Agent Cards, Starlette app assembly, extension echo.

a2a-sdk 1.2.1 parses the inbound `A2A-Extensions` header into
`RequestContext.requested_extensions`, but does not echo activated
extensions back on the response. `ExtensionEchoMiddleware` adds that echo
(spec 0.2 section 3: an agent SHOULD echo the URIs it activated; clients
MUST NOT depend on observing it, and the demo client does not).
"""

from __future__ import annotations

import os
import sys
from typing import Iterable

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from starlette.applications import Starlette
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from a2a.extensions.common import HTTP_EXTENSION_HEADER, get_requested_extensions
from a2a.server.agent_execution.agent_executor import AgentExecutor
from a2a.server.request_handlers.default_request_handler_v2 import DefaultRequestHandlerV2 as DefaultRequestHandler
from a2a.server.routes.agent_card_routes import create_agent_card_routes
from a2a.server.routes.jsonrpc_routes import create_jsonrpc_routes
from a2a.server.tasks.inmemory_task_store import InMemoryTaskStore
from a2a.types.a2a_pb2 import (
    AgentCapabilities,
    AgentCard,
    AgentExtension,
    AgentInterface,
    AgentProvider,
    AgentSkill,
)
from a2a.utils.constants import PROTOCOL_VERSION_1_0, TransportProtocol

from scholia_a2a import agent_extension

HOST = "127.0.0.1"
PLANNER_PORT = 9601
ANALYST_PORT = 9602
RPC_PATH = "/a2a"


class ExtensionEchoMiddleware:
    """Echo the subset of requested extension URIs that this agent supports."""

    def __init__(self, app: ASGIApp, supported: Iterable[str]):
        self.app = app
        self.supported = set(supported)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        requested = get_requested_extensions(
            [v.decode("latin-1") for k, v in scope.get("headers", []) if k.lower() == HTTP_EXTENSION_HEADER.lower().encode()]
        )
        activated = sorted(requested & self.supported)

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start" and activated:
                headers = list(message.get("headers", []))
                headers.append((HTTP_EXTENSION_HEADER.lower().encode(), ",".join(activated).encode()))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_wrapper)


def make_card(
    name: str,
    description: str,
    port: int,
    skill: AgentSkill,
    *,
    with_extension: bool = True,
    extension_params: dict | None = None,
) -> AgentCard:
    url = f"http://{HOST}:{port}{RPC_PATH}"
    extensions = []
    if with_extension:
        entry = agent_extension(**(extension_params or {}))
        extensions.append(AgentExtension(**entry))
    return AgentCard(
        name=name,
        description=description,
        version="0.2.0",
        provider=AgentProvider(organization="Doug Fir Labs (demo)", url="https://scholialang.org"),
        documentation_url="https://scholialang.org/ext/a2a/provenance/v1",
        supported_interfaces=[
            AgentInterface(url=url, protocol_binding=TransportProtocol.JSONRPC, protocol_version=PROTOCOL_VERSION_1_0)
        ],
        capabilities=AgentCapabilities(streaming=False, push_notifications=False, extensions=extensions),
        default_input_modes=["text/plain"],
        default_output_modes=["text/plain", "application/json"],
        skills=[skill],
    )


def make_app(card: AgentCard, executor: AgentExecutor) -> Starlette:
    handler = DefaultRequestHandler(agent_executor=executor, task_store=InMemoryTaskStore(), agent_card=card)
    routes = create_agent_card_routes(card) + create_jsonrpc_routes(handler, RPC_PATH)
    app = Starlette(routes=routes)
    supported = [e.uri for e in card.capabilities.extensions]
    return ExtensionEchoMiddleware(app, supported)  # type: ignore[return-value]


def serve(app: ASGIApp, port: int) -> None:
    import uvicorn

    uvicorn.run(app, host=HOST, port=port, log_level="warning")
