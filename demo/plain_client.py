"""A plain A2A client: no A2A-Extensions header, no metadata. Must still get a normal answer.

Demonstrates required=false compatibility (spec section 5, last rule).
"""

from __future__ import annotations

import asyncio
import sys
import uuid

import httpx
from google.protobuf.json_format import MessageToDict

from a2a.client import ClientConfig, create_client
from a2a.types.a2a_pb2 import Message, Part, Role, SendMessageRequest

from demo.common import ANALYST_PORT, HOST
from scholia_a2a import has_provenance


async def ask(url: str, question: str) -> dict:
    async with httpx.AsyncClient(timeout=30.0) as http:
        client = await create_client(url, ClientConfig(streaming=False, httpx_client=http))
        msg = Message(message_id=str(uuid.uuid4()), role=Role.ROLE_USER, parts=[Part(text=question, media_type="text/plain")])
        task = {}
        async for resp in client.send_message(SendMessageRequest(message=msg)):
            if resp.HasField("task"):
                task = MessageToDict(resp.task)
        await client.close()
    art = (task.get("artifacts") or [{}])[0]
    text = " ".join(p.get("text", "") for p in art.get("parts", []) if "text" in p).strip()
    return {
        "state": (task.get("status") or {}).get("state"),
        "answer": text,
        "has_provenance": has_provenance(art.get("metadata") or {}, art.get("extensions") or []),
        "metadata_keys": sorted(art.get("metadata") or {}),
        "extensions": list(art.get("extensions") or []),
    }


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else f"http://{HOST}:{ANALYST_PORT}"
    res = asyncio.run(ask(url, "compare Dapr Agents and OpenTalon"))
    print(res)
    ok = res["state"] == "TASK_STATE_COMPLETED" and res["answer"] and not res["has_provenance"]
    print("PASS" if ok else "FAIL", "plain client (extension not activated) got a normal answer with no provenance block")
    sys.exit(0 if ok else 1)
