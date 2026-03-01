#!/usr/bin/env python3
"""MCP tool mapping helpers for OpenAI-compatible LangChain tools."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from pydantic import BaseModel, Field

MAP_PATH = Path(__file__).parent.parent / "mcp-map.json"


class ListFuncsArgs(BaseModel):
    filter: str = Field(default="", description="Glob filter for function names.")
    offset: int = Field(default=0, description="Start index.")
    count: int = Field(default=50, description="Max functions (0 means all).")


class PayloadJsonArgs(BaseModel):
    payload_json: str = Field(
        description="JSON object string matching the tool input schema from mcp-map.json."
    )


def loadMap(path: Path = MAP_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def getAllowedToolSpecs(mapData: dict[str, Any]) -> dict[str, dict[str, Any]]:
    allowed = set(mapData.get("ida_tools_allowed", []))
    specs = {spec["name"]: spec for spec in mapData.get("ida_tool_specs", []) if spec.get("name") in allowed}
    return specs


def getAllowedDbgToolSpecs(mapData: dict[str, Any]) -> dict[str, dict[str, Any]]:
    allowed = set(mapData.get("dbg_tools_allowed", []))
    specs = {spec["name"]: spec for spec in mapData.get("dbg_tool_specs", []) if spec.get("name") in allowed}
    return specs


def makeListFuncsTool(rawTool: Any, spec: dict[str, Any]):
    from langchain_core.tools import StructuredTool

    description = spec.get("description") or getattr(rawTool, "description", "List functions.")

    async def listFuncs(filter: str = "", offset: int = 0, count: int = 50) -> Any:
        query: dict[str, Any] = {}
        if filter:
            query["filter"] = filter
        if offset:
            query["offset"] = offset
        query["count"] = count
        return await rawTool.ainvoke({"queries": [query]})

    return StructuredTool.from_function(
        coroutine=listFuncs,
        name="list_funcs",
        description=description,
        args_schema=ListFuncsArgs,
    )


def makePayloadTool(rawTool: Any, spec: dict[str, Any]):
    from langchain_core.tools import StructuredTool

    schemaSnippet = json.dumps(spec.get("inputSchema", {}), separators=(",", ":"), ensure_ascii=True)
    description = (
        f"{spec.get('description') or getattr(rawTool, 'description', rawTool.name)}\n"
        f"Input schema: {schemaSnippet}"
    )

    async def callWithPayload(payload_json: str) -> Any:
        payload = json.loads(payload_json.strip() or "{}")
        if not isinstance(payload, dict):
            raise ValueError("payload_json must decode to a JSON object")
        return await rawTool.ainvoke(payload)

    return StructuredTool.from_function(
        coroutine=callWithPayload,
        name=getattr(rawTool, "name", "mcp_tool"),
        description=description,
        args_schema=PayloadJsonArgs,
    )


def prepareIdaToolsForOpenAI(
    model: Any,
    rawTools: list[Any],
    mapPath: Path = MAP_PATH,
    log: Callable[[str], None] | None = None,
) -> list[Any]:
    mapData = loadMap(mapPath)
    allowedOrder = list(mapData.get("ida_tools_allowed", []))
    specs = getAllowedToolSpecs(mapData)
    rawByName = {getattr(tool, "name", ""): tool for tool in rawTools}

    prepared: list[Any] = []
    for name in allowedOrder:
        rawTool = rawByName.get(name)
        if rawTool is None:
            continue
        spec = specs.get(name, {})
        tool = makeListFuncsTool(rawTool, spec) if name == "list_funcs" else makePayloadTool(rawTool, spec)
        model.bind_tools([tool])
        prepared.append(tool)

    if not prepared:
        raise RuntimeError("No allowed MCP tools could be prepared from mcp-map.json.")

    if log is not None:
        toolNames = ", ".join(getattr(tool, "name", "unknown") for tool in prepared)
        log(f"[binary-analysis] allowed tools from map: {toolNames}")

    return prepared


def prepareDbgToolsForOpenAI(
    model: Any,
    rawTools: list[Any],
    mapPath: Path = MAP_PATH,
    log: Callable[[str], None] | None = None,
) -> list[Any]:
    mapData = loadMap(mapPath)
    allowedOrder = list(mapData.get("dbg_tools_allowed", []))
    specs = getAllowedDbgToolSpecs(mapData)
    rawByName = {getattr(tool, "name", ""): tool for tool in rawTools}

    prepared: list[Any] = []
    for name in allowedOrder:
        rawTool = rawByName.get(name)
        if rawTool is None:
            continue
        spec = specs.get(name, {})
        tool = makePayloadTool(rawTool, spec)
        model.bind_tools([tool])
        prepared.append(tool)

    if not prepared:
        raise RuntimeError("No debugger MCP tools could be prepared from mcp-map.json.")

    if log is not None:
        toolNames = ", ".join(getattr(tool, "name", "unknown") for tool in prepared)
        log(f"[exploit-debugger] allowed tools from map: {toolNames}")

    return prepared
