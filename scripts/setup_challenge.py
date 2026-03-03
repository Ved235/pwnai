#!/usr/bin/env python3
"""Prepare the challenge playground and start binary analysis in container."""

from __future__ import annotations

import argparse
import asyncio
import json
import shlex
import subprocess
import sys
import os
import httpx
from pathlib import Path, PurePosixPath


CONTAINER_NAME = "ctf-dev"
WORKSPACE_IN_CONTAINER = PurePosixPath("/workspace")
PLAYGROUND_PATH = PurePosixPath("/workspace/playground")


class SetupError(RuntimeError):
    pass


def status(message: str) -> None:
    print(message)


def run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if check and proc.returncode != 0:
        details = (proc.stderr or "").strip() or (proc.stdout or "").strip() or f"exit code {proc.returncode}"
        raise SetupError(f"command failed: {shlex.join(cmd)}\n{details}")
    return proc


def dockerExec(shellCmd: str, *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run(["bash", "-lc", shellCmd], check=check)


def quote(value: str) -> str:
    return shlex.quote(value)


def parseArgs() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Setup challenge environment and start binary analysis.")
    parser.add_argument("--manifest", default="manifest.json", help="Path to challenge manifest JSON.")
    parser.add_argument("--binary-name", default=None, help="Optional binary name when source is a directory.")
    return parser.parse_args()

def loadSourceFromManifest(manifestPath: Path) -> str:
    if not manifestPath.exists():
        raise SetupError(f"manifest not found: {manifestPath}")
    try:
        data = json.loads(manifestPath.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SetupError(f"invalid manifest JSON: {manifestPath}\n{exc}") from exc

    source = data.get("source")
    if not isinstance(source, str) or not source.strip():
        raise SetupError("manifest 'source' must be a non-empty string")
    return source.strip()


def resolveRepoPath(repoRoot: Path, targetPath: Path) -> Path:
    try:
        return targetPath.resolve().relative_to(repoRoot.resolve())
    except ValueError as exc:
        raise SetupError(f"path must be inside repo root: {targetPath}") from exc


def resolveSource(repoRoot: Path, sourceFromManifest: str) -> tuple[Path, Path]:
    sourceHost = (repoRoot / sourceFromManifest).resolve()
    if not sourceHost.exists():
        raise SetupError(f"manifest source does not exist: {sourceHost}")
    sourceRel = resolveRepoPath(repoRoot, sourceHost)
    return sourceHost, sourceRel


def isExecutableElf(path: Path) -> bool:
    if not path.is_file() or not os.access(path, os.X_OK):
        return False
    with path.open("rb") as handle:
        return handle.read(4) == b"\x7fELF"


def resolveBinaryNameForLoader(sourceHost: Path, binaryNameArg: str | None) -> str:
    if binaryNameArg:
        return binaryNameArg
    if sourceHost.is_file():
        return sourceHost.name
    candidates = [p.name for p in sourceHost.rglob("*") if isExecutableElf(p)]
    if len(candidates) == 1:
        return candidates[0]
    raise SetupError("unable to infer binary name from source directory, pass --binary-name")


def startBinaryAnalysis(manifestContainerPath: PurePosixPath, binaryName: str | None) -> str:
    pythonCode = (
        "from scripts.binary_analysis_agent import runBinaryAnalysisAgent; "
        f"runBinaryAnalysisAgent({str(manifestContainerPath)!r}, {binaryName!r})"
    )
    proc = dockerExec(f"cd /workspace && python3 -c {quote(pythonCode)}")
    return proc.stdout.strip()


def startExploitDevelopment(manifestContainerPath: PurePosixPath, binaryName: str | None) -> str:
    pythonCode = (
        "from scripts.exploit_development_agent import runExploitDevelopmentAgent; "
        f"runExploitDevelopmentAgent({str(manifestContainerPath)!r}, {binaryName!r})"
    )
    proc = dockerExec(f"cd /workspace && python3 -c {quote(pythonCode)}")
    return proc.stdout.strip()


async def main() -> int:
    args = parseArgs()
    manifestPath = Path(args.manifest).expanduser().resolve()
    repoRoot = Path.cwd().resolve()

    try:
        status(f"[1/5] Loading manifest: {manifestPath}")
        sourceFromManifest = loadSourceFromManifest(manifestPath)

        status("[2/5] Resolving source and manifest paths")
        sourceHost, sourceRel = resolveSource(repoRoot, sourceFromManifest)
        binaryNameForLoader = resolveBinaryNameForLoader(sourceHost, args.binary_name)
        manifestRel = resolveRepoPath(repoRoot, manifestPath)
        sourceContainer = WORKSPACE_IN_CONTAINER / PurePosixPath(sourceRel.as_posix())
        manifestContainer = WORKSPACE_IN_CONTAINER / PurePosixPath(manifestRel.as_posix())

        status(f"[3/5] Validating Docker container: {CONTAINER_NAME}")

        status(f"[4/5] Preparing playground at {PLAYGROUND_PATH} and MCP")
        if sourceHost.is_dir():
            copyCmd = f"cp -a {quote(str(sourceContainer))}/. {quote(str(PLAYGROUND_PATH))}/"
            copiedTargetPath = str(PLAYGROUND_PATH)
        else:
            copyCmd = f"cp {quote(str(sourceContainer))} {quote(str(PLAYGROUND_PATH))}/ && chmod +x {quote(str(PLAYGROUND_PATH / sourceHost.name))}"
            copiedTargetPath = str(PLAYGROUND_PATH / sourceHost.name)

        setupCmd = " && ".join(
            [
                f"rm -rf {quote(str(PLAYGROUND_PATH))}",
                f"mkdir -p {quote(str(PLAYGROUND_PATH))}",
                copyCmd,
                f"mkdir -p {quote(str(PLAYGROUND_PATH / 'artifacts'))}",
                f"echo {quote('flag{test_flag}')} > {quote(str(PLAYGROUND_PATH / 'flag.txt'))}"
            ]
        )
        dockerExec(setupCmd)
        loader_url = os.environ.get("SETUP_URL").strip()
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(loader_url, json={"filename": binaryNameForLoader})
        if resp.status_code != 200:
            raise SetupError(f"failed to notify loader: {resp.status_code} {resp.text}")
        status("[5/6] Starting binary analysis")
        analysisOutput = startBinaryAnalysis(manifestContainer, args.binary_name)
        if analysisOutput:
            print(analysisOutput)
        status("[6/6] Starting exploit development")
        exploitOutput = startExploitDevelopment(manifestContainer, args.binary_name)
        if exploitOutput:
            print(exploitOutput)

        status("Setup flow complete")
        summary = {
            "container_name": CONTAINER_NAME,
            "source": sourceFromManifest,
            "copied_target_path": copiedTargetPath,
            "playground_path": str(PLAYGROUND_PATH),
            "binary_analysis_started": True,
            "exploit_development_started": True,
            "exploit_development_success": True,
        }
        print(json.dumps(summary))
        return 0
    except SetupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
