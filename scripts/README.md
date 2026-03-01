# Setup Script

Prepare the challenge playground, run binary analysis, then run exploit development.

## Required env vars

- `OPENAI_KEY`
- `MODEL`
- `IDA_MCP_URL`
- `PWNDBG_MCP_URL`

## Run

```bash
python3 scripts/setup_challenge.py
```

## Optional flags

```bash
python3 scripts/setup_challenge.py \
  --manifest manifest.json \
  --binary-name binary_name
```

## Output artifact

`/workspace/playground/artifacts/binary_analysis.json`

`/workspace/playground/artifacts/exploit.py`

`/workspace/playground/artifacts/exploit_report.json`
