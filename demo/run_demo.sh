#!/usr/bin/env bash
# Start both agents on 127.0.0.1, run the scenario, print PASS/FAIL, stop the agents.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] || { echo "missing venv: python3 -m venv .venv && .venv/bin/pip install -e .[test]"; exit 2; }
OUT="${OUT:-$ROOT/demo-out}"
mkdir -p "$OUT"
LLM_FLAG=""; [ "${1:-}" = "--llm" ] && LLM_FLAG="--llm"

export PYTHONPATH="$ROOT"
"$PY" -m demo.analyst --port 9602 $LLM_FLAG >"$OUT/analyst.log" 2>&1 &
A_PID=$!
"$PY" -m demo.planner --port 9601 >"$OUT/planner.log" 2>&1 &
P_PID=$!
cleanup() { kill "$A_PID" "$P_PID" 2>/dev/null; wait "$A_PID" "$P_PID" 2>/dev/null; }
trap cleanup EXIT INT TERM

wait_card() { for _ in $(seq 1 100); do curl -sf "http://127.0.0.1:$1/.well-known/agent-card.json" >/dev/null && return 0; sleep 0.1; done; echo "agent on $1 did not start"; cat "$OUT"/*.log; return 1; }
wait_card 9602 || exit 1
wait_card 9601 || exit 1
echo "agents up: analyst :9602, planner :9601"

"$PY" -m demo.scenario --out "$OUT"
RC=$?
echo "exit $RC ($([ $RC -eq 0 ] && echo PASS || echo FAIL))"
exit $RC
