#!/bin/sh
# Stub agent for kb-scan tests — NEVER a real model call, never a real secret.
# The substituted prompt is the last argv element. Depending on which prompt
# file it came from, write a canned results.json (explore) or verdicts.json
# (verify) into the current working directory (the per-agent dir).
for last; do :; done
prompt="$last"
id=$(printf '%s\n' "$prompt" | sed -n 's/^[-* ]*Task id:[[:space:]]*//p' | head -n 1)
[ -z "$id" ] && id="stub-unknown"
# record whether a (fake) secret leaked into the scrubbed env
printf '%s' "${KB_SCAN_TEST_SECRET:-}" > env.txt
# the engine passes the rendered prompt TEXT as the final argv element
case "$prompt" in
  *"Explore task"*)
    cat > results.json <<EOF
{"schema": "kb-scan-leads/1", "leads": [{"query": "stub query", "summary": "stub lead from $id", "urls": [{"url": "https://example.invalid/x", "read": "via-snippet"}], "status": "unverified"}]}
EOF
    ;;
  *"Verify task"*)
    cat > verdicts.json <<EOF
{"schema": "kb-scan-verdicts/1", "verdicts": [{"id": "$id", "status": "confirmed", "sources": [{"url": "https://example.invalid/v", "read": "full"}]}]}
EOF
    ;;
  *)
    echo "stub: unknown prompt" >&2
    exit 1
    ;;
esac
exit 0
