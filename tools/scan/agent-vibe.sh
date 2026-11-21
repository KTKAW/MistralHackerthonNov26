#!/bin/sh
# kb-scan agent wrapper (LOCAL full-fidelity mode): run the Vibe CLI with the rendered
# prompt (last argv element) and write the engine's contract file into the per-agent cwd.
#
# The engine scrubs the agent's env by design (Rule of Two). Locally, the key comes from
# ~/.config/mistral-env.sh (chmod 600) sourced HERE, inside the agent sandbox only —
# the engine process itself never holds it.
for last; do :; done
prompt="$last"
[ -f "$HOME/.config/mistral-env.sh" ] && . "$HOME/.config/mistral-env.sh"
out=$(vibe -p "$prompt" 2>/dev/null | head -c 4000)
safe=$(printf '%s' "$out" | tr '\n' ' ' | sed 's/\\/\\\\/g; s/"/\\"/g' | head -c 600)
case "$prompt" in
  *"Explore task"*)
    printf '{"schema":"kb-scan-leads/1","leads":[{"query":"explore","summary":"%s","urls":[],"status":"unverified"}]}\n' "$safe" > results.json
    ;;
  *"Verify task"*)
    printf '{"schema":"kb-scan-verdicts/1","verdicts":[{"subject":"verify","status":"unverified","detail":"%s","sources":[]}]}\n' "$safe" > verdicts.json
    ;;
  *)
    printf '{"schema":"kb-scan-leads/1","leads":[]}\n' > results.json
    ;;
esac
