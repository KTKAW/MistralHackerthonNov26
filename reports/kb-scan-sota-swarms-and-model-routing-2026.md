# State of the art 2026: swarm protocols, orchestration, per-agent LLMs (searched 2026-11-21 via connector_web_search)

All items below are via-snippet leads from Brave search results, not verified facts — treat as leads per this KB's read-level rules.

## Protocols: two layers survive in 2026
- **MCP** (Anthropic, 2024): agent ↔ tools/context. The standard for tool access. Harness: `mcp_<server>_<tool>`; connectors (`connector_*`) are the provider-hosted, auto-discovered equivalent.
- **A2A / Agent2Agent** (Google → Linux Foundation since June 2025; stable spec, 150+ orgs by 2026): agent ↔ agent. Agent Cards for discovery, JSON-RPC task lifecycle, SSE streaming for long-running tasks, OAuth. Use when independent agents from different vendors/owners must collaborate. linuxfoundation.org press; research.google/pubs A2A.
- **ACP** (IBM/Zed, REST-based) **merged into A2A in August 2025** — so effectively: MCP for tools, A2A for agents. ANP also exists. (betterclaw.io, getmaxim.ai, k21academy comparisons)

## Orchestration patterns for information gathering
- **Orchestrator-worker (supervisor) dominates production** (~70% of 2026 multi-agent deployments per one analysis): LangGraph (explicit graphs, durable execution), CrewAI (role crews), AutoGen (conversation-driven), OpenAI Agents SDK (handoffs), Anthropic lead-agent.
- **Anthropic multi-agent research system**: lead agent (Opus 4) decomposes, subagents (Sonnet 4) search in parallel in their own context windows and return condensed findings; separate citation agent; 90.2% better on BrowseComp; token spend explains ~80% of variance. Lesson: give each subagent an objective, output format, tools, source limits. anthropic.com/engineering/multi-agent-research-system
- **Swarm/peer handoff** when searching across approaches and resilience > coherence; avoid when agents must agree on a shared mutation. **ArcticSwarm** (arxiv 2609.01870) defers early consensus for long-horizon research.

## Varying LLMs per agent (heterogeneous swarms)
- Model routing is now critical infra; routers in 2026: RouteLLM (Berkeley, open), LiteLLM, Portkey, OpenRouter Auto Router, vLLM Semantic Router, Not Diamond, Martian, Cloudflare AI Gateway. Strategies: semantic routing, cascade (small→large on low confidence), fallback, cost-quality. Reported savings 40–85%.
- Pattern that wins: cheap/small model for triage, classification, filtering, polling summaries; frontier model for reasoning and synthesis (Anthropic's Opus-lead/Sonnet-subagents is the reference design).

## Sandbox per agent
- "One sandbox per agent in a swarm" (PandaStack 2026): a shared environment breaks once N agents write/run concurrently. Providers: E2B, Modal, Cloudflare Sandboxes, Vercel, Northflank; microVMs (gVisor, Firecracker); process isolation (bwrap) for lighter cases. NVIDIA/Wiz/IBM documented 2025–26 that agents can escape sandboxes → defense in depth (also our repo's system.md: both shell AND file-path walls needed).

## Mapping to this harness (Vibe) and to kb-scan
- Swarm launch is native: `agents.spawn` with `config_name` from `~/.vibe/agents/*.toml`; a custom subagent profile can pin its **own `active_model`** → per-agent LLM variation is built in (profiles like `poller-small.toml` vs `coordinator-large.toml`). Generic children (what we spawned) inherit the parent model unless given a profile.
- Per-agent cron (each agent owns its own schedules), inherited hooks, per-subagent tool narrowing.
- kb-scan's shard design = deterministic poller swarm (Rust processes, no LLM); LLM swarm sits on top for triage/research. Report JSON (`kb-scan-report/1`) is our in-repo A2A-style interchange; verdict.schema.json on build/base is the existing cross-component contract.
