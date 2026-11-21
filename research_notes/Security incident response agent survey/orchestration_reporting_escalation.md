# Orchestration, reporting, prioritization and escalation tooling for a security incident response agent ("react, report, escalate")

Method note: every GitHub repo below was verified on 2026-11-21 with `gh api repos/OWNER/REPO` (stars, `pushed_at`, `license.spdx_id`, `archived`). "Stale" means no push in 12+ months (last push before 2025-11-21). Where GitHub returned `NOASSERTION` or `null`, the LICENSE file was read and the real license is given in brackets. Repos that redirected (renamed or transferred) are listed under their new name. Stage codes used throughout: S1 ingest, S2 exposure check, S3 react/mitigate, S4 patch, S5 report, S6 escalate.

## 1. SOAR and security automation platforms (AI-native first): LLM or agent features, MCP support, vulnerability-response playbooks

### Takeaway
Tracecat is the strongest open-source fit for an AI incident-response agent. It is AGPL-3.0, pushed today, and ships agents, an MCP client, its own MCP server, case management and human approval of sensitive tool calls. Shuffle (AGPL-3.0) now has an LLM and agent layer that can use Mistral or local models. StackStorm is mature but has no LLM features. SOARCA is the reference open-source CACAO v2 executor, but it is small and built for research. Keep (alert management and AIOps) keeps its best AI feature, AI correlation, out of the open-source edition. n8n has an MCP Client node and 283 SecOps templates, but its license is fair-code, not open source. I found no ready-made CVE or KEV response playbook in any of these repos.

### Cited Findings

Verified repo metadata (2026-11-21):

| Repo | Lang | License | Stars | Last push | Status |
|---|---|---|---|---|---|
| [TracecatHQ/tracecat](https://github.com/TracecatHQ/tracecat) | Python | AGPL-3.0 | 3,908 | 2026-11-21 | active |
| [Shuffle/Shuffle](https://github.com/Shuffle/Shuffle) | JavaScript | AGPL-3.0 | 2,487 | 2026-11-18 | active |
| [Shuffle/shuffle-docs](https://github.com/Shuffle/shuffle-docs) | - | MIT | 22 | 2026-11-19 | active |
| [Shuffle/workflows](https://github.com/Shuffle/workflows) (linked as shuffle-workflows) | - | MIT | 25 | 2022-10-26 | STALE |
| [StackStorm/st2](https://github.com/StackStorm/st2) | Python | Apache-2.0 | 6,566 | 2026-11-20 | active |
| [COSSAS/SOARCA](https://github.com/COSSAS/SOARCA) | Go | Apache-2.0 | 108 | 2026-11-05 | active |
| [COSSAS/SOARCA-GUI](https://github.com/COSSAS/SOARCA-GUI) | TypeScript | Apache-2.0 | 8 | 2026-11-16 | active |
| [oasis-tcs/cacao](https://github.com/oasis-tcs/cacao) (CACAO TC repo) | - | NOASSERTION (OASIS TC terms) | 39 | 2024-01-16 | STALE |
| [oasis-open/cacao-json-schemas](https://github.com/oasis-open/cacao-json-schemas) | - | Apache-2.0 | 4 | 2024-08-08 | STALE |
| [cyentific-rni/cacao-roaster](https://github.com/cyentific-rni/cacao-roaster) (CACAO playbook editor) | TypeScript | NOASSERTION (OASIS Open Project license) | 1 | 2026-10-18 | active, tiny |
| [Orestistsira/cacao-knowledge-base](https://github.com/Orestistsira/cacao-knowledge-base) | Python | Apache-2.0 | 3 | 2025-10-09 | STALE |
| [keephq/keep](https://github.com/keephq/keep) | Python | NOASSERTION (MIT outside `ee/`; `ee/` separate) | 12,544 | 2026-11-20 | active |
| [n8n-io/n8n](https://github.com/n8n-io/n8n) | TypeScript | NOASSERTION (Sustainable Use License; `.ee` files need an n8n Enterprise License) | 211,573 | 2026-11-21 | active |
| [Zie619/n8n-workflows](https://github.com/Zie619/n8n-workflows) | Python | MIT | 57,292 | 2026-06-24 | active |
| [demisto/content](https://github.com/demisto/content) (content for the closed Cortex XSOAR) | Python | MIT | 1,324 | 2026-11-20 | active |
| [phantomcyber/playbooks](https://github.com/phantomcyber/playbooks) (content for the closed Splunk SOAR) | Python | Apache-2.0 | 561 | 2026-10-30 | active |
| [Patrowl/PatrowlManager](https://github.com/Patrowl/PatrowlManager) | HTML | AGPL-3.0 | 640 | 2026-11-17 | active |
| [twilio-labs/socless](https://github.com/twilio-labs/socless) | Python | Apache-2.0 | 141 | 2026-04-15 | active (low activity) |
| [nsacyber/WALKOFF](https://github.com/nsacyber/WALKOFF) | Python | NOASSERTION | 1,238 | 2022-12-12 | ARCHIVED |

Capabilities:

- **Tracecat** (S1, S3, S5, S6). The README calls it "the open source security automation platform for teams and AI agents". Features: agents built from prompts, tools, MCP, subagents and skills; case management with agent-written verdicts, timelines, IoCs and evidence; workflow DAGs; a Tracecat MCP server that Claude Code, Codex and Copilot can drive; an MCP client that connects agents to any remote (HTTP/OAuth) or local (`npx`/`uvx`) MCP server; "100+ pre-built connectors and 50+ hosted MCP servers"; `nsjail` sandboxes for untrusted code and agents; RBAC, ABAC and OAuth2.0 scopes "for humans and agents"; "Human-in-the-loop: review and approve sensitive tools calls from a unified inbox, Slack, or email"; workspaces kept in Git version control — [Tracecat README](https://github.com/TracecatHQ/tracecat#readme). The LICENSE file is plain AGPL-3.0 — [LICENSE](https://github.com/TracecatHQ/tracecat/blob/main/LICENSE).
- **Shuffle** (S1, S3, S6). The README describes "an open source automation platform, built for and by the security professionals" with an OpenAPI-based app creator and ready-made apps for security tools — [Shuffle README](https://github.com/Shuffle/Shuffle#readme). LLM and agent layer: "all LLM-related functionality passes through the RunAiQuery() function"; agents; an OpenAI-compatible `POST /api/v1/chat/completions`; on-prem installs can use Ollama, vLLM or LM Studio, including fully air-gapped; cloud providers include Google Gemini, OpenAI, Anthropic, **Mistral**, Groq, DeepSeek, Together AI and OpenRouter; the docs page also embeds an "mcp-setup" component — [Shuffle docs/AI.md](https://github.com/Shuffle/shuffle-docs/blob/master/docs/AI.md). The frontend code includes `AgentUI.jsx` and `AgentChatWidget.jsx` — [Shuffle repo tree](https://github.com/Shuffle/Shuffle). Shuffle Cloud runs its AI features on "Shuffle AI credits" — [Shuffle docs/AI.md](https://github.com/Shuffle/shuffle-docs/blob/master/docs/AI.md).
- **StackStorm** (S1, S3, S6). StackStorm is event-driven automation ("IFTTT for Ops") built from sensors, triggers, actions and rules, with "160 integration packs with 6000+ actions" and ChatOps. Its README gives an auto-remediation example that freezes the workflow and calls PagerDuty when something goes wrong — [st2 README](https://github.com/StackStorm/st2#readme). The repo ships a `core.ask` action and "inquiry" example workflows — [contrib/core/actions/ask.yaml](https://github.com/StackStorm/st2/blob/master/contrib/core/actions/ask.yaml). The README does not mention LLM or MCP features, and its badge still lists Python 3.6/3.8 — [st2 README](https://github.com/StackStorm/st2#readme).
- **SOARCA** (CACAO executor; S3). SOARCA "can ingest, validate and execute CACAOv2 security playbooks", which arrive through a JSON API along with their triggers. It has native http(s), SSH and OpenC2 capabilities. It "was developed for research and innovation purposes", currently runs playbooks sequentially, and has only machine and command-line interfaces, with a GUI planned — [SOARCA README](https://github.com/COSSAS/SOARCA#readme). It is extended through the "FIN" protocol with a Python library (an MQTT broker deployment is included), and ships an API reporter plus example OpenC2 and FIN playbooks — [SOARCA repo tree / docs](https://github.com/COSSAS/SOARCA/tree/development/docs/content/en/docs). It has no LLM features.
- **Other CACAO tooling**: OASIS publishes JSON validation schemas for CACAO playbooks (stale since 2024-08) — [cacao-json-schemas](https://github.com/oasis-open/cacao-json-schemas). There is a CACAO playbook editor (cacao-roaster, 1 star) — [cacao-roaster](https://github.com/cyentific-rni/cacao-roaster) — and a knowledge base that stores, retrieves and executes CACAO playbooks (3 stars, stale) — [cacao-knowledge-base](https://github.com/Orestistsira/cacao-knowledge-base).
- **Keep** (S1, S6). Keep calls itself "the open-source AIOps and alert management platform". Its README lists Anthropic and OpenAI as "AI Backends for Enrichments, Correlations and Incident Context Gathering" — [Keep README](https://github.com/keephq/keep#readme). Which AI features are in the open-source edition: AI Correlation is "Keep Open Source: ⛔️" (Cloud and Enterprise only) — [ai-correlation.mdx](https://github.com/keephq/keep/blob/main/docs/overview/ai-correlation.mdx); the AI Incident Assistant is "(experimental)" in OSS — [ai-incident-assistant.mdx](https://github.com/keephq/keep/blob/main/docs/overview/ai-incident-assistant.mdx); AI in Workflows (third-party AI providers as workflow steps and actions) is available in OSS — [ai-in-workflows.mdx](https://github.com/keephq/keep/blob/main/docs/overview/ai-in-workflows.mdx). I found no MCP code in the repo tree — [keep repo](https://github.com/keephq/keep). License: everything outside `ee/` is MIT — [Keep LICENSE](https://github.com/keephq/keep/blob/main/LICENSE).
- **n8n** (S1, S6). The repo describes it as "Fair-code workflow automation platform with native AI capabilities ... 400+ integrations" — [n8n repo](https://github.com/n8n-io/n8n). It is distributed under the Sustainable Use License, and `.ee` files need an n8n Enterprise License — [n8n LICENSE.md](https://github.com/n8n-io/n8n/blob/master/LICENSE.md). An MCP Client node ships in `@n8n/nodes-langchain` — [McpClient node](https://github.com/n8n-io/n8n/tree/master/packages/%40n8n/nodes-langchain/nodes/mcp/McpClient). The SecOps template category lists 283 templates. The visible ones include "Automate Security Alert Triage with NixGuard AI and Route to Slack or Jira", and none of the visible ones is a CVE-alert template — [n8n SecOps templates](https://n8n.io/workflows/categories/secops/). A community dump of n8n workflows has 57,292 stars — [Zie619/n8n-workflows](https://github.com/Zie619/n8n-workflows).
- **Playbook content for closed platforms**: demisto/content is the open (MIT) content repository for Cortex XSOAR (closed) — [demisto/content](https://github.com/demisto/content). Phantom Community Playbooks are for Splunk SOAR (closed) — [phantomcyber/playbooks](https://github.com/phantomcyber/playbooks).
- **PatrOwl** describes itself as an "Open Source, Smart and Scalable Security Operations Orchestration Platform" (AGPL-3.0) — [PatrowlManager](https://github.com/Patrowl/PatrowlManager). **SOCless** is "The SOCless automation framework" (serverless) — [socless](https://github.com/twilio-labs/socless). **WALKOFF** (NSA) is archived — [WALKOFF](https://github.com/nsacyber/WALKOFF).

### Inferences
- Tracecat is the best fit for a hackathon "react + escalate" backbone. It already has the three pieces an IR agent needs (cases, agent tool-calling through MCP, approval gates) and runs self-hosted under AGPL. An AGPL backend is fine for a hackathon demo, but a team that modifies it and offers it as a network service must publish its changes.
- Shuffle is the easiest way to get a Mistral-backed agent inside a SOAR, because Mistral is a first-class provider and it exposes an OpenAI-compatible endpoint. Its workflow repo has not been updated since 2022, so the team would have to write its own playbooks.
- SOARCA plus CACAO is attractive for a standards story: the LLM drafts a CACAO v2 playbook, it is checked against the OASIS JSON schemas, and SOARCA executes it. It is research-grade, and most CACAO tooling has one to a few dozen stars.
- StackStorm is a reasonable deterministic executor if the team wants the LLM to only *choose* among pre-approved actions. Its `core.ask` inquiry mechanism would provide the human gate. This reading of `core.ask` comes from file names and the standard StackStorm design; I did not open the docs.
- n8n is quick for glue (webhook in, Slack or Jira out). Its Sustainable Use License is not an OSI open-source license, which matters only if the project is redistributed commercially.

### Gaps
- I did not find documented, ready-made CVE, KEV or supply-chain response playbooks in Tracecat, Shuffle, SOARCA or Keep. The visible n8n SecOps templates had none named for CVE alerts. demisto/content probably contains vulnerability-management packs, but I did not open them.
- The current OASIS status of CACAO v2.0 (Committee Specification vs OASIS Standard) was not verified in this pass. The TC repo has not been pushed since 2024-01-16.
- Shuffle's MCP support is only implied by an "mcp-setup" docs component. I did not confirm which MCP role (client or server) Shuffle implements, or whether it is cloud-only.

## 2. Incident management and on-call escalation: declaring incidents, paging, ticketing, SLA tracking

### Takeaway
Two of the named open-source incident tools are effectively gone. Netflix Dispatch was archived read-only on 2025-09-01. Grafana OnCall OSS went into maintenance on 2025-03-11 and was archived on 2026-03-24, and its repo moved to `grafana-cold-storage`. PagerDuty's open-source local MCP server repo is also archived, in favour of the hosted remote MCP at `mcp.pagerduty.com/mcp`. Opsgenie shuts down on 2027-04-05. For self-hosted paging, GoAlert (Apache-2.0, active) is the best open-source option. It has a trivial generic HTTP API (`summary`, `details`, `dedup`, `action=close`) and rule-based Universal Integration Keys. OneUptime adds on-call, status pages and an MCP endpoint. For tickets and chat, the official hosted Atlassian MCP (GA) and Slack MCP (`mcp.slack.com/mcp`) are the cleanest paths. Open-source alternatives are sooperset/mcp-atlassian (98 tools) and korotovsky/slack-mcp-server, where message posting is off by default.

### Cited Findings

Verified repo metadata (2026-11-21):

| Repo | Lang | License | Stars | Last push | Status |
|---|---|---|---|---|---|
| [Netflix/dispatch](https://github.com/Netflix/dispatch) | Python | Apache-2.0 | 6,482 | 2025-09-03 | ARCHIVED |
| [grafana/oncall](https://github.com/grafana-cold-storage/oncall) (now grafana-cold-storage/oncall) | Python | AGPL-3.0 | 3,879 | 2026-03-24 | ARCHIVED |
| [target/goalert](https://github.com/target/goalert) | Go | Apache-2.0 | 2,882 | 2026-11-20 | active |
| [amitray007/goalert-mcp](https://github.com/amitray007/goalert-mcp) | TypeScript | MIT | 2 | 2026-06-03 | community, tiny |
| [OneUptime/oneuptime](https://github.com/OneUptime/oneuptime) | TypeScript | NOASSERTION (Apache-2.0 outside `ee/`; `ee/` under OneUptime Enterprise License) | 7,834 | 2026-11-21 | active |
| [linkedin/oncall](https://github.com/linkedin/oncall) | Python | BSD-2-Clause | 1,258 | 2025-08-20 | STALE |
| [linkedin/iris](https://github.com/linkedin/iris) | Python | BSD-2-Clause | 844 | 2025-06-12 | STALE |
| [incidentbot/incidentbot](https://github.com/incidentbot/incidentbot) (formerly echoboomer/incident-bot) | Python | MIT | 166 | 2026-09-19 | active |
| [monzo/response](https://github.com/monzo/response) | JavaScript | MIT | 1,557 | 2024-03-20 | STALE |
| [VersusControl/versus-incident](https://github.com/VersusControl/versus-incident) | Go | MIT | 963 | 2026-11-21 | active |
| [caronc/apprise](https://github.com/caronc/apprise) | Python | BSD-2-Clause | 17,803 | 2026-11-21 | active |
| [binwiederhier/ntfy](https://github.com/binwiederhier/ntfy) | Go | Apache-2.0 | 35,671 | 2026-11-20 | active |
| [PagerDuty/pagerduty-mcp-server](https://github.com/PagerDuty/pagerduty-mcp-server) | Python | Apache-2.0 | 79 | 2026-09-04 | ARCHIVED (deprecated) |
| [wpfleger96/pagerduty-mcp-server](https://github.com/wpfleger96/pagerduty-mcp-server) | Python | MIT | 8 | 2026-11-20 | community |
| [PagerDuty/go-pagerduty](https://github.com/PagerDuty/go-pagerduty) | Go | Apache-2.0 | 309 | 2026-07-07 | active |
| [PagerDuty/python-pagerduty](https://github.com/PagerDuty/python-pagerduty) | Python | MIT | 19 | 2026-11-12 | active |
| [PagerDuty/pdpyras](https://github.com/PagerDuty/pdpyras) | Python | MIT | 133 | 2025-06-03 | ARCHIVED |
| [rootlyhq/rootly-mcp-server](https://github.com/rootlyhq/rootly-mcp-server) (formerly Rootly-AI-Labs/Rootly-MCP-server; for the closed Rootly SaaS) | Python | Apache-2.0 | 45 | 2026-11-20 | active |
| [atlassian/atlassian-mcp-server](https://github.com/atlassian/atlassian-mcp-server) (docs and plugins for the hosted server) | Python | Apache-2.0 | 1,184 | 2026-11-19 | active |
| [sooperset/mcp-atlassian](https://github.com/sooperset/mcp-atlassian) | Python | MIT | 6,140 | 2026-11-20 | active |
| [korotovsky/slack-mcp-server](https://github.com/korotovsky/slack-mcp-server) | Go | MIT | 1,900 | 2026-07-16 | active |
| [ubie-oss/slack-mcp-server](https://github.com/ubie-oss/slack-mcp-server) | TypeScript | Apache-2.0 | 109 | 2026-11-15 | active |
| [slackapi/slack-skills-plugin](https://github.com/slackapi/slack-skills-plugin) (wires up Slack's hosted MCP) | Python | MIT | 172 | 2026-11-18 | active |
| [slackapi/python-slack-sdk](https://github.com/slackapi/python-slack-sdk) | Python | MIT | 4,018 | 2026-11-20 | active |
| [modelcontextprotocol/servers-archived](https://github.com/modelcontextprotocol/servers-archived) (old reference Slack server) | JavaScript | MIT | 307 | 2025-05-28 | ARCHIVED |
| [github/github-mcp-server](https://github.com/github/github-mcp-server) | Go | MIT | 34,636 | 2026-11-21 | active |
| [grafana/mcp-grafana](https://github.com/grafana/mcp-grafana) | Go | Apache-2.0 | 3,690 | 2026-11-21 | active |

Status changes:
- Dispatch: "This repository will be archived and marked as read-only on September 1, 2025 ... We encourage users to fork the repository if they wish to continue development independently" — [Dispatch README](https://github.com/Netflix/dispatch#readme). The archived code still contains a GenAI module with `generate_incident_summary`, `generate_read_in_summary`, `generate_tactical_report`, `generate_case_signal_summary` and `get_tag_recommendations` — [dispatch/ai/service.py](https://github.com/Netflix/dispatch/blob/main/src/dispatch/ai/service.py).
- Grafana OnCall: "On 2025-03-11 Grafana OnCall (OSS) entered maintenance mode and was archived on 2026-03-24". The README points users to Grafana Cloud IRM, which is closed and commercial — [OnCall README](https://github.com/grafana-cold-storage/oncall#readme).
- PagerDuty MCP: "This repository is deprecated and now read-only. Development has moved to PagerDuty's hosted Remote MCP Server" — [pagerduty-mcp-server README](https://github.com/PagerDuty/pagerduty-mcp-server#readme). The hosted endpoint is `https://mcp.pagerduty.com/mcp` (EU: `https://mcp.eu.pagerduty.com/mcp`) — [PagerDuty MCP integration guide](https://support.pagerduty.com/main/docs/pagerduty-mcp-server-integration-guide). Search summaries of the PyPI page say the local package exposes only read-only tools unless started with `--enable-write-tools`, while the hosted server exposes read and write tools by default. Treat this as secondhand: I did not open the page itself — [pagerduty-mcp on PyPI](https://pypi.org/project/pagerduty-mcp). Third-party listings put the hosted tool count at 40 to 60+, covering incidents, on-call, escalation policies, event orchestration and status pages, so the count is unconfirmed — [DEV Community overview](https://dev.to/grove_chatforest/pagerduty-mcp-server-60-tools-for-ai-powered-incident-management-4ea5).
- Opsgenie: new sales ended June 4, 2025. Customers can keep using it until April 5, 2027, when access is shut off and unmigrated data is deleted. The migration paths lead to Jira Service Management or Compass — [Atlassian Opsgenie migration](https://www.atlassian.com/software/opsgenie/migration); [Atlassian announcement](https://www.atlassian.com/blog/announcements/evolution-of-it-operations).
- PagerDuty's `pdpyras` Python client is archived. The active PagerDuty Python client repo is `python-pagerduty` — [pdpyras](https://github.com/PagerDuty/pdpyras); [python-pagerduty](https://github.com/PagerDuty/python-pagerduty).
- monzo/response (last push 2024-03), linkedin/oncall (2025-08) and linkedin/iris (2025-06) are stale — repo metadata above.

Capabilities and interfaces:
- **GoAlert**: "on-call scheduling, automated escalations and notifications (like SMS or voice calls)". It ships as a single binary or Docker image, and `goalert/demo` is a demo container for integration testing — [GoAlert README](https://github.com/target/goalert#readme). The generic API integration key handler accepts `summary`, `details`, `action` and `dedup` (form fields or JSON), and `action == "close"` closes the alert — [genericapi/handler.go](https://github.com/target/goalert/blob/master/genericapi/handler.go). Universal Integration Keys accept any JSON. Rules written in the Expr language map that JSON to actions, including non-critical messages, and the keys use ECDSA-signed tokens — [universal-integration-keys.md](https://github.com/target/goalert/blob/master/docs/universal-integration-keys.md). Grafana and Prometheus Alertmanager integrations exist in the tree — [GoAlert repo](https://github.com/target/goalert). There is a community MCP server for schedules, alerts and escalation policies (2 stars) — [goalert-mcp](https://github.com/amitray007/goalert-mcp).
- **OneUptime**: monitoring plus "Incidents and on-call: ... Page whoever is on call by phone, SMS, email, push, Slack or Microsoft Teams, and escalate until someone responds". It also has workflows connecting Jira and ServiceNow, an API, CLI and Terraform provider, and an MCP server at `https://oneuptime.com/mcp` — [OneUptime README](https://github.com/OneUptime/oneuptime#readme).
- **incidentbot**: an incident bot for Slack or Matrix with customizable status, severity and role definitions and an incident digest channel. It integrates with Confluence, Jira, GitLab, Statuspage, PagerDuty, Zoom and Phare, and can "Automatically build a postmortem document base" — [incidentbot README](https://github.com/incidentbot/incidentbot#readme).
- **Versus Incident**: a self-hosted "AI SRE agent" that learns normal log patterns. It also takes webhook alerts, formats them with templates, fans them out to Slack or Teams, and escalates to on-call through AWS Incident Manager, PagerDuty, ServiceNow or incident.io when no one acknowledges. Metrics and traces sources are Enterprise-only — [Versus README](https://github.com/VersusControl/versus-incident#readme).
- **Notification fan-out**: Apprise ("Push Notifications that work with just about every platform") — [apprise](https://github.com/caronc/apprise); ntfy ("Send push notifications to your phone or desktop using PUT/POST") — [ntfy](https://github.com/binwiederhier/ntfy).
- **PagerDuty Events API v2**: alert events create incidents assigned to whoever is on call. Change events carry non-problem context (for example a merged PR) and do not notify anyone. The required fields are `summary`, `source` and `severity` (`info`, `warning`, `error` or `critical`), and the `routing_key` is the service integration key — [PagerDuty Events API v2 overview](https://docs.pagerduty.com/developer/events-api-v2-overview). The endpoint constant is `https://events.pagerduty.com/v2/enqueue`, and the event struct has `event_action` and `dedup_key` — [go-pagerduty event_v2.go](https://github.com/PagerDuty/go-pagerduty).
- **Atlassian (Jira/JSM)**: the official server is "a cloud-hosted bridge" to Jira, Confluence, Jira Service Management, Bitbucket, Compass and Loom. Its status badge reads "Generally Available", it authenticates with OAuth 2.1 or an API token, and new setups should use `https://mcp.atlassian.com/v2/mcp` — [atlassian-mcp-server README](https://github.com/atlassian/atlassian-mcp-server#readme). The community server sooperset/mcp-atlassian has "98 tools total", including `jira_create_issue`, `jira_transition_issue` and `confluence_create_page`, with API token, PAT or OAuth 2.0 auth — [mcp-atlassian README](https://github.com/sooperset/mcp-atlassian#readme).
- **Slack**: the official hosted MCP is at `https://mcp.slack.com/mcp` (JSON-RPC 2.0 over Streamable HTTP) and uses confidential OAuth. Its tools search messages, files, users and channels; send, schedule and draft messages; and create canvases and lists. "Only apps published in the Slack Marketplace and internal apps can use MCP at this time", and admins must approve — [Slack MCP server docs](https://docs.slack.dev/ai/mcp-server/). In korotovsky/slack-mcp-server, "Posting messages is disabled by default for safety". Setting `SLACK_MCP_ADD_MESSAGE_TOOL` enables it, optionally for a channel allowlist. The server also has a "stealth" mode that uses browser session tokens — [korotovsky README](https://github.com/korotovsky/slack-mcp-server#readme).
- **GitHub as the ticket system**: GitHub's official MCP server has toolsets including `issues`, `actions`, `code_security` and `dependabot` — [github-mcp-server README](https://github.com/github/github-mcp-server#readme).
- **Closed tools (context only)**: Grafana Cloud IRM, PagerDuty and Rootly are closed SaaS. Rootly publishes an Apache-2.0 MCP server for its SaaS — [rootly-mcp-server](https://github.com/rootlyhq/rootly-mcp-server).

### Inferences
- How the agent would declare, page, ticket and track an SLA through these tools:
  1. **Declare and page**: send a PagerDuty Events v2 `trigger` with `dedup_key` set to a stable key such as `vuln:<CVE>:<service>`, so repeated signals fold into one incident. Map `severity=critical` to SSVC Act. Send `resolve` with the same key once the patch is verified. The self-hosted equivalent is GoAlert's generic endpoint with the same `dedup` value, then `action=close`.
  2. **Ticket**: call `createJiraIssue` on the Atlassian hosted MCP, `jira_create_issue` on sooperset, or a GitHub issue through github-mcp-server. Alternatively write the finding into DefectDojo or SecObserve and let their built-in Jira sync create and close the issue (section 3).
  3. **Chat**: post a summary to a fixed channel through the Slack MCP, using an allowlist so the agent can only post to `#sec-incidents`.
  4. **SLA**: store the due date on the ticket, taken from the KEV `dueDate` or the team's SSVC-to-days mapping (section 6). DefectDojo can track SLA breach per severity.
- For a hackathon demo, the lowest-friction stack is the PagerDuty free or developer account through the Events API (one HTTPS POST), the Slack hosted MCP or an incoming webhook, and GitHub Issues through github-mcp-server. Use GoAlert (`docker run goalert/demo`) only if everything must be self-hosted.
- Avoid building on Dispatch, Grafana OnCall OSS, Opsgenie or the local PagerDuty MCP repo. All four are archived or end-of-life. Dispatch's archived `ai/service.py` is still worth reading as a reference design for LLM-generated incident summaries and tactical reports.

### Gaps
- I did not verify the exact PagerDuty hosted MCP tool list or whether it requires OAuth or a user API token. Secondary sources conflict on both.
- I could not confirm whether Slack's hosted MCP needs a paid plan. The docs only state the Marketplace or internal-app restriction.
- I found no open-source tool that natively tracks vulnerability-remediation SLAs *and* pages. The SLA logic lives in vulnerability-management tools (DefectDojo) and paging lives elsewhere.

## 3. Vulnerability management and ASPM platforms: deduplication, SLA tracking, Jira sync, APIs an agent can write findings to

### Takeaway
DefectDojo (BSD-3-Clause, 5,262 stars) is still the default open-source findings hub. It does same-tool, cross-tool and reimport deduplication, tracks per-asset SLAs by severity with breach notifications, pushes to Jira with optional bidirectional webhook sync, and has REST API v2 and experimental outbound webhooks. Since 2026 it also has an official MCP server. SecObserve (BSD-style, 340 stars) is the most VEX-native option. It exports and imports VEX in CSAF, CycloneDX and OpenVEX, syncs issues one way to GitHub, GitLab or Jira, enriches findings nightly with EPSS and exploit data (KEV, Exploit-DB, Metasploit, Nuclei, PoC-in-GitHub, VulnCheck KEV), and has a Rego rule engine. Faraday is pentest-oriented. ArcherySec is stale. OpenCVE is source-available (BSL 1.1), not open source.

### Cited Findings

Verified repo metadata (2026-11-21):

| Repo | Lang | License | Stars | Last push | Status |
|---|---|---|---|---|---|
| [DefectDojo/django-DefectDojo](https://github.com/DefectDojo/django-DefectDojo) | Python | BSD-3-Clause | 5,262 | 2026-11-21 | active |
| [DefectDojo/defectdojo-mcp](https://github.com/DefectDojo/defectdojo-mcp) | Python | BSD-3-Clause | 3 | 2026-11-20 | active, official, new |
| [SecObserve/SecObserve](https://github.com/SecObserve/SecObserve) (formerly MaibornWolff/SecObserve) | Python | NOASSERTION (BSD-style text) | 340 | 2026-11-21 | active |
| [nh4ttruong/secobserve-mcp](https://github.com/nh4ttruong/secobserve-mcp) | Python | MIT | 2 | 2026-11-20 | community |
| [infobyte/faraday](https://github.com/infobyte/faraday) | Python | GPL-3.0 | 6,875 | 2026-10-29 | active |
| [archerysec/archerysec](https://github.com/archerysec/archerysec) | JavaScript | GPL-3.0 | 2,476 | 2025-06-11 | STALE |
| [DependencyTrack/dependency-track](https://github.com/DependencyTrack/dependency-track) | Java | Apache-2.0 | 4,494 | 2026-11-20 | active |
| [secprog/dependency-track-mcp](https://github.com/secprog/dependency-track-mcp) | Python | MIT | 5 | 2026-08-16 | community |
| [mitre/heimdall2](https://github.com/mitre/heimdall2) | HTML | NOASSERTION (Apache-2.0 with MITRE notice) | 295 | 2026-11-21 | active |
| [secureCodeBox/secureCodeBox](https://github.com/secureCodeBox/secureCodeBox) | Go | NOASSERTION (Apache-2.0 text) | 994 | 2026-11-20 | active |
| [opencve/opencve](https://github.com/opencve/opencve) | Python | NOASSERTION (Business Source License 1.1) | 2,973 | 2026-11-16 | active, source-available |
| [gravion-ux/fixqueue](https://github.com/gravion-ux/fixqueue) | JavaScript | MIT | 2 | 2026-11-20 | tiny |

DefectDojo:
- **Deduplication**: later imports of the same vulnerability are marked as duplicates of the earliest-created Finding, which stays the canonical original. Duplicates are set Inactive by default. Scope defaults to the Asset (formerly Product) and can be narrowed to an Engagement; DefectDojo Pro's "Dedupe Pools" widen it across Assets. Reimport compares hash codes and discards matches before same-tool dedup runs. Cross-tool matching algorithms are documented separately — [about_deduplication.md](https://github.com/DefectDojo/django-DefectDojo/blob/dev/docs/content/triage_findings/finding_deduplication/about_deduplication.md).
- **SLA**: each Asset can have an SLA set in days per Finding severity (Risk-based SLAs are Pro-only). The countdown starts when the Finding is created, and breaches are labeled and tracked as negative days. SLA violations "can be configured to trigger Notifications", and a "Mitigated Within SLA" column records the outcome. Allowed values are 0 to 36500 days — [OS__sla_configuration.md](https://github.com/DefectDojo/django-DefectDojo/blob/dev/docs/content/asset_modelling/OS_hierarchy/OS__sla_configuration.md).
- **Jira**: DefectDojo can push Findings to one or more Jira spaces, selectively or all. Bidirectional sync works through a Jira webhook to `https://<dojo>/jira/webhook/<SECRET>`. The integration is off by default — [os__jira_guide.md](https://github.com/DefectDojo/django-DefectDojo/blob/dev/docs/content/connectors/os_jira/os__jira_guide.md).
- **Outbound webhooks**: "This is an experimental Open Source feature". DefectDojo sends HTTP requests on events (ping, product_added, engagement_added, test_added, scan_added) and auto-disables failing endpoints. On the API wire, an Asset is `product` and an Organization is `product_type` — [notification_webhooks.md](https://github.com/DefectDojo/django-DefectDojo/blob/dev/docs/content/automation/api/notification_webhooks.md).
- **APIs**: REST API v2 and client wrappers. The Pro edition (closed) adds a new UI, risk-based vulnerability management and connectors such as ServiceNow — [DefectDojo README](https://github.com/DefectDojo/django-DefectDojo#readme).
- **MCP**: the official server works through REST API v2 with an API v2 key; the PyPI package is `defectdojo-mcp-server`. The README warns that a package named `defectdojo-mcp` "is an unrelated project" — [defectdojo-mcp README](https://github.com/DefectDojo/defectdojo-mcp#readme).

SecObserve:
- **VEX**: exports and imports VEX in CSAF, CycloneDX (ECMA-424) and OpenVEX. The feature sits behind the `FEATURE_VEX` flag. Exports can be scoped by product, vulnerabilities and branches, and document IDs use the form `prefix_year_counter`. CycloneDX VEX is exported as a dedicated BOM with BOM-links — [vex.md](https://github.com/SecObserve/SecObserve/blob/main/docs/integrations/vex.md).
- **Issue trackers**: one-way sync to GitHub, GitLab or Jira. New observations on the default branch become issues; issues close when the observation is assessed or resolved and reopen when the observation reappears. Sync can be limited by minimum severity and labels — [issue_trackers.md](https://github.com/SecObserve/SecObserve/blob/main/docs/integrations/issue_trackers.md).
- **Deduplication**: an asynchronous check flags potential duplicates (same title across components, or same file and line from different scanners), and users then mark them — [duplicates.md](https://github.com/SecObserve/SecObserve/blob/main/docs/usage/duplicates.md).
- **Enrichment**: EPSS score and percentile are imported nightly at 03:00 UTC, and Rego rules can read EPSS to set priority — [epss.md](https://github.com/SecObserve/SecObserve/blob/main/docs/integrations/epss.md). Exploit information comes from CISA KEV, Exploit-DB, Metasploit, Nuclei, PoC-in-GitHub and VulnCheck KEV via the cvss-bt project — [exploit_information.md](https://github.com/SecObserve/SecObserve/blob/main/docs/integrations/exploit_information.md).
- **Other features**: rule-based assessment, security gates, configurable expiry for accepted risks, metrics, and SBOM license management — [features.md](https://github.com/SecObserve/SecObserve/blob/main/docs/getting_started/features.md). An MCP server (community) and a Terraform provider exist — [SecObserve README](https://github.com/SecObserve/SecObserve#readme); [secobserve-mcp](https://github.com/nh4ttruong/secobserve-mcp) ("triage vulnerability findings ... generate VEX documents").
- **Licensing and stewardship**: copyright is held by "MaibornWolff GmbH / Stefan Fleckenstein" for 2023 to November 2025 and by "Stefan Fleckenstein" since December 2025, and the repo was transferred to the SecObserve org — [SecObserve LICENSE](https://github.com/SecObserve/SecObserve/blob/main/LICENSE.txt).

Others:
- **Faraday**: its description now reads "Open-source and AI-powered cybersecurity tools for offensive security, vulnerability management, and autonomous pentesting" — [faraday repo](https://github.com/infobyte/faraday). The README documents an Agents Dispatcher (runs scanners remotely) and an API at api.faradaysec.com, but no LLM feature — [Faraday README](https://github.com/infobyte/faraday#readme).
- **Dependency-Track**: SBOM-based "intelligent Component Analysis platform" — [dependency-track](https://github.com/DependencyTrack/dependency-track). Its docs tree includes triage analysis states, suppression, notifications, a DefectDojo integration and the REST API — [docs/_docs](https://github.com/DependencyTrack/dependency-track/tree/master/docs/_docs). Community MCP servers exist; the most-starred is self-described as "Vibe Coded" — [secprog/dependency-track-mcp](https://github.com/secprog/dependency-track-mcp).
- **OpenCVE** is a "Vulnerability Intelligence Platform" under BSL 1.1 — [opencve LICENSE](https://github.com/opencve/opencve/blob/master/LICENSE). **Heimdall2** views, stores and compares security scan results — [heimdall2](https://github.com/mitre/heimdall2). **fixqueue** merges SARIF, Trivy, Grype and OSV output into "one deduplicated, EPSS/KEV-prioritized fix queue" (2 stars) — [fixqueue](https://github.com/gravion-ux/fixqueue).

### Inferences
- For the agent's "report" and "log a VEX statement" paths, SecObserve is the most directly useful. It already stores per-finding assessments with VEX justifications and emits all three VEX formats. The agent could post its exposure verdict as an assessment and export OpenVEX or CSAF from there. The VEX feature must be enabled first.
- DefectDojo is the better choice if the team wants SLA countdowns and bidirectional Jira out of the box. The agent would write findings through the import or reimport API or the official MCP server. Dedup keys would stop repeated advisories from producing repeated tickets.
- Both platforms push tickets to Jira themselves. The agent may not need direct Jira access for the "ticket" tier, only for "page"-tier incidents.
- Avoid ArcherySec (stale) and OpenCVE (BSL) as core dependencies.

### Gaps
- I did not open Dependency-Track's notification or VEX docs. Its support for CycloneDX VEX import and export and for Jira/Slack/webhook publishers comes from general knowledge, not verified here.
- I did not verify DefectDojo's cross-tool dedup algorithm details (hash fields per parser) or the exact API endpoints for import/reimport.
- Whether Faraday's open-source edition contains any LLM features (versus its commercial edition) is unclear.

## 4. DFIR and case management (brief): IRIS, TheHive/Cortex, Velociraptor, Wazuh, OpenCTI, MISP

### Takeaway
DFIR-IRIS (LGPL-3.0, active) is the best fully open case manager with a documented API. TheHive 3 and 4 are archived and no longer distributed. TheHive 5 is commercial, with a free Community license that must be requested (otherwise the UI is read-only). Cortex stays AGPL and active. Catalyst (AGPL, Go and Vue incident response platform) was archived in 2026. Velociraptor (AGPL-3.0) and Wazuh (GPL-2.0 plus AGPL-3.0 engine) are active and both have community MCP servers. Wazuh's active response is triggered by rules; I found no source showing a vulnerability finding automatically triggering patching. OpenCTI (Apache-2.0 Community Edition plus EE) and MISP (AGPL-3.0) supply threat-intel context, and MISP has an official misp-mcp repo with no license file.

### Cited Findings

Verified repo metadata (2026-11-21):

| Repo | Lang | License | Stars | Last push | Status |
|---|---|---|---|---|---|
| [dfir-iris/iris-web](https://github.com/dfir-iris/iris-web) | Shell | LGPL-3.0 | 1,631 | 2026-11-10 | active |
| [dfir-iris/iris-client](https://github.com/dfir-iris/iris-client) | Python | LGPL-3.0 | 31 | 2024-08-19 | STALE |
| [srozb/iris-mcp](https://github.com/srozb/iris-mcp) | Python | MIT | 6 | 2026-01-28 | community |
| [TheHive-Project/TheHive](https://github.com/TheHive-Project/TheHive) | Scala | AGPL-3.0 | 3,951 | 2025-07-25 | ARCHIVED |
| [TheHive-Project/Cortex](https://github.com/TheHive-Project/Cortex) | Scala | AGPL-3.0 | 1,650 | 2026-10-20 | active |
| [TheHive-Project/Cortex-Analyzers](https://github.com/TheHive-Project/Cortex-Analyzers) | Python | AGPL-3.0 | 495 | 2026-11-19 | active |
| [TheHive-Project/TheHive4py](https://github.com/TheHive-Project/TheHive4py) | Python | MIT | 244 | 2026-10-04 | active |
| [lidless-labs/thehive-mcp](https://github.com/lidless-labs/thehive-mcp) | TypeScript | MIT | 1 | 2026-10-29 | community, tiny |
| [SecurityBrewery/catalyst](https://github.com/SecurityBrewery/catalyst) | Vue | AGPL-3.0 | 536 | 2026-07-18 | ARCHIVED |
| [flowintel/flowintel](https://github.com/flowintel/flowintel) | Python | AGPL-3.0 | 174 | 2026-11-19 | active |
| [Velocidex/velociraptor](https://github.com/Velocidex/velociraptor) | Go | NOASSERTION (AGPL-3.0 text) | 4,495 | 2026-11-20 | active |
| [mgreen27/mcp-velociraptor](https://github.com/mgreen27/mcp-velociraptor) | Python | none | 96 | 2026-06-28 | community, no license |
| [wazuh/wazuh](https://github.com/wazuh/wazuh) | C++ | NOASSERTION (GPL-2.0; engine AGPL-3.0-or-later; shared libs dual) | 17,849 | 2026-11-21 | active |
| [gensecaihq/Wazuh-MCP-Server](https://github.com/gensecaihq/Wazuh-MCP-Server) | Python | MIT | 277 | 2026-11-20 | community |
| [OpenCTI-Platform/opencti](https://github.com/OpenCTI-Platform/opencti) | TypeScript | NOASSERTION (Apache-2.0 Community Edition; EE separate) | 10,414 | 2026-11-21 | active |
| [zxzinn/opencti-mcp](https://github.com/zxzinn/opencti-mcp) | TypeScript | MIT | 43 | 2026-08-03 | community |
| [MISP/MISP](https://github.com/MISP/MISP) | PHP | AGPL-3.0 | 6,687 | 2026-11-20 | active |
| [MISP/misp-mcp](https://github.com/MISP/misp-mcp) | Python | none | 16 | 2026-06-26 | official, no license file |
| [yeti-platform/yeti](https://github.com/yeti-platform/yeti) | Python | Apache-2.0 | 2,045 | 2026-11-19 | active |
| [google/timesketch](https://github.com/google/timesketch) | Python | Apache-2.0 | 3,452 | 2026-11-12 | active |
| [socfortress/CoPilot](https://github.com/socfortress/CoPilot) | Python | AGPL-3.0 | 548 | 2026-11-21 | active |

- **TheHive**: "TheHive 3 and TheHive 4 versions are no longer maintained, distributed, or publicly accessible since 2023 ... TheHive is now distributed as a commercial version" — [TheHive README](https://github.com/TheHive-Project/TheHive#readme). Tiers are Community (free, self-hosted, licence must be requested), Gold, Platinum, and "ONE" (6.0+). Without a registered Community licence, the interface is "limited to read-only mode". The same page calls Cortex "a fully open-source project" — [StrangeBee licenses](https://docs.strangebee.com/thehive/installation/licenses/about-licenses/). The terms conflict. The current docs call Community a "free, self-hosted version of TheHive for non-commercial use" — [StrangeBee licenses](https://docs.strangebee.com/thehive/installation/licenses/about-licenses/). The 2021 launch post said Community was free for "personal, educational, and basic commercial use" — [StrangeBee blog, 2021-10-16](https://strangebee.com/blog/thehive-turns-5-and-adopts-a-model-shaped-for-the-future/).
- **DFIR-IRIS**: "Collaborative Incident Response platform". Its backend is a Python/Flask API and workers, and the API reference is in the docs — [iris-web README](https://github.com/dfir-iris/iris-web#readme).
- **Catalyst**: "a self-hosted, open source incident response platform and ticket system" with tickets for alerts and incidents, HTTP/webhook triggers, and Python and HTTP actions. It is archived. Its last commits (July 2026) were dependency bumps, and the README gives no reason for archiving — [catalyst](https://github.com/SecurityBrewery/catalyst).
- **Wazuh**: active response automates response actions when findings meet configured conditions, using out-of-the-box scripts that block network access or disable accounts. It is configured as rule-triggered commands such as `firewall-drop` — [Wazuh active response docs](https://documentation.wazuh.com/5.0-beta/user-manual/capabilities/active-response/index.html). Vulnerability detection assesses monitored endpoints for vulnerable OS components and applications — [Wazuh vulnerability detection](https://wazuh.com/resources/use-cases/vulnerability-detection/). The community Wazuh MCP server advertises "55 security tools for alert triage, threat hunting, vulnerability management ... and active response" — [Wazuh-MCP-Server](https://github.com/gensecaihq/Wazuh-MCP-Server).
- **MISP** offers "Turn your MISP into an MCP service" in an official repo with no license file — [misp-mcp](https://github.com/MISP/misp-mcp). **OpenCTI**: the Community Edition is Apache-2.0 — [OpenCTI LICENSE](https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE). Community MCP servers exist — [zxzinn/opencti-mcp](https://github.com/zxzinn/opencti-mcp).

### Inferences
- These tools matter to the agent mainly as optional context sources (MISP or OpenCTI for "is this CVE being exploited / by whom") and as an alternative case store (IRIS). For a vulnerability-signal agent (as opposed to an alert-triage agent), a Jira, GitHub issue or DefectDojo record is usually enough. IRIS or TheHive is overkill unless the scenario turns into a real compromise, for example a supply-chain package that executed in CI.
- If the scenario includes "we ran the malicious package", Velociraptor (artifact collection) and Wazuh (rule-triggered active response) are the open-source "react" levers. Their MCP bridges are community-maintained, and some have no license (mcp-velociraptor, misp-mcp).

### Gaps
- TheHive 5 Community user and organization limits: one search snippet said 2 users and 1 organisation, but the docs page I fetched gave no numbers. Unverified.
- I did not verify whether OpenCTI's or Filigran's AI features are open source or EE-only.
- Catalyst's reason for archiving is not stated.

## 5. Reporting and advisory output formats and tools (CSAF, OpenVEX, CycloneDX VEX/VDR, SARIF), postmortem templates and generators, and report fields

### Takeaway
For the "report" stage, emit **OpenVEX** for per-vulnerability exposure verdicts (simplest; `vexctl` and `go-vex`). Emit **CycloneDX VEX** (spec 1.7, latest release 1.7.2 on 2026-09-17) if the project already produces CycloneDX SBOMs. Emit **CSAF 2.0** for a full advisory: it is an OASIS Standard and ISO/IEC 20153, while CSAF 2.1 is still a committee draft (CSD02, February 2026). SARIF is for code-level findings, not advisories. Open-source *AI-written* incident reports are rare. Dispatch's archived GenAI module and Keep's experimental open-source incident assistant are the notable examples, and templates come from PagerDuty's Apache-2.0 postmortem docs. Because the hackathon is Mistral's and EU-based: since 2026-09-11 the EU Cyber Resilience Act requires manufacturers to report actively exploited vulnerabilities within 24h (early warning), 72h (notification) and 14 days after a fix is available (final report). That timeline should drive the report template.

### Cited Findings

Verified repo metadata (2026-11-21):

| Repo | Lang | License | Stars | Last push | Status |
|---|---|---|---|---|---|
| [oasis-tcs/csaf](https://github.com/oasis-tcs/csaf) | HTML | NOASSERTION (OASIS TC terms) | 231 | 2026-11-18 | active |
| [gocsaf/csaf](https://github.com/gocsaf/csaf) | Go | null (LICENSES/: Apache-2.0, BSD-3-Clause, MIT) | 73 | 2026-11-18 | active |
| [secvisogram/secvisogram](https://github.com/secvisogram/secvisogram) | JavaScript | Apache-2.0 | 46 | 2026-11-19 | active |
| [secvisogram/csaf-validator-lib](https://github.com/secvisogram/csaf-validator-lib) | JavaScript | Apache-2.0 | 5 | 2026-11-20 | active |
| [anthonyharrison/csaf](https://github.com/anthonyharrison/csaf) | Python | MIT | 9 | 2024-10-16 | STALE |
| [openvex/spec](https://github.com/openvex/spec) | - | CC0-1.0 | 203 | 2026-10-30 | active |
| [openvex/vexctl](https://github.com/openvex/vexctl) | Go | Apache-2.0 | 222 | 2026-11-20 | active |
| [openvex/go-vex](https://github.com/openvex/go-vex) | Go | Apache-2.0 | 74 | 2026-11-19 | active |
| [aquasecurity/vexhub](https://github.com/aquasecurity/vexhub) | - | Apache-2.0 | 40 | 2026-03-23 | active (low activity) |
| [CycloneDX/specification](https://github.com/CycloneDX/specification) | XSLT | Apache-2.0 | 585 | 2026-11-21 | active |
| [CycloneDX/cyclonedx-cli](https://github.com/CycloneDX/cyclonedx-cli) | C# | Apache-2.0 | 564 | 2026-10-19 | active |
| [oasis-tcs/sarif-spec](https://github.com/oasis-tcs/sarif-spec) | HTML | NOASSERTION (OASIS TC terms) | 216 | 2026-11-08 | active |
| [microsoft/sarif-sdk](https://github.com/microsoft/sarif-sdk) | C# | NOASSERTION (MIT text) | 228 | 2026-11-14 | active |
| [PagerDuty/postmortem-docs](https://github.com/PagerDuty/postmortem-docs) | Dockerfile | Apache-2.0 | 73 | 2026-10-30 | active |
| [PagerDuty/incident-response-docs](https://github.com/PagerDuty/incident-response-docs) | Dockerfile | Apache-2.0 | 1,054 | 2026-10-30 | active |
| [dastergon/postmortem-templates](https://github.com/dastergon/postmortem-templates) | - | CC0-1.0 | 1,460 | 2023-07-12 | STALE |
| [danluu/post-mortems](https://github.com/danluu/post-mortems) | - | none | 12,742 | 2026-08-31 | active (collection) |
| [nbshah3/incident-postmortem-ai](https://github.com/nbshah3/incident-postmortem-ai) | - | MIT | 1 | 2026-01-23 | tiny |

Formats:
- **OpenVEX** (spec v0.2.0): documents carry `@context: https://openvex.dev/ns/v0.2.0`, and the document `version` "must be incremented when any content within the VEX document changes". Statuses are `not_affected`, `affected`, `fixed` and `under_investigation`. A `not_affected` statement MUST include a `justification` or an `impact_statement`, and an `affected` statement should include an `action_statement`. The five justification labels are `component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary` and `inline_mitigations_already_exist` — [OPENVEX-SPEC.md](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md). `vexctl` creates VEX documents, wraps them in signed attestations, and applies VEX to scanner results — [vexctl README](https://github.com/openvex/vexctl#readme).
- **CycloneDX VEX/VDR** (schema 1.7): `analysis.state` ∈ {resolved, resolved_with_pedigree, exploitable, in_triage, false_positive, not_affected}. `analysis.justification` ∈ {code_not_present, code_not_reachable, requires_configuration, requires_dependency, requires_environment, protected_by_compiler, protected_at_runtime, protected_at_perimeter, protected_by_mitigating_control}. `analysis.response` ∈ {can_not_fix, will_not_fix, update, rollback, workaround_available}. Analysis also carries `detail`, `firstIssued` and `lastUpdated`. The vulnerability object includes `ratings`, `cwes`, `recommendation`, `workaround`, `proofOfConcept`, `advisories` and `affects` — [bom-1.7.schema.json](https://github.com/CycloneDX/specification/blob/master/schema/bom-1.7.schema.json). The latest releases are 1.7.2 (2026-09-17) and 1.7.1 (2026-06-02) — [CycloneDX releases](https://github.com/CycloneDX/specification/releases). CycloneDX is standardized as ECMA-424 — [SecObserve vex.md](https://github.com/SecObserve/SecObserve/blob/main/docs/integrations/vex.md).
- **CSAF**: CSAF 2.1 Committee Specification Draft 02 is dated 25 February 2026, and its public review ended April 7 — [CSAF 2.1 CSD02](https://docs.oasis-open.org/csaf/csaf/v2.1/csd02/csaf-v2.1-csd02.pdf); [OASIS review notice](https://groups.oasis-open.org/discussion/invitation-to-comment-on-csaf-v21-csd02-ends-april-7th-3). The 2.1 draft still refers to CSAF 2.0 as the current OASIS Standard — [CSAF 2.1 CSD02](https://docs.oasis-open.org/csaf/csaf/v2.1/csd02/csaf-v2.1-csd02.pdf). Search summaries say 2.0 became an OASIS Standard in November 2022. CSAF 2.0 was adopted as ISO/IEC 20153 — [ISO 20153](https://www.iso.org/standard/89986.html). gocsaf provides a trusted provider, checker, aggregator, downloader, validator and uploader, and is building CSAF 2.1 support as major version 5 — [gocsaf README](https://github.com/gocsaf/csaf#readme). Secvisogram is the BSI web editor for CSAF 2.0/2.1 and validates against a strict schema — [secvisogram README](https://github.com/secvisogram/secvisogram#readme).
- **SARIF**: the OASIS TC repo for the draft standard is active — [sarif-spec](https://github.com/oasis-tcs/sarif-spec). Microsoft maintains a .NET SDK — [sarif-sdk](https://github.com/microsoft/sarif-sdk).

Postmortem and report generators:
- **PagerDuty postmortem docs** (Apache-2.0) include a postmortem template PDF and guides on effective, blameless postmortems — [postmortem-docs](https://github.com/PagerDuty/postmortem-docs). **dastergon/postmortem-templates** collects templates (CC0, stale) — [postmortem-templates](https://github.com/dastergon/postmortem-templates). **danluu/post-mortems** is a collection of public postmortems with no license — [post-mortems](https://github.com/danluu/post-mortems).
- **AI-written (open source)**: Dispatch (archived) has `generate_tactical_report`, `generate_incident_summary` and `generate_read_in_summary` — [dispatch/ai/service.py](https://github.com/Netflix/dispatch/blob/main/src/dispatch/ai/service.py). Keep's AI Incident Assistant, experimental in OSS, streams incident context (alerts, descriptions, topology) to the LLM — [ai-incident-assistant.mdx](https://github.com/keephq/keep/blob/main/docs/overview/ai-incident-assistant.mdx). incidentbot can "Automatically build a postmortem document base" — [incidentbot README](https://github.com/incidentbot/incidentbot#readme). FunnyWolf's Agentic SOC Platform produces "severity, confidence, impact, priority, verdicts, and structured investigation reports" — [ASP README](https://github.com/FunnyWolf/agentic-soc-platform#readme). incident-postmortem-ai does "Deterministic incident postmortems from logs and metrics: timeline reconstruction, root-cause hypotheses ... PDF reports" (1 star) — [incident-postmortem-ai](https://github.com/nbshah3/incident-postmortem-ai).

Regulatory and reference inputs for report fields:
- **EU CRA**: "As of 11 September 2026, manufacturers are required to report actively exploited vulnerabilities and severe incidents". The deadlines are an early warning within 24 hours of awareness, a full notification within 72 hours, and a final report no later than 14 days after a corrective measure is available (one month for severe incidents). Reports go through ENISA's Single Reporting Platform to the CSIRT of the manufacturer's main establishment, with ENISA receiving them at the same time. Obligations for open-source stewards apply from 11 December 2027 — [EC CRA reporting](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting). Vulnerabilities whose active exploitation was known before 11 September 2026 need not be reported retrospectively, and legacy products are covered — [ENISA SRP launch](https://www.enisa.europa.eu/news/the-cra-single-reporting-platform-is-launched).
- **NIST SP 800-61r3** (final, April 2025) recasts incident response as a CSF 2.0 Community Profile and supersedes the Rev. 2 lifecycle — [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final).
- **CISA KEV entry fields**: `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded`, `shortDescription`, `requiredAction`, `dueDate`, `knownRansomwareCampaignUse`, `forensicTriage`, `notes`, `cwes`. Read from the catalog JSON, catalogVersion 2026.11.20 — [cisagov/kev-data](https://github.com/cisagov/kev-data).

### Inferences
- A good vulnerability-incident report built from the sources above would have these sections:
  1. **Header**: report ID, version, status (draft or final), author (agent ID plus human approver), timestamps, regulatory clocks (CRA 24h/72h/14d if applicable).
  2. **Signal**: source (CVE, GHSA, OSV, KEV addition, vendor advisory), IDs and aliases, publish and modify dates, when the agent ingested it.
  3. **Affected assets**: product, component purl and version, deployment or service, environment, internet exposure, owner.
  4. **Exposure verdict with evidence**: VEX status and justification using the OpenVEX or CycloneDX vocabulary, `impact_statement`, plus the evidence (lockfile or SBOM match, reachability or call-graph result, configuration check, runtime check) and the confidence.
  5. **Severity context**: CVSS v4 vector and score (CVSS-B/BT/BE), EPSS score and percentile with date, KEV flag with `dateAdded`, `dueDate`, `knownRansomwareCampaignUse` and `forensicTriage`, SSVC decision points and outcome.
  6. **Timeline**: detection, triage, decision, mitigation, patch PR, deploy, verify, close.
  7. **Actions**: mitigation or workaround, patch (version, PR link), CycloneDX-style `response` value.
  8. **Escalation record**: who was paged, ticket IDs, acknowledgement times, approvals given.
  9. **Residual risk and follow-ups**: accepted risk with expiry (SecObserve and DefectDojo both model risk-acceptance expiry), next review date.
  10. **Machine-readable attachments**: an OpenVEX statement and/or a CSAF advisory.
- The cheapest format path for a hackathon: generate OpenVEX with `go-vex` or `vexctl` (Go) or emit the JSON directly, since the schema is small. Optionally convert to CSAF later or use Secvisogram for a human-edited advisory.
- An LLM is well suited to drafting the human-readable sections (summary, impact statement, timeline narrative). Machine-readable fields such as VEX status, KEV and EPSS values should be filled deterministically from tool outputs, not generated.

### Gaps
- I found no maintained open-source *Python* CSAF generator. anthonyharrison/csaf has been stale since 2024-10. gocsaf is Go and focuses on distribution and validation, not authoring.
- I did not verify the CRA notification content requirements, which are in Commission guidance section 9.1 and the FAQs referenced from the EC page.
- I did not confirm the meaning of the new KEV `forensicTriage` field (Yes/No). Its name suggests CISA recommends compromise assessment for those entries, but I found no CISA definition.
- I did not open the PagerDuty postmortem template PDF to extract its exact fields.

## 6. Severity and prioritization logic for escalation: SSVC, EPSS/KEV policies, CVSS v4, and which implementations decide page vs ticket vs log

### Takeaway
The most defensible and agent-friendly policy is CISA's SSVC tree. It is a fixed 36-row lookup with four outcomes: Track, Track*, Attend, Act. Exploitation comes from KEV, Vulnrichment and PoC sources; Automatable and Technical Impact come from CISA's Vulnrichment ADP data, published in the CVE record; Mission & Well-being comes from the team's own asset criticality. CERTCC/SSVC (PyPI `certcc-ssvc`) and Vulnesis/python-ssvc (PyPI `ssvc`, MIT) implement it. KEV now often sets 3-day due dates: 166 of the 306 entries added in 2026 have a 3-day deadline. EPSS v4 (March 2025) and NIST's LEV metric (CSWP 41, May 2025) supply likelihood. CVSS v4 libraries exist; the actively maintained one is pandatix/go-cvss, while FIRST's calculator and Red Hat's Python library are stale.

### Cited Findings

Verified repo metadata (2026-11-21):

| Repo | Lang | License | Stars | Last push | Status |
|---|---|---|---|---|---|
| [CERTCC/SSVC](https://github.com/CERTCC/SSVC) | Python | NOASSERTION (per-directory licenses; CMU copyright) | 202 | 2026-11-21 | active |
| [Vulnesis/python-ssvc](https://github.com/Vulnesis/python-ssvc) | Python | MIT | 23 | 2026-11-19 | active |
| [cisagov/vulnrichment](https://github.com/cisagov/vulnrichment) | - | CC0-1.0 | 888 | 2026-11-21 | active |
| [cisagov/kev-data](https://github.com/cisagov/kev-data) | HTML | NOASSERTION (CC0-1.0 text) | 149 | 2026-11-20 | active |
| [FIRSTdotorg/cvss-v4-calculator](https://github.com/FIRSTdotorg/cvss-v4-calculator) | JavaScript | BSD-2-Clause | 44 | 2024-08-19 | STALE |
| [RedHatProductSecurity/cvss](https://github.com/RedHatProductSecurity/cvss) | Python | LGPL-3.0 | 132 | 2025-08-04 | STALE |
| [pandatix/go-cvss](https://github.com/pandatix/go-cvss) | Go | MIT | 54 | 2026-11-12 | active |
| [TURROKS/CVE_Prioritizer](https://github.com/TURROKS/CVE_Prioritizer) | Python | BSD-3-Clause | 713 | 2026-08-23 | active |
| [rapticore/ssvc_ore_miner](https://github.com/rapticore/ssvc_ore_miner) | Python | Apache-2.0 | 9 | 2026-07-24 | tiny |

SSVC (CISA guide, published November 2022):
- **Outcomes**: *Track*: "does not require action at this time ... remediating Track vulnerabilities within standard update timelines". *Track\**: "specific characteristics that may require closer monitoring for changes", remediated within standard timelines. *Attend*: "requires attention from the organization's internal, supervisory-level individuals ... may involve publishing a notification", remediated "sooner than standard update timelines". *Act*: requires "supervisory-level and leadership-level individuals"; internal groups "meet to determine the overall response", and remediation should happen "as soon as possible" — [CISA SSVC Guide](https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%20508c.pdf).
- **Decision points**: Exploitation ∈ {none, public PoC, active}; Technical Impact ∈ {partial, total}; Automatable ∈ {no, yes}, where "yes" applies for example to unauthenticated RCE or command injection. Mission & Well-being ∈ {low, medium, high} is derived from Mission Prevalence {minimal, support, essential} × Public Well-Being Impact {minimal, material, irreversible}: essential always gives high; minimal × minimal gives low; support × minimal, support × material and minimal × material give medium; anything × irreversible gives high. Mitigation status "does not change the priority of the SSVC decision" but should be tracked — [CISA SSVC Guide](https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%20508c.pdf).
- **Full decision table (Table 9; Exploitation / Automatable / Technical Impact / Mission&Well-being → outcome)** — [CISA SSVC Guide](https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%20508c.pdf):
  - none: every combination is Track except: no+total+high → Track\*; yes+partial+high → Attend; yes+total+high → Attend.
  - poc: no+partial+high → Track\*; no+total+medium → Track\*; no+total+high → Attend; yes+partial+high → Attend; yes+total+medium → Track\*; yes+total+high → Attend; all other poc rows → Track.
  - active: no+partial+low/medium → Track; no+partial+high → Attend; no+total+low → Track; no+total+medium → Attend; no+total+high → **Act**; yes+partial+low/medium → Attend; yes+partial+high → **Act**; yes+total+low → Attend; yes+total+medium/high → **Act**.
- **Vulnrichment**: every CVE analyzed by the CISA ADP gets three SSVC decision points (`Exploitation`, `Automatable`, `Technical Impact`) in its ADP container. CVEs rated Total impact, Automatable, or with PoC or active exploitation get further CWE, CVSS and CPE enrichment when evidence allows, and a KEV flag is also added — [vulnrichment README](https://github.com/cisagov/vulnrichment#readme).
- **CERTCC/SSVC**: "The `ssvc` python module provides tools to work with decision points, decision point groups, and outcomes". Decision tables are shipped as CSVs, and "Customizing the 'outcome' column in this csv is the primary recommended way that stakeholders might adapt SSVC". There is also a D3 calculator directory — [CERTCC/SSVC README](https://github.com/CERTCC/SSVC#readme). The package name is `certcc-ssvc` — [pyproject.toml](https://github.com/CERTCC/SSVC/blob/main/pyproject.toml).
- **Vulnesis/python-ssvc**: `pip install ssvc`. It has a plugin architecture with CISA, Coordinator and Supplier methodologies plus an "AI/LLM triage" methodology, and supports vector strings and JSON. Example API: `ssvc.Decision(...)`, then `.outcome.action`, `.outcome.priority` and `.to_vector()` — [python-ssvc README](https://github.com/Vulnesis/python-ssvc#readme).

KEV, EPSS, LEV and CVSS:
- **KEV catalog** (catalogVersion 2026.11.20) has 1,790 entries; 361 are flagged `knownRansomwareCampaignUse = Known` and 111 have `forensicTriage = Yes`. Of the 306 entries added in 2026, the `dueDate − dateAdded` offsets are 3 days (166 entries), 14 days (93), 21 days (44), 2 days (2) and 5 days (1). The newest entry, CVE-2026-76466, was added 2026-11-20 with a due date of 2026-11-23. All of these figures were computed from the JSON — [cisagov/kev-data](https://github.com/cisagov/kev-data).
- **EPSS v4** was released 2025-03-17, according to secondary sources citing FIRST — [Wikipedia: EPSS](https://en.wikipedia.org/wiki/Exploit_Prediction_Scoring_System); [Empirical Security: Introducing EPSS v4](https://research.empiricalsecurity.com/research/introducing-epss-version-4). The FIRST API endpoint is `api.first.org/data/v1/epss` — [FIRST EPSS API](https://api.first.org/epss).
- **LEV**: NIST CSWP 41 (Mell, NIST and Spring, CISA; May 2025) proposes the "Likely Exploited Vulnerabilities" metric, a probability that a CVE has already been exploited, computed from historical EPSS data. It is meant to augment EPSS and KEV, not replace them — [NIST CSRC news](https://csrc.nist.gov/news/2025/nist-publishes-cybersecurity-white-paper-41); [NIST CSWP 41 PDF](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.41.pdf).
- **CVSS v4.0**: released by FIRST on 2023-11-01. The Temporal group became Threat (Exploit Maturity). Supplemental metrics (Automatable, Recovery, Value Density, Vulnerability Response Effort, Provider Urgency, Safety) do not change the score. Score labels are CVSS-B, CVSS-BT, CVSS-BE and CVSS-BTE. These are secondary news sources, not the spec text — [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-cvss-40-vulnerability-severity-rating-standard-released/); [The Hacker News](https://thehackernews.com/2023/11/first-announces-cvss-40-new.html).
- **Implementations**: FIRST's official v4 calculator (BSD-2, stale since 2024-08) — [cvss-v4-calculator](https://github.com/FIRSTdotorg/cvss-v4-calculator). Red Hat's CVSS 2/3/4 Python library (LGPL-3.0, last push 2025-08) — [RedHatProductSecurity/cvss](https://github.com/RedHatProductSecurity/cvss). go-cvss (MIT, active) — [pandatix/go-cvss](https://github.com/pandatix/go-cvss).
- **CVE_Prioritizer** combines CVSS, EPSS and KEV (CISA or VulnCheck). It gives priority to KEV entries and uses "EPSS Threshold is set to 0.2", following FIRST's EPSS user guide on combining CVSS and EPSS — [CVE_Prioritizer README](https://github.com/TURROKS/CVE_Prioritizer#readme).
- Platform hooks: SecObserve's Rego rules can read EPSS to set priority — [SecObserve epss.md](https://github.com/SecObserve/SecObserve/blob/main/docs/integrations/epss.md). DefectDojo SLA days are set per severity — [DefectDojo SLA docs](https://github.com/DefectDojo/django-DefectDojo/blob/dev/docs/content/asset_modelling/OS_hierarchy/OS__sla_configuration.md).

### Inferences
- Suggested page / ticket / log policy. This is my synthesis, not a CISA rule; the CISA wording only gives "as soon as possible / sooner than standard / standard timelines".
  1. **Gate 0, exposure first**: if the exposure check proves `not_affected` (component absent, vulnerable code not present or not reachable), write an OpenVEX `not_affected` statement with a justification and evidence, record it in SecObserve or DefectDojo, and **log only** (no human).
  2. **Gate 1, hard overrides to PAGE**: exposed AND (in KEV, or Vulnrichment `Exploitation=active`, or confirmed supply-chain compromise that executed in our build or runtime) AND the asset is internet-facing or production. Also page if the team is an EU "manufacturer" and the vulnerability is actively exploited *in its own product*, because the CRA 24h early-warning clock starts.
  3. **Gate 2, SSVC table**: Act → **page** (on-call plus a lead), ticket due in about 3 days, which mirrors the dominant 2026 KEV due date. Attend → **ticket**, high priority, due in about 14 days, with a Slack notification but no page. Track\* → **ticket**, normal priority, with a watch for changes to EPSS, KEV or PoC status. Track → **log** (record plus VEX `affected` or `under_investigation` with an action statement) and fix within the standard cycle.
  4. **Re-evaluate on change**: re-run when KEV adds the CVE, EPSS rises sharply, a PoC appears, or Vulnrichment updates. Because SSVC is deterministic, re-scoring is cheap and auditable.
- Use EPSS or LEV only to break ties or to promote Track to Track\*, for example EPSS ≥ 0.2 following CVE_Prioritizer's threshold. Do not let the LLM invent the score. The LLM's job is to gather evidence for each decision point and write the justification. The table lookup should be code.
- For a hackathon, hard-code the 36-row CISA table (or use `certcc-ssvc` / `ssvc`) instead of computing CVSS v4. Use Vulnrichment for Automatable and Technical Impact, KEV for Exploitation, and a one-line config per asset for Mission & Well-being.

### Gaps
- I did not verify the current CISA web SSVC calculator or whether CISA has published an updated SSVC guide since November 2022.
- I did not read the official FIRST EPSS v4 announcement; the date rests on agreeing secondary sources. I also did not confirm EPSS API rate limits or batch sizes.
- LEV formulas were not extracted, and I found no maintained open-source LEV implementation.
- What rapticore/ssvc_ore_miner does is not clear from its description, so it is not evaluated.

## 7. Open-source "AI SOC analyst" and alert-triage agents (2025-2026) that make the escalation decision, and how they keep a human in the loop

### Takeaway
Open-source agentic-SOC projects grew quickly in 2025-2026. The largest new ones are Argus (Apache-2.0, 1,259 stars) and FunnyWolf's Agentic SOC Platform (no license file, 1,235 stars). Tracecat is the most production-ready, and HolmesGPT (CNCF sandbox, Apache-2.0, 3,949 stars) is the SRE analogue and is read-only by design. Wazuh-Autopilot has the most explicit human-in-the-loop design: four autonomy levels, an approvals queue, a two-person rule, and agents that never receive state-changing tools. The recurring patterns are read-only agents with a separate executor, approval gates on tool calls, write tools disabled by default, channel allowlists, and CI eval gates. Alias Robotics' CAI framework was archived in August 2026 and replaced by a commercial successor, a reminder of single-vendor risk.

### Cited Findings

Verified repo metadata (2026-11-21):

| Repo | Lang | License | Stars | Last push | Status |
|---|---|---|---|---|---|
| [Sec-Link/Argus-Agentic-SOC-Platform](https://github.com/Sec-Link/Argus-Agentic-SOC-Platform) | Python | Apache-2.0 | 1,259 | 2026-11-20 | active |
| [FunnyWolf/agentic-soc-platform](https://github.com/FunnyWolf/agentic-soc-platform) | Python | none (no license detected) | 1,235 | 2026-09-29 | active |
| [HolmesGPT/holmesgpt](https://github.com/HolmesGPT/holmesgpt) (formerly robusta-dev/holmesgpt) | Python | Apache-2.0 | 3,949 | 2026-11-20 | active |
| [gensecaihq/Wazuh-Autopilot](https://github.com/gensecaihq/Wazuh-Autopilot) | Python | MIT | 67 | 2026-09-24 | active |
| [google/mcp-security](https://github.com/google/mcp-security) (for the closed Google SecOps) | Python | Apache-2.0 | 546 | 2026-11-20 | active |
| [CrowdStrike/falcon-mcp](https://github.com/CrowdStrike/falcon-mcp) (for the closed Falcon) | Python | MIT | 289 | 2026-11-17 | active |
| [panther-labs/mcp-panther](https://github.com/panther-labs/mcp-panther) (for the closed Panther) | Python | Apache-2.0 | 50 | 2026-11-14 | active |
| [markolauren/ResponseMCP](https://github.com/markolauren/ResponseMCP) | Python | none | 22 | 2026-02-03 | community |
| [NathanCavalcanti/pouchnexus](https://github.com/NathanCavalcanti/pouchnexus) | Python | none | 81 | 2026-04-02 | community |
| [tahasiddiquii/soc-triage-agent](https://github.com/tahasiddiquii/soc-triage-agent) | Python | MIT | 1 | 2026-07-01 | tiny |
| [tarvia-soc/soc-triage-agent](https://github.com/tarvia-soc/soc-triage-agent) | Python | none | 2 | 2026-11-08 | hackathon project |
| [ameshram/agentic-alert-triage](https://github.com/ameshram/agentic-alert-triage) | Python | MIT | 0 | 2026-09-16 | reference implementation |
| [aliasrobotics/cai](https://github.com/aliasrobotics/cai) | Python | NOASSERTION | 9,870 | 2026-08-22 | ARCHIVED |

- **Argus**: tickets, an AI assistant with "MCP tool integration", an "MCP-style tool registry and JSON-RPC connector" at `/api/v1/mcp/`, ticket-context queries, similar-case retrieval, CMDB queries and automation chains. The README advises configuring "access boundaries, auditing, and least-privilege for AI/MCP features" — [Argus README](https://github.com/Sec-Link/Argus-Agentic-SOC-Platform#readme).
- **FunnyWolf Agentic SOC Platform (ASP)**: converts SIEM or webhook alerts into Cases. It automatically produces "severity, confidence, impact, priority, verdicts, and structured investigation reports", and its Playbooks orchestrate both SOAR steps and LLM analysis. It is exposed to Claude Code, Codex and OpenCode through a CLI and plugins, and extracts knowledge from closed cases — [ASP README](https://github.com/FunnyWolf/agentic-soc-platform#readme).
- **HolmesGPT**: "Open-source AI agent for investigating production incidents". It uses an agentic loop over observability data, can "Fetch alerts from AlertManager, PagerDuty, OpsGenie, or Jira—and write findings back", and supports any LLM provider. "By design, HolmesGPT has read-only access and respects RBAC permissions". An Operator mode runs it in the background so investigations do not wait for a human trigger — [HolmesGPT README](https://github.com/HolmesGPT/holmesgpt#readme).
- **Wazuh-Autopilot**: a 13-agent Strands swarm that reaches Wazuh only through the Wazuh MCP Server. It has an "Autonomy policy" with "Four levels: observe, recommend, supervised, autonomous", per-action rules (confidence floor, hourly budget), protected targets, "a two-person rule and a business-hours limit". "Agents never receive state-changing Wazuh tools: the MCP tool filter and a pre-tool hook both block them. The platform runs approved actions, verifies them ... and can roll them back". Its standards list includes CISA KEV, FIRST EPSS, SSVC and SP 800-61r3. Models include Bedrock, Anthropic, OpenAI-compatible endpoints, vLLM, LiteLLM and Ollama — [Wazuh-Autopilot README](https://github.com/gensecaihq/Wazuh-Autopilot#readme).
- **Tracecat** human-in-the-loop: "review and approve sensitive tools calls from a unified inbox, Slack, or email" — [Tracecat README](https://github.com/TracecatHQ/tracecat#readme).
- **Small and hackathon-scale patterns**: tahasiddiquii/soc-triage-agent says "no containment action ever runs without a human approving it". Its drafted containment is "inert" until approved, and `soc eval` gates CI over 40 labelled alerts — [soc-triage-agent README](https://github.com/tahasiddiquii/soc-triage-agent#readme). tarvia-soc's agent works as "code checks the facts, an LLM judges, a person decides" — [tarvia-soc](https://github.com/tarvia-soc/soc-triage-agent). ameshram's reference combines "LLM reasoning + a deterministic policy engine, prompt-injection defenses, human-in-the-loop, and a CI-gated eval harness" — [agentic-alert-triage](https://github.com/ameshram/agentic-alert-triage). pouchnexus is a LangGraph multi-agent SOC/DFIR assistant that does IOC extraction, ATT&CK mapping, CVE correlation and report generation — [pouchnexus](https://github.com/NathanCavalcanti/pouchnexus).
- **Vendor MCP bridges** (open-source code for closed platforms): Google SecOps, GTI, SCC and SecOps SOAR MCP servers, plus a recommended hosted remote MCP server for SecOps — [google/mcp-security README](https://github.com/google/mcp-security#readme). There are also bridges for CrowdStrike Falcon — [falcon-mcp](https://github.com/CrowdStrike/falcon-mcp) — and Panther — [mcp-panther](https://github.com/panther-labs/mcp-panther). ResponseMCP exposes Microsoft Defender XDR response actions (for example `confirm_user_compromised`) and works alongside the Sentinel MCP — [ResponseMCP README](https://github.com/markolauren/ResponseMCP#readme).
- **Write-gating in escalation MCPs**: korotovsky's Slack server ships with posting disabled by default — [korotovsky README](https://github.com/korotovsky/slack-mcp-server#readme). The local PagerDuty MCP package was reportedly read-only unless `--enable-write-tools` was set (secondhand, from search summaries) — [pagerduty-mcp on PyPI](https://pypi.org/project/pagerduty-mcp).
- **CAI**: "Archived. The research it produced continues." Development ran from March 2025 to August 2026, and the successor is the commercial "Cybersecurity Superintelligence (CSI)" — [CAI README](https://github.com/aliasrobotics/cai#readme).

### Inferences
- The patterns worth copying for the hackathon agent are:
  1. Split *decide* from *do*. The LLM agent gets read and verify tools only, and a deterministic executor performs paging, patch PRs and containment after a policy check, as in Wazuh-Autopilot.
  2. Use autonomy levels per action type. For example: log VEX = autonomous; open ticket = autonomous; post to Slack = autonomous to an allowlisted channel; page on-call = supervised with an auto-approve rule only for SSVC Act plus a KEV override; merge a patch or isolate a host = always human-approved.
  3. Keep the escalation decision deterministic (the SSVC table) and have the LLM produce the evidence and justification.
  4. Add a small labelled eval set of past advisories with expected outcomes and gate changes on it, as tahasiddiquii and ameshram do.
- Argus and ASP show that "AI SOC" projects are converging on case-centric designs with MCP tool registries. Neither appears to implement vulnerability-specific prioritization (SSVC or KEV) natively; Wazuh-Autopilot lists SSVC, KEV and EPSS among its standards.
- FunnyWolf ASP has no detected license file, so legally it cannot be reused beyond viewing. Treat it as inspiration only.

### Gaps
- I did not find an open-source AI SOC project focused specifically on *vulnerability advisories* (CVE, GHSA or KEV) rather than SIEM alerts. Most target alert triage. End-to-end LLM vulnerability agents were out of scope for this note and are covered by other researchers.
- Closed commercial "AI SOC" products were not researched. Only closed platforms that appeared incidentally are noted: Grafana Cloud IRM, TheHive 5 paid tiers, DefectDojo Pro, Keep Enterprise AI correlation, Rootly, PagerDuty and Opsgenie.
- I did not check the Argus or FunnyWolf code for explicit approval gates, beyond what their READMEs state.
