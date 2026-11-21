# Watchlist

Where new material for the knowledge base comes from. Patch and advisory data has its own page: [Feeds](feeds.md).

Last checked: 2026-11-21 (seed).

## Publishers

| Source | Where | Why it is here |
|---|---|---|
| Verizon DBIR | https://www.verizon.com/business/resources/reports/dbir/ | Yearly. How organisations are breached. |
| Microsoft Digital Defense Report | https://www.microsoft.com/en-us/security/security-insider | Yearly. Exploit speed, identity, what its responders see. |
| FBI IC3 annual report | https://www.ic3.gov | Yearly. US reported losses by type of fraud. |
| UK Finance annual fraud report | https://www.ukfinance.org.uk | Yearly. UK payment fraud, including APP fraud. |
| UK Cyber Security Breaches Survey | https://www.gov.uk/government/collections/cyber-security-breaches-survey | Yearly. What UK businesses experience and do. |
| UK NCSC | https://www.ncsc.gov.uk | Guidance for small organisations, and joint advisories. |
| European Commission, CRA pages | https://digital-strategy.ec.europa.eu/en/policies/cra-reporting | The reporting duty the team's tool drafts for. Watch for changes and new guidance. |
| Anthropic threat intelligence reports | https://www.anthropic.com | How AI is misused, as seen by one model maker. |
| Push Security | https://pushsecurity.com/blog | Browser-side attack data, including ClickFix. |
| Socket | https://socket.dev/blog | Malicious packages and dependency practice. |
| Unit 42 | https://unit42.paloaltonetworks.com | Detailed write-ups, including agent supply chain. |
| OWASP GenAI Security Project | https://genai.owasp.org | The agentic top 10 and quarterly exploit round-ups. |
| Cloud Security Alliance labs | https://labs.cloudsecurityalliance.org | Research notes on MCP and agent incidents. |
| Simon Willison | https://simonwillison.net | Names things early and follows agent security week by week. |

## Open leads

Things the knowledge base needs and does not have.

- **The design branch.** `docs/system-design` was ingested at commit `c0211d4`. Ingest it again when it moves.
- **The CRA text itself.** Article 14 of Regulation (EU) 2024/2847, and the Commission's guidance and FAQ, for what each report must contain and how "actively exploited" is defined.
- **Raise the read levels.** Start with the nine pages the research report read in full, then the pages behind the advisories. A `via-snippet` note is only a lead.
- **A source for the baseline steps.** NIST's incident-response guide (SP 800-61) is the first candidate. Each *(baseline)* tag in a playbook is a claim waiting for a source.
- **Fix status for every curated advisory.** Read the originals and record whether a fix shipped, and in which version.
- **Meta's Rule of Two paper** itself. The note here rests on a summary of it.
- **The full OWASP top 10 for agentic applications.** Only one item is recorded.
- **The Black Hat 2026 research on AI browsers** that the research report mentions without a link.
- **Reporting routes outside the UK.**
- **Topics not covered at all:** ransomware response, lost or stolen devices, cloud misconfiguration, legal duties beyond the CRA's reporting deadlines.
