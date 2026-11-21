# Exposure detection building blocks (non-LLM): vulnerability feeds, SCA/SBOM scanners, continuous SBOM monitoring, reachability, live-exposure checks, VEX tooling, and MCP wrappers

Scope: deterministic tools and open data an AI incident-response agent would call in stage 1 ("ingest the advisory") and stage 2 ("assess exposure"), plus the VEX formats used in stage 5. Stage codes used below: **S1** ingest, **S2a** dependency/version match, **S2b** reachability, **S2c** deployed/config/runtime exposure, **S5** report (VEX).
Verification: every GitHub repo below was checked on 2026-11-21 with `gh api repos/OWNER/REPO --jq '{full_name,stargazers_count,pushed_at,license:.license.spdx_id,archived,description}'` (plus `language`). Stars, last push, license (as GitHub returns it) and archived status come from that call. "Stale" means no push for 12+ months, i.e. before 2025-11-21. Where GitHub returned a redirect (the repo was renamed or moved), both names are given. Latest release tags come from `gh api repos/OWNER/REPO/releases`.

## 1. Vulnerability intelligence and alert sources: which open feeds and alerting projects exist, how are they accessed, which push and which must be polled, with what latency?

### Takeaway
The open data layer is rich but almost entirely **pull-based**. OSV.dev (API plus GCS dumps with a reverse-chronological `modified_id.csv`), the GitHub Advisory Database (REST, filterable by `affects`, `type=malware` and EPSS), CVE List V5 (git, refreshed about every 7 minutes), CISA KEV (JSON/CSV) and the EPSS API all have to be polled. The real push triggers are: GitHub webhooks (`security_advisory` for GitHub Apps only, `dependabot_alert` per repo or org), email/webhook alerts from OpenCVE and CIRCL Vulnerability-Lookup watchlists, and Dependency-Track notifications (section 3). In 2026, NVD enrichment is no longer universal: since April 2026 most CVEs are "Not Scheduled" and get no NVD CVSS or CPE. That makes package-native data (OSV/GHSA purl ranges) plus CNA data, CISA ADP (Vulnrichment), KEV and EPSS the dependable inputs.

### Cited Findings

**Inventory (metadata verified via gh api, 2026-11-21)**

| Repo | One-line purpose | Stage | Interface | Output | Lang | License (gh) | Stars | Last push | Archived |
|---|---|---|---|---|---|---|---|---|---|
| [google/osv.dev](https://github.com/google/osv.dev) | OSV aggregated open-source vulnerability DB and API | S1, S2a | REST API + GCS bulk dumps | OSV JSON | Go | Apache-2.0 | 3,079 | 2026-11-20 | no |
| [ossf/osv-schema](https://github.com/ossf/osv-schema) | OSV format spec | S1 | spec / JSON schema | OSV JSON | Go | Apache-2.0 | 279 | 2026-11-19 | no |
| [github/advisory-database](https://github.com/github/advisory-database) | GitHub Advisory DB (GHSA) as git files | S1 | git; REST `/advisories`; webhooks | OSV JSON | n/a | CC-BY-4.0 | 2,564 | 2026-11-21 | no |
| [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) | Cache of the official CVE List | S1 | git, `deltaLog.json` | CVE JSON 5.x | n/a | none returned (CVE Terms of Use) | 3,301 | 2026-11-21 | no |
| [CVEProject/cvelist](https://github.com/CVEProject/cvelist) | Legacy CVE submission pilot | none | n/a | n/a | n/a | none | 1,489 | 2025-06-03 | **yes (archived)** |
| [cisagov/vulnrichment](https://github.com/cisagov/vulnrichment) | CISA ADP enrichment: SSVC, CWE, CVSS | S1 | git; also inside CVE records | CVE JSON 5 ADP container | n/a | CC0-1.0 | 888 | 2026-11-21 | no |
| [cisagov/kev-data](https://github.com/cisagov/kev-data) | GitHub mirror of the CISA KEV catalog | S1 | git / raw files | JSON, CSV, JSON schema | HTML | NOASSERTION (LICENSE text: CC0 1.0) | 149 | 2026-11-20 | no |
| [fkie-cad/nvd-json-data-feeds](https://github.com/fkie-cad/nvd-json-data-feeds) | Community rebuild of the legacy NVD JSON feeds | S1 | git, daily releases | NVD JSON | Shell | none returned | 258 | 2026-11-21 | no |
| [opencve/opencve](https://github.com/opencve/opencve) | CVE watch and alerting platform | S1 | Web UI, email/webhook alerts (SaaS or self-hosted) | n/a | Python | NOASSERTION (LICENSE text: Business Source License 1.1) | 2,973 | 2026-11-16 | no |
| [vulnerability-lookup/vulnerability-lookup](https://github.com/vulnerability-lookup/vulnerability-lookup) (old name: cve-search/vulnerability-lookup, redirects) | CIRCL multi-source vulnerability correlator | S1 | REST API, RSS/Atom, email/webhook watchlists, NDJSON dumps | JSON / NDJSON | Python | AGPL-3.0 | 616 | 2026-11-20 | no |
| [cve-search/cve-search](https://github.com/cve-search/cve-search) | Local CVE/CPE search (MongoDB) | S1 | CLI, web UI, web API | CSV and others via `-o` | Python | AGPL-3.0 | 2,677 | 2026-11-14 | no |
| [projectdiscovery/vulnx](https://github.com/projectdiscovery/vulnx) (old name: projectdiscovery/cvemap, redirects) | CVE search CLI with KEV/EPSS/PoC/Nuclei-template filters | S1, S2c | CLI (queries ProjectDiscovery's service; a free key lifts the rate limits) | JSON, CSV | Go | MIT | 2,752 | 2026-11-21 | no |
| [aboutcode-org/vulnerablecode](https://github.com/aboutcode-org/vulnerablecode) | PURL-keyed open vulnerability DB | S1, S2a | Web UI + API | API responses (format not checked) | Python | Apache-2.0 | 719 | 2026-11-19 | no |
| [ossf/malicious-packages](https://github.com/ossf/malicious-packages) | Reports of malicious OSS packages | S1 | git | OSV JSON | Go | Apache-2.0 | 643 | 2026-11-21 | no |
| [pypa/advisory-database](https://github.com/pypa/advisory-database) | PyPI advisories | S1 | git | advisory files | Shell | CC-BY-4.0 | 379 | 2026-11-20 | no |
| [rustsec/advisory-db](https://github.com/rustsec/advisory-db) | RustSec advisories for crates.io | S1 | git | advisory files | n/a | NOASSERTION (LICENSE text: CC0 1.0) | 1,207 | 2026-11-21 | no |
| [golang/vulndb](https://github.com/golang/vulndb) | Go vulnerability DB (mirror) | S1 | git / vuln DB | advisory files | Go | NOASSERTION (BSD-style text) | 612 | 2026-11-17 | no |
| [anchore/vunnel](https://github.com/anchore/vunnel) | Collects vulnerability data to build the Grype DB | S1 | CLI | n/a | Python | Apache-2.0 | 137 | 2026-11-19 | no |

**OSV.dev (API and dumps)**
- Endpoints: `POST /v1/query` (a package at a version or commit), `POST /v1/querybatch`, `GET /v1/vulns/{id}`. Experimental: `POST /v1experimental/determineversion` (C/C++ version guessing), `GET /v1experimental/importfindings`, `POST /v1experimental/ubuntu/binary-to-source`. OpenAPI spec at osv.dev/docs/osv_service_v1.swagger.json — [OSV API docs](https://google.github.io/osv.dev/api/)
- Rate limits: "Currently there are no limits on the API." Responses are capped at 32 MiB over HTTP/1.1, with no cap over HTTP/2 — [OSV API docs](https://google.github.io/osv.dev/api/)
- Bulk data: `gs://osv-vulnerabilities/all.zip`, per-ecosystem `<ECOSYSTEM>/all.zip` (e.g. https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip), and per-record `<ECOSYSTEM>/<ID>.json`. Exports run "continuously" (no interval given). `modified_id.csv` (top-level and per ecosystem) is sorted in reverse chronological order, so a poller can stop once it reaches an already-seen timestamp. There is no push or webhook mechanism — [OSV data docs](https://google.github.io/osv.dev/data/)
- Direct sources include GitHub Advisory DB, PyPI, Go, RustSec, OpenSSF Malicious Packages, OSS-Fuzz, Ubuntu, Red Hat, Chainguard/Wolfi, Bitnami, Android, Curl, Docker Hardened Images and others. Debian, Alpine and NVD CVEs for open-source software are converted by OSV.dev itself. OSV stopped exporting prefixed ecosystems (e.g. `Alpine:.*`) — [OSV data docs](https://google.github.io/osv.dev/data/)

**GitHub Advisory Database, REST API and webhooks**
- Advisories are stored in OSV format in the repo, and NVD is among the listed upstream sources — [github/advisory-database README](https://github.com/github/advisory-database)
- `GET /advisories`: `type` = `reviewed` (default) / `malware` / `unreviewed`, and malware is excluded unless `type=malware`. Also filters on `ecosystem` (npm, pip, maven, nuget, composer, go, rust, erlang, actions, pub, swift, rubygems, other), `affects` (up to 1,000 packages or `package@version`), `modified` / `published` / `updated` date ranges, `epss_percentage` / `epss_percentile`, `cve_id`, `ghsa_id`, `severity`, `cwes`, `is_withdrawn`. `per_page` goes up to 100 with cursor pagination. No specific rate limit is stated (422/429 codes) — [GitHub REST docs](https://docs.github.com/en/rest/security-advisories/global-advisories)
- Webhook `security_advisory`: availability **GitHub App only**, actions `published`, `updated`, `withdrawn` — [GitHub webhook docs](https://docs.github.com/en/webhooks/webhook-events-and-payloads)
- Webhook `dependabot_alert`: availability repository, organization, app (needs the "Dependabot alerts" read permission). Actions: `assignees_changed`, `auto_dismissed`, `auto_reopened`, `created`, `dismissed`, `fixed`, `reintroduced`, `reopened`, `withdrawn` — [GitHub webhook docs](https://docs.github.com/en/webhooks/webhook-events-and-payloads)
- `repository_vulnerability_alert` is "closing down"; use `dependabot_alert` instead. `code_scanning_alert` is available to repo, org and app — [GitHub webhook docs](https://docs.github.com/en/webhooks/webhook-events-and-payloads)

**CVE List V5, CISA Vulnrichment and KEV**
- cvelistV5 is "updated regularly (about every 7 minutes) using the official CVE Services API". `deltaLog.json` normally keeps a rolling 30 days of changes. Legacy CSV/HTML/XML/CVRF downloads ended 2024-06-30. Records carry a CNA container, an optional CVE Program (ADP) container and a CISA-ADP container — [cvelistV5 README](https://github.com/CVEProject/cvelistV5)
- Recent format changes noted in the README: CVE Record Format 5.2.0 / CVE Services 2.6.0 (announced 2025-10-29), and a record date normalization pass from 2026-02-16 to 2026-02-28 that temporarily cut deltaLog retention to 15 days — [cvelistV5 README](https://github.com/CVEProject/cvelistV5)
- Vulnrichment: CISA scores new and recent CVEs with three SSVC decision points (Exploitation: none/poc/active, Automatable, Technical Impact). It adds CWE and/or CVSS where the CNA did not supply them, never overwrites CNA data, and pushes results back into CVE records through the ADP program — [cisagov/vulnrichment](https://github.com/cisagov/vulnrichment)
- KEV is published as JSON + CSV + JSON schema. The GitHub mirror updates shortly after cisa.gov, "typically ... weekdays during normal US Eastern business hours", and the two are synchronized "within minutes of each other". KEV additions now rest on the authority of **BOD 26-04** ("Prioritizing Security Updates Based on Risk") — [cisagov/kev-data](https://github.com/cisagov/kev-data)

**NVD API and the 2026 enrichment change**
- Rate limits: 5 requests per rolling 30 s without an API key, 50 per rolling 30 s with a key. An NVD workflow guide recommends sleeping about 6 s between requests — [NVD Start Here](https://nvd.nist.gov/developers/start-here) (figures confirmed through search results; the page did not render for WebFetch)
- April 2026: NIST moved to risk-based enrichment. Only CVEs in CISA KEV, software used by the federal government, and EO 14028 "critical software" get enriched. Everything else is "Not Scheduled", with no NVD CVSS and no CPE. The pre-March-2026 backlog is being moved to Not Scheduled. NIST no longer adds its own CVSS when the CNA has provided one. Users can request enrichment of specific CVEs at nvd@nist.gov. Brian Martin's count: the visible backlog fell from over 33,000 to about 4,000, with about 29,000 moved to Not Scheduled. NIST says CVE submissions rose 263% between 2020 and 2025 — [Socket blog, 2026-04-17](https://socket.dev/blog/nist-officially-stops-enriching-most-cves) (links NIST's announcement at https://www.nist.gov/news-events/news/2026/04/nist-updates-nvd-operations-address-record-cve-growth, which I did not read directly)
- fkie-cad/nvd-json-data-feeds syncs with NVD every 2 hours and publishes release packages daily at 00:00 UTC. It is "neither endorsed nor certified by the NVD" — [fkie-cad/nvd-json-data-feeds](https://github.com/fkie-cad/nvd-json-data-feeds)

**CVE program funding**
- After MITRE disclosed in April 2025 that its contract would lapse, CISA issued an emergency 11-month extension. On 2026-03-09 CSO Online reported that CISA and MITRE had renegotiated the contract to remove the expiration. Per sources, the program moved to a protected line in CISA's budget, and the CVE Board was told on 2026-01-21 there would be "no funding cliff in March". Contract terms were not disclosed, and a FOIA request had gone unanswered — [CSO Online, 2026-03-09](https://www.csoonline.com/article/4142600/cve-program-funding-secured-easing-fears-of-repeat-crisis.html)
- Vulnerability-Lookup lets an organization act as a GNA and publish **GCVE** identifiers in the decentralized Global CVE Allocation System, "no MITRE dependency". It also runs db.gcve.eu — [vulnerability-lookup README](https://github.com/vulnerability-lookup/vulnerability-lookup)

**FIRST EPSS API**
- Base URL `https://api.first.org/data/v1/epss`, status BETA. Parameters: `cve` (comma-separated, up to 2,000 chars), `date` (historic scores since 2021-04-14), `days`, `epss-gt`/`epss-lt`, `percentile-gt`/`percentile-lt`, `q`, `scope=public|time-series` (last 30 days). JSON envelope with `total`/`offset`/`limit` (sample shows limit 100) and `data[{cve, epss, percentile, date}]` — [api.first.org/epss](https://api.first.org/epss)

**Alerting platforms and search tools**
- OpenCVE aggregates MITRE, NVD, Red Hat and Vulnrichment data. You can filter by vendor, product, CVSS, KEV, EPSS and CWE, subscribe to vendors and products, and get alerts "instantly via email or webhook" (Slack and Teams "coming soon"), plus daily per-project reports. Available as SaaS (opencve.io) or self-hosted with Docker. Latest release v3.1.0 (2026-08-14) — [opencve/opencve](https://github.com/opencve/opencve)
- Vulnerability-Lookup: public instances at vulnerability.circl.lu and db.gcve.eu. Feeders include the NVD API 2.0 (with the FKIE feeds) and CNVD. Features: KEV catalogs (CISA, ENISA), watchlists with email or webhook reports, RSS/Atom feeds, enrichment from EPSS, Vulnrichment and vendor VEX (Red Hat, Microsoft, SUSE), a REST API with cross-source correlation, and NDJSON dumps. Latest release v7.0.0 (2026-11-16) — [vulnerability-lookup README](https://github.com/vulnerability-lookup/vulnerability-lookup)
- cve-search imports CVE/CPE into MongoDB for local search (CLI, web UI, web API). CIRCL's public cve.circl.lu service "has since been superseded by Vulnerability-Lookup" — [cve-search README](https://github.com/cve-search/cve-search)
- vulnx (renamed from cvemap: `gh api repos/projectdiscovery/cvemap` resolves to projectdiscovery/vulnx). Query DSL such as `vulnx search "is_kev:true && age_in_days:<90"`, `epss_score:>0.8`, `is_poc:true`, `is_template:true` (a Nuclei template exists), with 69 filter fields, `--json` and CSV output, and `vulnx id CVE-... --json`. It works without a key but is rate-limited; a free API key from cloud.projectdiscovery.io removes the limits. v2.0.0 released 2026-03-25 — [projectdiscovery/vulnx](https://github.com/projectdiscovery/vulnx)
- VulnerableCode is a PURL-keyed vulnerability DB with a Web UI and API, and a public instance at public.vulnerablecode.io — [aboutcode-org/vulnerablecode](https://github.com/aboutcode-org/vulnerablecode)
- OpenSSF Malicious Packages publishes malicious-package reports in OSV format, and OSV.dev ingests them as a direct source — [ossf/malicious-packages](https://github.com/ossf/malicious-packages); [OSV data docs](https://google.github.io/osv.dev/data/)

### Inferences
- **Push or poll for the agent's trigger:** the only first-party push for *new advisories* is a GitHub App subscribed to `security_advisory`. For *"this hits my repo"* there is `dependabot_alert` (repo/org webhooks, no App needed). Everything else needs a poller. The cheapest incremental pollers are OSV `modified_id.csv` (stop at the last-seen timestamp), cvelistV5 `deltaLog.json` (about 7-minute freshness), the KEV JSON (weekday cadence), and GHSA `GET /advisories?modified=>...`. Vulnerability-Lookup or OpenCVE webhooks are a self-hostable push layer for vendor/product watchlists (CPE-style, not SBOM-aware).
- **Supply-chain compromise signals:** GHSA `type=malware` (not returned by default) and OpenSSF malicious-packages (MAL- records via OSV) are the open sources. Socket's `threat_feed` (section 7) is commercial.
- **Impact of the NVD change:** CPE-keyed matching (cve-search, OpenCVE vendor/product subscriptions, OWASP dependency-check, the Vuls CPE mode) will silently miss more 2026 CVEs, because "Not Scheduled" CVEs have no CPE. For OSS dependencies, purl/ecosystem ranges from OSV/GHSA are the safer join key. For severity, read the CNA CVSS plus CISA-ADP SSVC from the CVE record, then KEV and EPSS.
- **Hackathon reuse:** poll OSV + GHSA + KEV + EPSS into a small normalizer that emits OSV JSON. That keeps one schema across ecosystems, and osv-scanner, OSV-format DBs and GUAC all speak it. Use vulnx as a quick CLI enrichment tool (KEV/EPSS/PoC/template flags in one call).
- **How a hackathon team could reuse each source:**
  - OSV.dev: send the SBOM's purls to `querybatch` for matching, and poll `modified_id.csv` for new advisories.
  - GHSA REST: `affects=` checks up to 1,000 `package@version` strings in one call, and `type=malware` gives supply-chain signals. A GitHub App with `security_advisory` gives a push trigger.
  - cvelistV5: pull and read `deltaLog.json` for CNA data plus CISA-ADP SSVC.
  - KEV JSON and the EPSS batch query (`cve=a,b,c`): prioritization and escalation flags.
  - fkie-cad feeds: an offline NVD snapshot that avoids NVD rate limits.
  - OpenCVE or Vulnerability-Lookup (self-hosted, or vulnerability.circl.lu): webhook or RSS watchlists for non-package products such as appliances or SaaS.
  - OpenSSF malicious-packages: match lockfiles against MAL- records during compromise incidents.
  - VulnerableCode: an alternative purl-keyed lookup.

### Gaps
- No documented publish-latency SLA was found for GitHub reviewed advisories or for OSV exports ("continuously" only).
- The EPSS page I fetched does not state update cadence, rate limits or the bulk CSV URL. Daily scoring is implied by the per-day `date` field and the 30-day time series, but I did not confirm it.
- I found no push or email mechanism for KEV in the sources reviewed (polling the JSON or the GitHub mirror is documented).
- The terms of the post-March-2026 CVE program contract are undisclosed. I did not research ENISA's EUVD API.
- I did not verify the GitHub GraphQL `securityVulnerabilities` API in this pass.

## 2. Scanners and SBOM tools: invocation, machine-readable output, VEX input/output

### Takeaway
The "is the vulnerable package present at an affected version?" step (S2a) is commodity and well-served. syft or cdxgen produce the SBOM (CycloneDX/SPDX), and osv-scanner, grype or trivy match it (all three emit JSON and SARIF; osv-scanner and grype also emit CycloneDX). Ecosystem-native auditors (pip-audit, cargo-audit, npm audit, govulncheck) are good secondary confirmers. On VEX: **Trivy consumes OpenVEX and CSAF (CycloneDX VEX only for SBOM targets)** and **Grype consumes VEX via `--vex`** (OpenVEX). **govulncheck emits OpenVEX** and **dep-scan emits CSAF VEX and CycloneDX VDR**. osv-scanner documents no VEX support (it uses its own ignore file), but it has call analysis and an MCP server.

### Cited Findings

**Inventory (metadata verified via gh api, 2026-11-21)**

| Repo | One-line purpose | Stage | Interface | Ecosystems | Output | Lang | License (gh) | Stars | Last push | Archived |
|---|---|---|---|---|---|---|---|---|---|---|
| [google/osv-scanner](https://github.com/google/osv-scanner) | OSV-backed SCA scanner (source + containers) | S2a, S2b | CLI (`scan source`, `scan image`, `fix`, `experimental-mcp`), GitHub Action | 13 language ecosystems via lockfiles, plus container artifacts | table, markdown, vertical, html, json, sarif, spdx-2-3, cyclonedx-1-4…1-7 | Go | Apache-2.0 | 11,579 | 2026-11-20 | no |
| [google/osv-scalibr](https://github.com/google/osv-scalibr) | SCA library (inventory extraction + detection) behind osv-scanner | S2a | Go library | many | Go structs | Go | Apache-2.0 | 665 | 2026-11-21 | no |
| [aquasecurity/trivy](https://github.com/aquasecurity/trivy) | All-in-one scanner (vulns, misconfig, secrets, SBOM) | S2a, S2c | CLI (`image`, `fs`, `repo`, `vm`, `k8s`, `sbom`) | OS + language packages | table, json, sarif, template, github, plus SBOM formats (on a linked page I did not read) | Go | Apache-2.0 | 39,586 | 2026-11-20 | no |
| [anchore/grype](https://github.com/anchore/grype) | Vulnerability scanner for images, filesystems, SBOMs | S2a | CLI, Go library | OS + language packages | json, table, cyclonedx, cyclonedx-json, sarif, template | Go | Apache-2.0 | 13,310 | 2026-11-20 | no |
| [anchore/syft](https://github.com/anchore/syft) | SBOM generator | S2a | CLI, Go library | dozens (apk, dpkg, RPM, Go, Python, Java, JS, Ruby, Rust, PHP, .NET…) | CycloneDX, SPDX, Syft JSON (+ in-toto attestations) | Go | Apache-2.0 | 9,942 | 2026-11-20 | no |
| [cdxgen/cdxgen](https://github.com/cdxgen/cdxgen) (old name: CycloneDX/cdxgen, redirects) | CycloneDX BOM generator (SBOM/OBOM/SaaSBOM) with evidence | S2a, S2b | CLI, library, REPL, server | many languages + images | CycloneDX JSON 1.6/1.7/2.0 (downgrade to 1.4/1.5), SPDX 3.0.1 JSON-LD | JavaScript | Apache-2.0 | 1,127 | 2026-11-20 | no |
| [owasp-dep-scan/dep-scan](https://github.com/owasp-dep-scan/dep-scan) (old name: AppThreat/dep-scan, redirects) | SCA + reachability + VDR/VEX generator | S2a, S2b, S5 | CLI (`depscan scan`, `validate`) | 7 ecosystems for reachability | CycloneDX VDR, CSAF 2.0/2.1 VEX, reports | Python | MIT | 1,462 | 2026-11-20 | no |
| [pypa/pip-audit](https://github.com/pypa/pip-audit) | Python dependency auditor | S2a | CLI | PyPI | columns, json, cyclonedx-json, cyclonedx-xml, markdown | Python | Apache-2.0 | 1,409 | 2026-11-19 | no |
| [rustsec/rustsec](https://github.com/rustsec/rustsec) (contains cargo-audit) | RustSec tooling incl. `cargo audit` | S2a | CLI (`cargo audit`, `cargo audit bin`, `cargo audit fix`) | crates.io | see Gaps | Rust | NOASSERTION | 1,991 | 2026-11-20 | no |
| [golang/vuln](https://github.com/golang/vuln) (govulncheck) | Official Go vuln DB client + govulncheck | S2a, S2b, S5 | CLI, Go API | Go | text, `-json`, `-format sarif`, `-format openvex` | Go | BSD-3-Clause | 536 | 2026-11-17 | no |
| [npm/cli](https://github.com/npm/cli) (npm audit) | npm package manager, incl. `npm audit` | S2a | CLI | npm | `--json` | JavaScript | NOASSERTION | 10,270 | 2026-11-19 | no |
| [semgrep/semgrep](https://github.com/semgrep/semgrep) | Static analysis; Supply Chain via AppSec Platform; `semgrep mcp` | S2a, S2b | CLI, MCP | many | not verified here | C (as GitHub reports) | LGPL-2.1 | 17,870 | 2026-11-20 | no |
| [future-architect/vuls](https://github.com/future-architect/vuls) | Agentless host/container/library scanner | S2a, S2c | CLI (remote SSH, local, server mode HTTP) | Linux, FreeBSD, containers, WordPress, libraries, network devices | JSON (server mode), reports, Slack | Go | GPL-3.0 | 12,359 | 2026-11-21 | no |
| [dependency-check/DependencyCheck](https://github.com/dependency-check/DependencyCheck) | OWASP dependency-check SCA | S2a | not verified here | not verified here | not verified here | Java | Apache-2.0 | 7,778 | 2026-11-20 | no |
| [jeremylong/DependencyCheck](https://github.com/jeremylong/DependencyCheck) | Old location of the above | none | n/a | n/a | n/a | Java | Apache-2.0 | 56 | 2025-09-27 | **yes (archived, moved)** |
| [microsoft/sbom-tool](https://github.com/microsoft/sbom-tool) | SPDX 2.2 SBOM generator | S2a | CLI | many artifacts | SPDX 2.2 | C# | MIT | 2,097 | 2026-09-21 | no |
| [CycloneDX/cyclonedx-cli](https://github.com/CycloneDX/cyclonedx-cli) | SBOM analysis, merging, diffs, conversion | S2a | CLI | n/a | CycloneDX / conversions | C# | Apache-2.0 | 564 | 2026-10-19 | no |
| [oss-review-toolkit/ort](https://github.com/oss-review-toolkit/ort) | Software compliance automation suite | S2a | CLI | many | reports | Kotlin | Apache-2.0 | 2,125 | 2026-11-20 | no |
| [DataDog/guarddog](https://github.com/DataDog/guarddog) | Detects malicious PyPI and npm packages | S1, S2a | CLI | PyPI, npm | n/a | Python | Apache-2.0 | 1,264 | 2026-11-16 | no |
| [snyk/cli](https://github.com/snyk/cli) | Snyk CLI (needs the commercial Snyk service) | S2a | CLI, `snyk mcp` | not verified here | not verified here | TypeScript | NOASSERTION (LICENSE text: Apache-2.0) | 5,715 | 2026-11-20 | no |

**osv-scanner (v2.7.1, 2026-11-09)**
- Frontend to OSV.dev and CLI for the OSV-SCALIBR library. It scans source lockfiles and container images (layer-aware), and offers guided remediation — [osv-scanner README](https://github.com/google/osv-scanner)
- Output formats: `table` (default), `markdown`, `vertical`, `html` (also `--serve`), `json`, `sarif` (2.1.0), `spdx-2-3`, `cyclonedx-1-4`, `-1-5`, `-1-6`, `-1-7`. No VEX input or output is documented; suppression uses `osv-scanner.toml` `[[IgnoredVulns]]` — [osv-scanner output docs](https://google.github.io/osv-scanner/output/)
- Lockfiles: conan.lock, pubspec.lock, mix.lock, go.mod, cabal/stack, Gradle lockfiles, verification-metadata.xml, pom.xml, bun.lock, package-lock.json, pnpm-lock.yaml, yarn.lock, deps.json, packages.lock.json, composer.lock, Pipfile.lock, poetry.lock, requirements.txt, pdm.lock, pylock.toml, uv.lock, renv.lock, Gemfile.lock, Cargo.lock. Container artifacts: APK, dpkg, Ubuntu chiseled, Go binaries, Rust binaries (with cargo-auditable), Java uber JARs, node modules, Python wheels — [supported lockfiles](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/)
- Privacy and network: it sends package names, versions, ecosystems and file hashes to the OSV API. `--offline-vulnerabilities --download-offline-databases` scans against local DBs — [osv-scanner README](https://github.com/google/osv-scanner); [usage docs](https://google.github.io/osv-scanner/usage/)
- Guided remediation (`osv-scanner fix`, experimental) covers npm `package-lock.json` (in-place), `package.json` (relock) and Maven `pom.xml` (override). The docs warn it "can be risky when run on untrusted projects" because the package manager may run scripts — [osv-scanner README](https://github.com/google/osv-scanner)

**Trivy (v0.76.2, 2026-11-05)**
- Output formats: `table`, `json`, `sarif`, `template` (JUnit, ASFF, HTML), `github` (dependency snapshot), plus SBOM formats on a linked page — [Trivy reporting docs](https://trivy.dev/latest/docs/configuration/reporting/)
- VEX (experimental) via `--vex` with `repo` (VEX repository), a local file, `oci` (VEX attestation) or `sbom-ref`. When several sources are given, order sets priority — [Trivy VEX docs](https://trivy.dev/latest/docs/supply-chain/vex/)
- Local VEX support: OpenVEX and CSAF for image, filesystem, repo, VM, Kubernetes and SBOM targets. CycloneDX VEX for **SBOM targets only**, and only as an independent VEX BOM with BOM-Link `affects.ref`. Filtering is tied to `not_affected`. CSAF relationship categories are all treated as "depends_on". Without a statement, a package is assumed affected — [Trivy local VEX docs](https://trivy.dev/latest/docs/supply-chain/vex/file/)
- [aquasecurity/vexhub](https://github.com/aquasecurity/vexhub) (40 stars, Apache-2.0, last push 2026-03-23, not archived) collects OpenVEX or CSAF documents from the source repos of registered OSS projects, keyed by PURL — [vexhub README](https://github.com/aquasecurity/vexhub)

**Grype (v0.122.1) and Syft (v1.57.2)**
- Grype: EPSS, KEV and risk-score prioritization; "OpenVEX support for filtering and augmenting scan results"; scans SBOMs (`grype sbom:./sbom.json` or stdin) — [grype README](https://github.com/anchore/grype)
- Grype `-o` formats: json, table, cyclonedx, cyclonedx-json, sarif, template. `embedded-cyclonedx-vex-json/xml` are deprecated. `--vex` takes "a list of VEX documents to consider when producing scanning results" — [Grype CLI reference](https://oss.anchore.com/docs/reference/grype/cli/) (quoted via search results)
- Syft: SBOMs for images, filesystems and archives; CycloneDX, SPDX and Syft JSON output with format conversion; signed in-toto attestations; e.g. `syft <image> -o spdx-json=./spdx.json -o cyclonedx-json=./cdx.json` — [syft README](https://github.com/anchore/syft)

**cdxgen and dep-scan**
- cdxgen is a CLI, library, REPL and server. It emits CycloneDX JSON (spec 1.6, 1.7, 2.0, downgradable to 1.4/1.5) and SPDX 3.0.1 JSON-LD (`--format spdx`). Profiles such as `--profile appsec --evidence --bom-audit`, plus OBOM/SaaSBOM generation. Both v12.9.x and v13.8.x release lines were active in Nov 2026 — [cdxgen README](https://github.com/cdxgen/cdxgen)
- dep-scan generates SBOMs with VDR data, generates CSAF 2.0/2.1 VEX, and has a `validate` subcommand for CSAF VEX or CycloneDX VDR/VEX. Reachability is on by default (details in section 4). Latest stable v6.3.2 (2026-11-12); v7.0.0a1 pre-release 2026-11-20 — [dep-scan README](https://github.com/owasp-dep-scan/dep-scan)

**Ecosystem-native auditors**
- pip-audit: `-f/--format` = columns, json, cyclonedx-json, cyclonedx-xml, markdown. Vulnerability service is PyPI or OSV (`-s`). `--fix`. Latest v2.10.1 (2026-06-10) — [pip-audit README](https://github.com/pypa/pip-audit)
- cargo-audit: `cargo audit` runs `cargo update --workspace` if Cargo.lock is missing, and Cargo can execute project code. For untrusted projects use `--file path/to/Cargo.lock` from outside the project. `cargo audit bin <paths>` audits binaries, best when built with cargo-auditable. `cargo audit fix` needs the `fix` feature — [cargo-audit README](https://github.com/rustsec/rustsec/tree/main/cargo-audit)
- govulncheck: source mode by default, `-mode binary`, `-mode extract`. `-format sarif`, `-format openvex`, streaming JSON via `-json`. `-show traces` / `-show verbose`, `-db` for alternate DBs, `-tags`, `-test` — [govulncheck docs](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
- npm audit POSTs package names and versions to the registry's Bulk Advisory endpoint `/-/npm/v1/security/advisories/bulk` and falls back to the slower Quick Audit endpoint. It requires a lockfile by default. `--json`; `--audit-level` changes only the failure threshold. `npm audit fix` runs a full `npm install`. `npm audit signatures` verifies registry signatures and provenance attestations — [npm audit docs](https://docs.npmjs.com/cli/v11/commands/npm-audit)
- Vuls: agentless "Fast Scan" with almost no load on targets; remote (SSH), local and server modes (targets POST collected data over HTTP and get JSON results); KEV including VulnCheck KEV; Slack reporting; periodic cron reports. Latest v0.43.0 (2026-11-17) — [vuls README](https://github.com/future-architect/vuls)
- OWASP dependency-check moved from jeremylong/DependencyCheck (archived) to dependency-check/DependencyCheck, latest v13.0.0 (2026-08-03) — [old repo notice](https://github.com/jeremylong/DependencyCheck); [new repo](https://github.com/dependency-check/DependencyCheck)
- Semgrep: the MCP server now ships in the main binary (`semgrep mcp`). Platform features need `SEMGREP_APP_TOKEN` from the Semgrep AppSec Platform. "Semgrep Guardian" bundles the MCP server, hooks and skills and scans with "Semgrep Code, Supply Chain, and Secrets" — [Semgrep MCP README](https://github.com/semgrep/semgrep/tree/develop/cli/src/semgrep/mcp)

### Inferences
- **VEX matrix for the agent.** *Consume*: Trivy (OpenVEX and CSAF everywhere, CycloneDX VEX for SBOM scans only), Grype (`--vex`), Dependency-Track, GUAC and Trustify (section 3). *Emit*: govulncheck (OpenVEX, with call-graph evidence), dep-scan (CSAF VEX + CycloneDX VDR), vexctl (section 6). *Neither*: osv-scanner (TOML ignore list), pip-audit, cargo-audit, npm audit. A practical loop: scan, decide, write OpenVEX with vexctl, then re-run Trivy or Grype with `--vex` to prove the finding is suppressed.
- **Default hackathon pipeline:** `syft dir:. -o cyclonedx-json` (or cdxgen), then `osv-scanner scan source -r . --format json` and/or `grype sbom:bom.json -o json` (EPSS/KEV in output), then the per-language confirmer (govulncheck / pip-audit / npm audit --json). Normalize on OSV IDs and purls. Trivy is the single binary that also covers images, IaC misconfig and secrets, which helps with S2c "configured in a vulnerable way".
- **How a hackathon team could reuse each tool:**
  - osv-scanner: primary source-repo matcher, plus `experimental-mcp` for a ready MCP tool.
  - syft + grype: SBOM-first scans with EPSS/KEV columns, and re-scan with `--vex` after the verdict.
  - Trivy: container images, IaC misconfig and secrets, plus VEX filtering (including VEX Hub).
  - cdxgen: CycloneDX SBOM with evidence, uploaded to Dependency-Track.
  - dep-scan: multi-language reachability and CSAF VEX output.
  - govulncheck, pip-audit, npm audit, cargo-audit: per-ecosystem confirmation. govulncheck also gives OpenVEX for free.
  - Vuls: host or VM package inventory, if the demo includes servers.
  - GuardDog: heuristic check of a suspicious new package version in a supply-chain compromise.
  - cyclonedx-cli: SBOM diff and merge, e.g. to prove that a patch removed the vulnerable version.
  - sbom-tool: SPDX output when required.
  - OWASP dependency-check: for teams that already use it, keeping its NVD/CPE dependence in mind.
- **Safety:** several tools execute project code or package-manager scripts (osv-scanner `fix`, cargo-audit without `--file`, `npm audit fix`, Snyk's SCA scan, dep-scan's Go analyzer with cgo). An agent should run them in a sandbox and prefer lockfile-only modes on untrusted repos.
- Semgrep Supply Chain reachability appears to need the commercial AppSec Platform token; the OSS CLI and MCP alone do not provide SCA reachability. This is inferred from the README's platform/token section, not stated explicitly.

### Gaps
- I did not confirm cargo-audit's JSON flag from its README (the grep found no JSON mention); check `cargo audit --help`.
- Trivy's VEX *output* capability and the exact SBOM `--format` values (cyclonedx, spdx, spdx-json) were not on the pages fetched.
- Grype's support for CSAF/CycloneDX VEX (versus OpenVEX only) is not stated in the README.
- npm/cli's license shows as NOASSERTION; I did not inspect the file.

## 3. Continuous exposure monitoring across many projects: how do portfolio tools notify when a new vulnerability affects an existing SBOM?

### Takeaway
**Dependency-Track** is the clear open-source choice for "tell me when a new CVE hits any SBOM I've uploaded". v5 is GA (5.2.2 released 2026-11-18). v4 reaches end of life in December 2026, about 6 months after v5 GA. Its notifications (NEW_VULNERABILITY, NEW_VULNERABLE_DEPENDENCY, VEX_CONSUMED/PROCESSED, VULNERABILITY_RETRACTED and more) go to Webhook, Slack, Teams, Mattermost, Webex, Jira, Email or Kafka, with project/tag scoping and CEL filter expressions. That makes it a ready push trigger for the agent. **GUAC** and **Trustify** answer "which artifacts are affected by CVE X?" through GraphQL/REST, but they are query-driven: GUAC's OSV certifier polls, and I found no notification layer for either. GitHub Dependabot is the hosted equivalent with `dependabot_alert` webhooks.

### Cited Findings

| Repo | One-line purpose | Stage | Interface | Formats in | Lang | License (gh) | Stars | Last push | Archived |
|---|---|---|---|---|---|---|---|---|---|
| [DependencyTrack/dependency-track](https://github.com/DependencyTrack/dependency-track) | Portfolio SBOM component analysis and notifications | S1 trigger, S2a | REST API, web UI, notification publishers | CycloneDX SBOM, VEX | Java | Apache-2.0 | 4,494 | 2026-11-20 | no |
| [DependencyTrack/hyades](https://github.com/DependencyTrack/hyades) | Incubator for v5 (merged into main repo) | none | n/a | n/a | Makefile | Apache-2.0 | 103 | 2026-05-29 | **yes (archived)** |
| [guacsec/guac](https://github.com/guacsec/guac) | Graph of SBOM/SLSA/VEX/OSV metadata | S2a | GraphQL (+REST), `guacone` CLI | SPDX, CycloneDX, SLSA, OpenVEX, CSAF VEX, OSV, deps.dev | Go | Apache-2.0 | 1,579 | 2026-11-17 | no |
| [guacsec/trustify](https://github.com/guacsec/trustify) (old name: trustification/trustify, redirects) | Vulnerability correlation engine (SBOM, advisory, VEX) | S2a, S5 | REST API (OpenAPI) + web UI | CycloneDX 1.3–1.7, SPDX, CSAF/VEX, OSV, CVE | Rust | Apache-2.0 | 90 | 2026-11-19 | no |
| [l3montree-dev/devguard](https://github.com/l3montree-dev/devguard) | SBOM, CVE and VEX management, dependency firewall (OWASP Incubator) | S2a, S5 | backend service (interfaces not checked) | SBOM, VEX | Go | NOASSERTION (custom per-file license notice) | 223 | 2026-11-20 | no |
| [aquasecurity/trivy-operator](https://github.com/aquasecurity/trivy-operator) | Continuous in-cluster scanning to K8s CRDs | S2a, S2c | Kubernetes CRDs / API | n/a | Go | Apache-2.0 | 2,011 | 2026-11-18 | no |

**Dependency-Track**
- v5 source is on `main`, v4 on `4.14.x`. Hyades was archived and "active development continues at DependencyTrack/dependency-track" — [hyades README](https://github.com/DependencyTrack/hyades)
- "v4 will reach end-of-life in December 2026, ~6 months after v5 GA". Docs live at dependencytrack.github.io/docs — [dependency-track README](https://github.com/DependencyTrack/dependency-track)
- No in-place upgrade: v5 runs on its own PostgreSQL cluster and ingests v4 data through an offline migration — [V5_MIGRATION.md](https://github.com/DependencyTrack/dependency-track/blob/main/V5_MIGRATION.md)
- v5 portfolio notification groups: BOM_CONSUMED, BOM_PROCESSED, BOM_PROCESSING_FAILED, BOM_VALIDATION_FAILED, **NEW_VULNERABILITY** ("Fires when the platform finds a new vulnerability"), **NEW_VULNERABLE_DEPENDENCY** ("Fires when a vulnerable component becomes a dependency of a project"), POLICY_VIOLATION, PROJECT_AUDIT_CHANGE, PROJECT_CREATED, **VEX_CONSUMED**, **VEX_PROCESSED**, **VULNERABILITY_RETRACTED**, NEW_VULNERABILITIES_SUMMARY, NEW_POLICY_VIOLATIONS_SUMMARY — [DT v5 docs: groups](https://github.com/DependencyTrack/docs/blob/main/docs/reference/notifications/groups.md)
- v5 publishers: Console, Email, Jira, Kafka, Mattermost, Microsoft Teams, Slack, Webex, Webhook — [DT v5 docs: publishers](https://github.com/DependencyTrack/docs/blob/main/docs/reference/notifications/publishers.md)
- Alerts subscribe to groups and can be restricted to projects or tags. An optional CEL filter expression is evaluated after the project/tag checks — [DT v5 docs: notification concepts](https://github.com/DependencyTrack/docs/blob/main/docs/concepts/notifications.md)
- v4 docs: webhooks are HTTP(S) POSTs with a JSON payload. Each NEW_VULNERABILITY notification carries one component, one vulnerability and one or more affected projects. Tag-scoped notifications exist since v4.12 — [DT v4.14 notification docs](https://docs.dependencytrack.org/integrations/notifications/)

**GUAC (v1.1.0, 2026-03-13)**
- Ingests deps.dev, OSV, SLSA, CSAF/CSAF VEX and OpenVEX among other sources. Exposes a GraphQL API that stays the same across backends. A dev-container brings up GraphQL, REST, collectsub, ingestor, NATS and the deps_dev / osv / ClearlyDefined collectors — [guac README](https://github.com/guacsec/guac)
- Workflow: `guacone collect --add-vuln-on-ingest files sbom.json` queries OSV at ingest. Because of rate limits you can instead run the polling certifier `guacone certifier osv`. Then `guacone query vuln purl "pkg:..." [--vuln-id ghsa-...]` or `guacone query vuln uri <sbom-uri>` shows whether an artifact is affected through direct or indirect dependencies — [GUAC docs: querying via CLI](https://github.com/guacsec/guac-docs/blob/main/guac/querying-via-cli.md)

**Trustify (v0.7.2, 2026-11-12)**
- Ingests CycloneDX JSON 1.3–1.7 and SPDX. Cross-references against Red Hat, GHSA, NVD and OSV advisories, with CSAF/VEX support and built-in importers for public feeds. Full REST API with OpenAPI spec plus web UI. Single binary plus PostgreSQL; "PM mode" embeds PostgreSQL but needs IPv6 with localhost resolving to `::1` — [trustify README](https://github.com/guacsec/trustify)

**Others**
- DevGuard (repo description): SBOM, CVE and VEX management, scanner integration, SLSA dependency ingestion, a dependency firewall, and attestation-based compliance; an OWASP Incubator project. Latest v1.19.2 (2026-11-20) — [devguard](https://github.com/l3montree-dev/devguard)
- Trivy Operator watches Kubernetes state changes and triggers scans automatically (e.g. a vulnerability scan when a new Pod is created). Reports are CRDs reachable through the Kubernetes API, including SBOMs for workloads — [trivy-operator README](https://github.com/aquasecurity/trivy-operator)
- GitHub's hosted option: `dependabot_alert` webhooks (`created`, `reintroduced`, and so on) for repos and orgs — [GitHub webhook docs](https://docs.github.com/en/webhooks/webhook-events-and-payloads)

### Inferences
- **Recommended trigger architecture:** run Dependency-Track v5 in Docker, upload the CycloneDX SBOM from CI (cdxgen's description advertises automatic submission to Dependency-Track), and point a **Webhook** alert scoped to the demo project's tag at the agent's `/ingest` endpoint, subscribed to NEW_VULNERABILITY + NEW_VULNERABLE_DEPENDENCY + VULNERABILITY_RETRACTED. The agent gets a push event naming component, vulnerability and affected projects, then runs the S2b reachability tools. After deciding, it uploads VEX back, which raises VEX_CONSUMED/VEX_PROCESSED and closes the loop.
- GUAC or Trustify fit an "ask the graph" tool (`which_artifacts_affected(vuln_id)`) better than a trigger. Trustify (single binary, REST/OpenAPI) is probably the lighter one for a hackathon. GUAC's last release (March 2026) suggests slower cadence, although commits continue.
- Starting fresh on v4 now makes little sense with its December 2026 EOL; use v5.
- DevGuard is an alternative all-in-one (SBOM + VEX management) if the team wants a UI with VEX workflows, but its custom per-file license notice needs checking before reuse.
- Trivy Operator is the in-cluster analogue: it rescans on workload changes and exposes the reports as Kubernetes CRDs. An agent can list its vulnerability-report CRDs (I did not verify the exact CRD kind name) to answer "is the vulnerable image actually running?" (S2c).

### Gaps
- I did not verify the exact v5 webhook JSON schema (the v5 docs reference a schema page that I did not read) or whether NEW_VULNERABILITY fires on re-analysis of existing components when a mirror adds a new advisory. The wording is only "finds a new vulnerability".
- I found no documented notification or webhook capability for GUAC or Trustify.

## 4. Reachability analysis: which languages are covered, how accurate is it, and how hard is it to run?

### Takeaway
Reachability (S2b) is fragmented by language. **Go** is best served: govulncheck is official and symbol-level, and emits OpenVEX. osv-scanner wraps call analysis for **Go and Rust** (Rust runs build scripts) and added **Java JAR** reachability in v2.2.2. **dep-scan** has the broadest open coverage (Java/JVM, JS/TS, Python, PHP via atom; Rust via rusi; Go via golem; .NET via dosai) but needs the heaviest setup. **Jelly** is a research-grade JS/TS call-graph analyzer with a vulnerability-exposure mode. I found no independent accuracy figures. Every tool documents soundness gaps (reflection, dynamic dispatch, binaries).

### Cited Findings

| Repo | One-line purpose | Languages | Interface | Output | Lang | License (gh) | Stars | Last push | Archived |
|---|---|---|---|---|---|---|---|---|---|
| [golang/vuln](https://github.com/golang/vuln) | govulncheck: call-graph-filtered Go vulns | Go | CLI | text, JSON, SARIF, OpenVEX | Go | BSD-3-Clause | 536 | 2026-11-17 | no |
| [google/osv-scanner](https://github.com/google/osv-scanner) | `--call-analysis` | Go, Rust; Java JARs | CLI | as section 2 | Go | Apache-2.0 | 11,579 | 2026-11-20 | no |
| [owasp-dep-scan/dep-scan](https://github.com/owasp-dep-scan/dep-scan) | Multi-language reachability + VEX | Java/JVM, JS/TS, Python, PHP, Rust, Go, .NET | CLI | CycloneDX VDR, CSAF VEX | Python | MIT | 1,462 | 2026-11-20 | no |
| [AppThreat/atom](https://github.com/AppThreat/atom) | IR + slicer (usages/reachables/data-flow) | C/C++, Java, JS/TS, Python, PHP, Ruby, Scala (WIP), JVM bytecode | CLI, Docker | JSON slices, SARIF (memory-safety) | Scala | MIT | 105 | 2026-11-20 | no |
| [cs-au-dk/jelly](https://github.com/cs-au-dk/jelly) | JS/TS call graphs + vulnerability exposure | JavaScript/TypeScript (Node.js) | CLI, `jelly-server` (JSON over stdio) | JSON call graphs, HTML, matches/call-stack JSON | TypeScript | BSD-3-Clause | 449 | 2026-08-12 | no |
| [eclipse-steady/steady](https://github.com/eclipse-steady/steady) (old name: eclipse/steady, redirects) | Java static + dynamic reachability | Java | CLI/Maven | n/a | Java | Apache-2.0 | 548 | **2023-12-04 (stale)** | no |
| [joernio/joern](https://github.com/joernio/joern) | Code property graph platform | C/C++, Java, binary, JS, Python, Kotlin | CLI/REPL | n/a | Scala | Apache-2.0 | 3,656 | 2026-11-21 | no |

- **govulncheck**: uses "static analysis of source code or a binary's symbol table to narrow down reports to only those that could affect the application". Example output: "mypackage.main calls golang.org/x/text/language.Parse". Limits: calls through `reflect` are invisible; `unsafe` may cause false negatives; function-pointer and interface calls are analyzed conservatively (possible false positives); binary mode shows no call stacks and may report unreachable code; where symbols cannot be extracted it reports every dependency module; binaries built before Go 1.18 only get stdlib findings — [govulncheck docs](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
- **osv-scanner**: flag `--call-analysis` "Enable call analysis for specific languages (e.g. --call-analysis=go). Supported: go, rust (*). (*) Will run build scripts." and `--no-call-analysis` — [osv-scanner flags.go](https://github.com/google/osv-scanner/blob/main/cmd/osv-scanner/internal/helper/flags.go). The changelog adds Java reachability for uncalled vulnerabilities in JAR files (v2.2.2), Go call analysis for Go 1.27 projects (v2.6.0), and call-analysis info kept when diffing results (v2.7.0) — [osv-scanner CHANGELOG](https://github.com/google/osv-scanner/blob/main/CHANGELOG.md)
- **dep-scan**: reachability for seven ecosystems through four slicers feeding one purl-keyed engine. Default analyzer `FrameworkReachability`; `SemanticReachability` adds services, endpoints and post-build tiers. It asks cdxgen for the `research` BOM profile. Go via golem needs `go` on PATH and runs with cgo off (cgo packages lose reachability unless you pass `--go-analyzer-cgo` on trusted input). `--go-analyzer-network offline` is meant for untrusted repos. .NET via dosai gives an explicit per-package verdict with confidence. Example: `depscan scan ./my-java-app --bom-profile research -t java -o ./reports --explain` — [dep-scan README](https://github.com/owasp-dep-scan/dep-scan)
- **atom** (v4.0.3): slices `usages` (cdxgen's evidence of library use), `reachables` (flows from tagged sources to tagged sinks with the packages they pass through), `data-flow`, `callsites`, and `memory-safety` (C/C++, JSON or SARIF). Needs Java 23+ (except native images). JS/TS/PHP/Ruby parsers come from `@appthreat/atom-parsetools`. Docker image `ghcr.io/appthreat/atom` — [atom README](https://github.com/AppThreat/atom)
- **Jelly** (v0.13.0, 2026-05-11): call-graph construction, library usage pattern matching and "vulnerability exposure analysis" for Node.js JS/TS, building on JAM, TAPIR and ACG, with approximate interpretation (`--approx`). CLI flags: `-v, --vulnerabilities <file>` ("report vulnerability matches"), `--matches-file`, `--callstacks-json`, `--vulnerabilities-full` — [jelly src/main.ts](https://github.com/cs-au-dk/jelly). Analyzing all dependencies "can take a long time" and may need `NODE_OPTIONS=--max-old-space-size=8192`. Dynamic call graphs need NodeProf (Docker build). Server mode speaks JSON over stdin/stdout — [jelly README](https://github.com/cs-au-dk/jelly)
- **Eclipse Steady**: last push 2023-12-04, so it is stale per the gh api check — [eclipse-steady/steady](https://github.com/eclipse-steady/steady)

### Inferences
- **Agent tool mapping:** `reachability(lang, repo, vuln_id)` should dispatch to govulncheck (Go: highest confidence, and its OpenVEX output can become the VEX statement directly), `osv-scanner --call-analysis=go,rust` (Rust only in a sandbox), dep-scan with `--bom-profile research` for Java/JS/Python/PHP/.NET, and Jelly as a JS/TS second opinion. Treat "not reachable" as evidence for `not_affected` + `vulnerable_code_not_in_execute_path`, not as proof, because every tool lists unsoundness sources.
- **Difficulty ranking** (easiest first): govulncheck (one `go install`), osv-scanner call analysis (needs the language toolchain), Jelly (npm install; memory-hungry on full dependency trees), dep-scan + cdxgen + atom (Java 23+, Node, language toolchains, per-language plugins). For a 48-hour hackathon, demoing Go (govulncheck) plus one other language through dep-scan is realistic.
- Joern is a general CPG engine. You would have to write the vulnerability-specific queries yourself, so it is lower priority than atom/dep-scan, which already package them.

### Gaps
- I found no independent precision/recall benchmarks for govulncheck, osv-scanner call analysis, dep-scan or Jelly in this pass. The Jelly README cites academic papers but I did not extract their numbers.
- The format of Jelly's `--vulnerabilities` input file (defined in `src/typings/vulnerabilities.ts`) was not checked.
- Whether osv-scanner enables Go call analysis by default was not confirmed.

## 5. Live or runtime exposure (brief): when should an agent use nuclei, Kubescape or Falco to confirm an internet-facing service is exploitable?

### Takeaway
Use these only after S2a/S2b say "affected" and the asset is deployed: they answer "is the running thing actually exploitable or exposed?" **nuclei** with **nuclei-templates** (3,587 `cve`-tagged templates; 1,496 unique KEV templates) is the standard non-LLM way to probe an owned, internet-facing service for a specific CVE. vulnx's `is_template:true` filter tells the agent whether such a template exists. Kubescape and trivy-operator cover cluster workloads (image CVEs, posture). Falco covers runtime behavior detection.

### Cited Findings

| Repo | One-line purpose | Stage | Interface | Lang | License (gh) | Stars | Last push | Archived |
|---|---|---|---|---|---|---|---|---|
| [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) | YAML-DSL vulnerability scanner (apps, APIs, networks, DNS, cloud config) | S2c | CLI | Go | MIT | 33,163 | 2026-11-21 | no |
| [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | Community templates incl. CVE/KEV checks | S2c | YAML templates | JavaScript | MIT | 13,379 | 2026-11-21 | no |
| [kubescape/kubescape](https://github.com/kubescape/kubescape) | Kubernetes security: posture, image CVEs, runtime | S2c | CLI, operator | Go | Apache-2.0 | 11,967 | 2026-11-20 | no |
| [falcosecurity/falco](https://github.com/falcosecurity/falco) | Cloud-native runtime security | S2c | daemon + rules | C++ | Apache-2.0 | 9,594 | 2026-11-20 | no |

- nuclei v3.11.1 (2026-08-08): "fast, customizable vulnerability scanner ... built on a simple YAML-based DSL" for applications, APIs, networks, DNS and cloud configurations — [nuclei repo](https://github.com/projectdiscovery/nuclei)
- nuclei-templates KEV coverage: 454 templates for CISA KEV, 1,449 for VulnCheck KEV, 1,496 unique KEV templates in total (`nuclei -tags kev,vkev`). The top-tag table shows `cve` with 3,587 templates. Stats are also published as TEMPLATES-STATS.json for integrations — [nuclei-templates README](https://github.com/projectdiscovery/nuclei-templates)
- vulnx can filter on `is_template:true` / `--template` (has Nuclei templates), `is_poc:true` and `is_remote:true` — [vulnx README](https://github.com/projectdiscovery/vulnx)
- Kubescape v4.0.21: image vulnerability scanning using Grype (an offline Grype DB server is supported), image patching via Copacetic, and eBPF-based runtime monitoring via Inspektor Gadget — [kubescape README](https://github.com/kubescape/kubescape)
- Falco 0.45.2 (2026-10-29), described as "Cloud Native Runtime Security" — [falco repo](https://github.com/falcosecurity/falco)

### Inferences
- **When to call:** (a) a KEV or high-EPSS CVE affects a component of an internet-facing service, and vulnx shows `is_template:true`: run that CVE's nuclei template against **owned, authorized** targets only (templates are tagged `cve`; `nuclei -tags kev,vkev` is the documented KEV sweep). A match upgrades the verdict to "exploitable" (CycloneDX `exploitable`). (b) In Kubernetes, use trivy-operator/Kubescape reports to confirm the vulnerable image is actually running. (c) Falco alerts are evidence of attempted exploitation and belong to escalation, not exposure detection.
- A negative nuclei result is weak evidence (the template may not cover every configuration), so it should not on its own justify `not_affected`.

### Gaps
- I did not verify Kubescape's runtime "relevancy" CVE filtering (filtering image CVEs to packages loaded at runtime) in this pass, or Falco's rule coverage for specific CVEs.

## 6. VEX and advisory standards tooling: which statuses and justifications make VEX a natural output for an "are we exposed?" verdict?

### Takeaway
All three VEX dialects encode exactly the agent's verdict space: **not affected (with a machine-readable reason), affected (with an action), fixed, under investigation**. OpenVEX is the leanest: 4 statuses, 5 justifications, `vexctl create/merge/validate/attest`. CycloneDX VEX is the richest: 6 analysis states, 9 justifications, 5 response types. CSAF VEX is the most formal and the vendor/regulatory standard: product-status buckets plus 5 flag labels identical to OpenVEX's justifications. Trivy, Grype, Dependency-Track, GUAC and Trustify can consume the output, so the agent's verdict can directly suppress or annotate scanner results.

### Cited Findings

| Repo | One-line purpose | Stage | Interface | Lang | License (gh) | Stars | Last push | Archived |
|---|---|---|---|---|---|---|---|---|
| [openvex/spec](https://github.com/openvex/spec) | OpenVEX specification | S5 | spec | n/a | CC0-1.0 | 203 | 2026-10-30 | no |
| [openvex/vexctl](https://github.com/openvex/vexctl) | Create, merge, validate, attest OpenVEX | S5 | CLI | Go | Apache-2.0 | 222 | 2026-11-20 | no |
| [openvex/go-vex](https://github.com/openvex/go-vex) | Go module to generate and transform VEX | S5 | Go library | Go | Apache-2.0 | 74 | 2026-11-19 | no |
| [CycloneDX/specification](https://github.com/CycloneDX/specification) | CycloneDX spec (SBOM, VDR, VEX) | S5 | JSON/XML schema | XSLT | Apache-2.0 | 585 | 2026-11-21 | no |
| [oasis-tcs/csaf](https://github.com/oasis-tcs/csaf) | OASIS CSAF TC artifacts and schemas | S5 | spec + JSON schema | HTML | NOASSERTION | 231 | 2026-11-18 | no |
| [gocsaf/csaf](https://github.com/gocsaf/csaf) (moved from csaf-poc/csaf_distribution, now a stub saying "moved to https://github.com/gocsaf/csaf/") | Tools to download or provide CSAF documents | S1, S5 | CLI/servers | Go | none returned (repo ships LICENSE-Apache-2.0.txt and a LICENSES dir) | 73 | 2026-11-18 | no |
| [secvisogram/secvisogram](https://github.com/secvisogram/secvisogram) | Web editor for CSAF 2.0 advisories | S5 | web app | JavaScript | Apache-2.0 | 46 | 2026-11-19 | no |
| [aquasecurity/vexhub](https://github.com/aquasecurity/vexhub) | Aggregated OSS VEX repository (OpenVEX/CSAF) | S1, S5 | git repo | n/a | Apache-2.0 | 40 | 2026-03-23 | no |

**OpenVEX**
- Statuses: `not_affected` (requires a justification), `affected`, `fixed`, `under_investigation` — [OpenVEX spec](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md)
- Justifications: `component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path` ("product includes the vulnerable subcomponent but does not call or use the vulnerable code"), `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist` — [OpenVEX spec](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md)
- A `not_affected` statement MUST carry either a `justification` or an `impact_statement`, and free-text impact statements are "highly discouraged for automated systems". An `affected` statement MUST carry an `action_statement` — [OpenVEX spec](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md)
- vexctl (v0.4.4, 2026-06-16): `vexctl create --product=pkg:... --vuln=... --status=not_affected --justification=...`; `vexctl merge` (history across documents, e.g. `under_investigation` then `fixed`); validation that exits non-zero on errors and can report JSON (e.g. it errors when `not_affected` lacks a justification or impact statement); attesting and attaching VEX to container images — [vexctl README](https://github.com/openvex/vexctl)

**CycloneDX VEX** (from bom-1.6 schema)
- `analysis.state`: `resolved`, `resolved_with_pedigree`, `exploitable`, `in_triage`, `false_positive`, `not_affected` — [CycloneDX bom-1.6.schema.json](https://github.com/CycloneDX/specification)
- `analysis.justification`: `code_not_present`, `code_not_reachable`, `requires_configuration`, `requires_dependency`, `requires_environment`, `protected_by_compiler`, `protected_at_runtime`, `protected_at_perimeter`, `protected_by_mitigating_control` — [CycloneDX bom-1.6.schema.json](https://github.com/CycloneDX/specification)
- `analysis.response`: `can_not_fix`, `will_not_fix`, `update`, `rollback`, `workaround_available` — [CycloneDX bom-1.6.schema.json](https://github.com/CycloneDX/specification)

**CSAF 2.0 VEX** (from csaf_json_schema.json)
- `product_status` buckets: `first_affected`, `first_fixed`, `fixed`, `known_affected`, `known_not_affected`, `last_affected`, `recommended`, `under_investigation` — [CSAF 2.0 JSON schema](https://github.com/oasis-tcs/csaf)
- `flags[].label`: `component_not_present`, `inline_mitigations_already_exist`, `vulnerable_code_cannot_be_controlled_by_adversary`, `vulnerable_code_not_in_execute_path`, `vulnerable_code_not_present` — [CSAF 2.0 JSON schema](https://github.com/oasis-tcs/csaf)
- `remediations[].category`: `mitigation`, `no_fix_planned`, `none_available`, `vendor_fix`, `workaround`. `threats[].category`: `exploit_status`, `impact`, `target_set` — [CSAF 2.0 JSON schema](https://github.com/oasis-tcs/csaf)

**Producers and consumers already in the toolchain**
- govulncheck `-format openvex` — [govulncheck docs](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck); dep-scan generates and validates CSAF 2.0/2.1 VEX — [dep-scan README](https://github.com/owasp-dep-scan/dep-scan)
- Trivy consumes OpenVEX, CSAF and (SBOM only) CycloneDX VEX, and pulls VEX Hub with `--vex repo` — [Trivy VEX docs](https://trivy.dev/latest/docs/supply-chain/vex/file/); Grype `--vex` — [grype README](https://github.com/anchore/grype); Dependency-Track raises VEX_CONSUMED/VEX_PROCESSED — [DT v5 groups](https://github.com/DependencyTrack/docs/blob/main/docs/reference/notifications/groups.md); GUAC ingests OpenVEX and CSAF VEX — [guac README](https://github.com/guacsec/guac); Trustify supports CSAF/VEX — [trustify README](https://github.com/guacsec/trustify)
- Vulnerability-Lookup enriches with vendor VEX from Red Hat, Microsoft and SUSE — [vulnerability-lookup README](https://github.com/vulnerability-lookup/vulnerability-lookup)

### Inferences
- **Verdict to VEX mapping for the agent** (OpenVEX / CycloneDX / CSAF):
  - Package absent from SBOM: `not_affected` + `component_not_present` / `not_affected` + `code_not_present` / `known_not_affected` + flag `component_not_present`.
  - Present but vulnerable function never called (govulncheck / osv-scanner / dep-scan says unreachable): `not_affected` + `vulnerable_code_not_in_execute_path` / `not_affected` + `code_not_reachable` / `known_not_affected` + flag `vulnerable_code_not_in_execute_path`.
  - Present and reachable, but needs a config the project does not use: OpenVEX has no exact label, so use `vulnerable_code_cannot_be_controlled_by_adversary` or an impact statement / CycloneDX `requires_configuration` or `requires_environment` / CSAF `vulnerable_code_cannot_be_controlled_by_adversary`.
  - Reachable or confirmed (nuclei hit): `affected` + `action_statement` / `exploitable` + response `update` or `workaround_available` / `known_affected` + remediation `vendor_fix` or `workaround`.
  - Triage running: `under_investigation` / `in_triage` / `under_investigation`.
  - After the patch PR merges: `fixed` / `resolved` / `fixed`.
- **Pick OpenVEX for the hackathon:** smallest schema, a Go library (go-vex) and CLI (vexctl), consumed by both Trivy and Grype. Emit CycloneDX VEX when the SBOM pipeline is CycloneDX/Dependency-Track centric, and CSAF only if a regulatory-style advisory is required (secvisogram can be used to inspect it). OpenVEX's discouragement of free-text `impact_statement` fits the deterministic-evidence goal: LLM rationale belongs in the incident report, while the VEX carries the label.

### Gaps
- CSAF 2.1 enumerations (dep-scan supports 2.1) were not checked. The CycloneDX 1.7 schema was not diffed against 1.6.
- I did not review CISA's "Minimum Requirements for VEX" document in this pass.

## 7. Which MCP servers wrap these tools and feeds?

### Takeaway
Usable **vendor-maintained** MCP servers exist for the main building blocks:
- **GitHub** (`dependabot`, `code_security`, `secret_protection`, `security_advisories` toolsets; hosted at api.githubcopilot.com/mcp/).
- **osv-scanner** `experimental-mcp` (since v2.2.4).
- **Trivy** (`trivy plugin install mcp`; last push December 2025, close to stale).
- **Semgrep**, now `semgrep mcp` inside the main binary (the standalone repo was archived October 2025).
- **Socket** (hosted, OAuth sign-in required).
- **Snyk** (`snyk/studio-mcp`, exposed via `snyk mcp`; needs a Snyk account).
- **Stacklok's osv-mcp** for raw OSV queries.

Anchore's official grype-mcp is archived. NVD, CVE-search/CIRCL, nuclei and Dependency-Track wrappers are small community projects, several of them stale. Wrapping the CLIs or REST APIs yourself is often as easy as adopting them.

### Cited Findings

| Repo | Wraps | Transport / invocation | Lang | License (gh) | Stars | Last push | Archived |
|---|---|---|---|---|---|---|---|
| [github/github-mcp-server](https://github.com/github/github-mcp-server) | GitHub incl. Dependabot, code scanning, advisories | remote `https://api.githubcopilot.com/mcp/` or local binary/Docker | Go | MIT | 34,636 | 2026-11-21 | no |
| [google/osv-scanner](https://github.com/google/osv-scanner) (`experimental-mcp`) | osv-scanner + OSV | stdio, or `--sse <addr>` | Go | Apache-2.0 | 11,579 | 2026-11-20 | no |
| [aquasecurity/trivy-mcp](https://github.com/aquasecurity/trivy-mcp) | Trivy | `trivy plugin install mcp`; `trivy mcp`; stdio, streamable HTTP, SSE | Go | MIT | 59 | **2025-12-17 (11 months, near stale)** | no |
| [semgrep/semgrep](https://github.com/semgrep/semgrep) (`semgrep mcp`) | Semgrep | stdio (default), `-t streamable-http`, Docker | C (GitHub) | LGPL-2.1 | 17,870 | 2026-11-20 | no |
| [semgrep/mcp](https://github.com/semgrep/mcp) | old standalone Semgrep MCP | n/a | Python | MIT | 688 | 2025-10-28 | **yes (archived, moved)** |
| [SocketDev/socket-mcp](https://github.com/SocketDev/socket-mcp) | Socket.dev package risk | hosted `https://mcp.socket.dev/` (OAuth) or self-host with API key | TypeScript | MIT | 142 | 2026-11-21 | no |
| [snyk/studio-mcp](https://github.com/snyk/studio-mcp) | Snyk (via `snyk mcp`) | stdio via Snyk CLI | Go | Apache-2.0 | 61 | 2026-11-20 | no |
| [StacklokLabs/osv-mcp](https://github.com/StacklokLabs/osv-mcp) | OSV API | ToolHive, or from source (listens on a port, default 8080) | Go | Apache-2.0 | 44 | 2026-11-20 | no |
| [anchore/grype-mcp](https://github.com/anchore/grype-mcp) | Grype | n/a | Python | NOASSERTION | 9 | 2025-08-29 | **yes (archived)** |
| [roadwy/cve-search_mcp](https://github.com/roadwy/cve-search_mcp) | CVE-Search API | community | Python | MIT | 110 | **2025-07-26 (stale)** | no |
| [Cyreslab-AI/circl-cve-search-mcp-server](https://github.com/Cyreslab-AI/circl-cve-search-mcp-server) | CIRCL Vulnerability-Lookup | community | TypeScript | MIT | 13 | 2026-09-20 | no |
| [marcoeg/mcp-nvd](https://github.com/marcoeg/mcp-nvd) | NVD API | community | Python | MIT | 18 | **2025-03-24 (stale)** | no |
| [gleicon/mcp-osv](https://github.com/gleicon/mcp-osv) | OSV | community | Go | none returned | 15 | 2025-12-24 | no |
| [kodustech/mcp-osv](https://github.com/kodustech/mcp-osv) | OSV (`osv_query`/`osv_query_batch`) | community HTTP | TypeScript | MIT | 2 | **2025-11-20 (stale, by one day)** | no |
| [addcontent/nuclei-mcp](https://github.com/addcontent/nuclei-mcp) | nuclei | community | Go | MIT | 51 | **2025-08-04 (stale)** | no |
| [secprog/dependency-track-mcp](https://github.com/secprog/dependency-track-mcp) | Dependency-Track ("Vibe Coded") | community | Python | MIT | 5 | 2026-08-16 | no |
| [ahmetak4n/grype-mcp](https://github.com/ahmetak4n/grype-mcp) | Grype | community | TypeScript | Apache-2.0 | 3 | **2025-11-09 (stale)** | no |

- **GitHub MCP server** (v2.2.0, 2026-11-16). Toolsets `code_security`, `dependabot`, `secret_protection`, `security_advisories`. Tools (OAuth scope `security_events`):
  - `get_dependabot_alert`, `list_dependabot_alerts` (filters `severity`, `state`, default open).
  - `update_dependabot_alert` (dismiss/reopen with `dismissed_reason`; per its docs, assigning `copilot-swe-agent[bot]` "requests remediation").
  - `get_code_scanning_alert`, `list_code_scanning_alerts`.
  - `get_global_security_advisory`, `list_global_security_advisories` (filters `affects`, `cveId`, `cwes`, `ecosystem`, `ghsaId`, `isWithdrawn`, `modified`, `published`, `severity`, `type`, `updated`), `list_repository_security_advisories`, `list_org_repository_security_advisories`.
  - It also bundles a `security-alert-triage` skill — [github-mcp-server README](https://github.com/github/github-mcp-server)
- **osv-scanner MCP**: command `experimental-mcp` ("Run osv-scanner as an MCP service (experimental)"). Tools `scan_vulnerable_dependencies`, `get_vulnerability_details`, `ignore_vulnerability` (gives instructions for writing an ignore config); prompt `scan_deps`. stdio by default, SSE with `--sse` — [osv-scanner mcp/command.go](https://github.com/google/osv-scanner/blob/main/cmd/osv-scanner/mcp/command.go). Added in v2.2.4 ("Add experimental OSV-Scanner MCP server"), with later fixes in v2.3.2 and v2.7.1 — [osv-scanner CHANGELOG](https://github.com/google/osv-scanner/blob/main/CHANGELOG.md)
- **Trivy MCP**: filesystem, container image and remote repository scanning. Optional Aqua Platform integration. stdio, streamable HTTP and SSE. Latest release v0.0.20 (2025-12-17) — [trivy-mcp README](https://github.com/aquasecurity/trivy-mcp)
- **Semgrep MCP**: "The Semgrep MCP server has been moved from a standalone repo to the main semgrep repository"; updates now ship via the `semgrep` binary — [semgrep/mcp README](https://github.com/semgrep/mcp). Run with `semgrep mcp` (stdio) or `semgrep mcp -t streamable-http`, or `docker run -i --rm semgrep/semgrep semgrep mcp -t stdio`. AppSec Platform features need `SEMGREP_APP_TOKEN` — [Semgrep MCP README](https://github.com/semgrep/semgrep/tree/develop/cli/src/semgrep/mcp)
- **Socket MCP** (v0.4.0, 2026-11-12). Tools: `depscore`, `organizations`, `alerts`, `threat_feed`, `package_files`, `package_file_contents`, `package_file_grep`. Ecosystems: npm, PyPI, cargo, Maven, NuGet, RubyGems, Go modules and more. The public server "requires Socket sign-in through OAuth for every tool call, including package scoring" — [socket-mcp README](https://github.com/SocketDev/socket-mcp)
- **Snyk MCP** (`snyk/studio-mcp`): ships with the Snyk CLI as `snyk mcp`. `snyk_sca_scan` appears in all versions. Other tools vary by version (`snyk_code_scan`, `snyk_iac_scan`, `snyk_container_scan`, `snyk_sbom_scan`, `snyk_package_health_check`, experimental `snyk_secret_scan`). Warning: `snyk_sca_scan` may run ecosystem tools such as Gradle or Maven locally — [pkg.go.dev snyk/studio-mcp](https://pkg.go.dev/github.com/snyk/studio-mcp@v1.12.2) (seen through search results, not fetched)
- **Stacklok osv-mcp** (v0.2.1, 2026-11-19): tools `query_vulnerability` (package+version or commit), `query_vulnerabilities_batch`, `get_vulnerability`. Packaged as `osv` in ToolHive — [osv-mcp README](https://github.com/StacklokLabs/osv-mcp)
- A GitHub search for MCP servers wrapping KEV/EPSS, govulncheck or Vulnerability-Lookup (official) returned no results. "vulnx mcp" returned only a 0-star wrapper (not verified, omitted) — gh search on 2026-11-21

### Inferences
- **Recommended MCP set for the agent:**
  - github-mcp-server (`security_advisories` + `dependabot` toolsets, read-only scopes) for GHSA lookup and repo alert state.
  - osv-scanner `experimental-mcp` for "scan this checkout".
  - Stacklok osv-mcp for raw OSV ID and batch lookups.
  - Optionally trivy-mcp for images, IaC and secrets.
- For feeds without a maintained MCP (KEV, EPSS, cvelistV5, vulnx, Dependency-Track, govulncheck, dep-scan, vexctl), write thin custom MCP tools over the CLI/REST described above. They are deterministic, schema-stable JSON and small enough to wrap in a few hours, which is safer than depending on stale community servers.
- Tools that mutate state (`update_dependabot_alert` dismissals, `ignore_vulnerability`, any `fix`) belong behind human approval (stage 6), not in the autonomous exposure-assessment toolset.

### Gaps
- I did not verify the current Snyk MCP tool list from Snyk's official docs, or which Snyk plan tiers allow MCP use.
- I did not check whether GitHub's remote MCP endpoint enables security toolsets by default or needs explicit `X-MCP-Toolsets` configuration (the README points to docs/remote-server.md, which I did not read).
- Community MCP servers were verified only for metadata, not for code quality or security.
