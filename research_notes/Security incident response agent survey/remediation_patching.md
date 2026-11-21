# Remediation and patching tools for the "mitigate and patch" stage of a security incident response agent

Scope: open-source tools and agents that fix or mitigate vulnerabilities, deterministic and LLM-based, plus closed products as short reference points. Detection tools, data feeds, SOAR and benchmarks are covered elsewhere (benchmarks appear here only where patching agents report results on them).

How this was verified: every GitHub repo listed was checked with `gh api repos/OWNER/REPO` on 2026-11-21. Metadata is written as `language · license (SPDX from GitHub) · stars · last push · archived?`. "Stale" means no push in 12+ months (before 2025-11-21). Repos that returned 404 were dropped (for example `pixee/codemodder-js`, `chains-project/byam`, `shellphish/artiphishell-afc`). GitHub redirected several renamed repos, and the canonical names are used here: `facebook/jscodeshift` → `meta/jscodeshift`, `codemod-com/codemod` → `codemod/codemod`, `antongolub/yarn-audit-fix` → `lockgraph/yarn-audit-fix`, `All-Hands-AI/OpenHands` → `OpenHands/OpenHands`, `sst/opencode` → `anomalyco/opencode`, `block/goose` → `aaif-goose/goose`, `nus-apr/auto-code-rover` → `AutoCodeRoverSG/auto-code-rover`, `sslab-gatech/oss-crs` → `ossf/oss-crs`.

## Q1. Deterministic remediation: dependency bots, codemods and container image patching. How do they handle transitive dependencies and breaking (major-version) upgrades?

### Takeaway
A mature, scriptable deterministic toolchain exists and should be the agent's first choice for dependency and container CVEs. OSV-Scanner `fix` (npm and Maven, solves the transitive graph and respects a per-package major/minor/patch ceiling), Renovate and Dependabot (CLI or app, both open a PR) and Copacetic (patches an image in place from a Trivy report, with no rebuild) cover most of it. Transitive dependencies are handled only partly: Renovate's OSV mode covers direct dependencies only, and Dependabot handles transitive fixes properly only in npm and NuGet. Major-version upgrades are either avoided by default (minimum fixed version, patch-level ceilings) or allowed through an explicit flag with no proof of compatibility. None of these tools runs your tests itself. Validation is left to your CI or the agent.

### Cited Findings

#### Dependency-update bots

**renovatebot/renovate**: https://github.com/renovatebot/renovate
- Metadata: TypeScript · AGPL-3.0 · 23,215★ · pushed 2026-11-21 · not archived. GitHub describes it as "Home of the Mend Renovate CLI: Cross-platform Dependency Automation by Mend.io". — [GitHub API / repo](https://github.com/renovatebot/renovate)
- Trigger (GitHub alerts): with the Dependency graph and Dependabot alerts turned on, "Renovate tries to raise fix PRs" for GitHub vulnerability alerts. In app mode the app needs `read` permission on Dependabot alerts. — [Renovate docs, configuration-options.md `vulnerabilityAlerts`](https://github.com/renovatebot/renovate/blob/main/docs/usage/configuration-options.md)
- Trigger (OSV): with `osvVulnerabilityAlerts: true`, Renovate checks extracted dependencies against OSV and raises vulnerability-fix PRs. The whole OSV database (about 85 MB compressed) is downloaded through `osv-offline` and queried offline. Supported datasources are crate, go, hackage, hex, maven, npm, nuget, packagist, pypi and rubygems. — [Renovate docs `osvVulnerabilityAlerts`](https://github.com/renovatebot/renovate/blob/main/docs/usage/configuration-options.md)
- Transitive dependencies: "You will only get OSV-based vulnerability alerts for _direct_ dependencies. The only exception today is the `pep621` manager, for `uv` projects." Separately, GitHub-alert PRs are still raised for dependencies that managers disable by default, such as `indirect` Go modules and Gradle `strictly` constraints. — [Renovate docs](https://github.com/renovatebot/renovate/blob/main/docs/usage/configuration-options.md)
- Upgrade size: `vulnerabilityAlerts.vulnerabilityFixStrategy` defaults to `lowest`, the lowest fixed version (for example 1.0.0 → 1.1.0 even when 1.2.0 exists). `highest` falls back to the normal upgrade policy. — [Renovate docs](https://github.com/renovatebot/renovate/blob/main/docs/usage/configuration-options.md)
- Behaviour: vulnerability PRs "skip the line". They ignore schedule, `prHourlyLimit` and similar limits, and have their own concurrency budget. Renovate warns that "a wrong vulnerability alert results in a flapping/looping vulnerability fix", so check automerged fixes. A `security:only-security-updates` preset exists. — [Renovate docs](https://github.com/renovatebot/renovate/blob/main/docs/usage/configuration-options.md)
- Supply-chain feature: experimental malicious-package protection. If OSV flags a proposed update as malicious, Renovate skips all updates to that dependency (`skipReason: malicious-update-proposed`). — [Renovate docs](https://github.com/renovatebot/renovate/blob/main/docs/usage/configuration-options.md)
- Interfaces: CLI (self-hosted), GitHub Action `renovatebot/github-action` (TypeScript · NOASSERTION · 565★ · pushed 2026-11-21), Mend-hosted app. The OSV backend is `renovatebot/osv-offline` (TypeScript · MIT · 25★ · pushed 2026-11-21). — [github-action](https://github.com/renovatebot/github-action), [osv-offline](https://github.com/renovatebot/osv-offline)
- A grep of the current `configuration-options.md` finds no `transitiveRemediation` entry. — [Renovate docs](https://github.com/renovatebot/renovate/blob/main/docs/usage/configuration-options.md)

**dependabot/dependabot-core** and **dependabot/cli**: https://github.com/dependabot/dependabot-core, https://github.com/dependabot/cli
- Metadata: dependabot-core is Ruby · MIT · 5,860★ · pushed 2026-11-20 ("Dependabot's core logic for creating update PRs"). dependabot/cli is Go · MIT · 485★ · pushed 2026-11-19 ("A tool for running Dependabot update jobs"). — [dependabot-core](https://github.com/dependabot/dependabot-core), [cli](https://github.com/dependabot/cli)
- Trigger and output: when security updates are on, Dependabot tries to open a PR for every open Dependabot alert that has a patch. The PR updates to "the minimum version that includes the patch" and is linked to the alert. If no fix can be produced, Dependabot "reports an error on the alert". — [GitHub Docs, About Dependabot security updates](https://docs.github.com/en/code-security/dependabot/dependabot-security-updates/about-dependabot-security-updates)
- Transitive dependencies: in npm, Dependabot updates the parent or removes the sub-dependency. In NuGet `PackageReference` it updates the parent if possible, and otherwise "adds a direct reference that pins the transitive dependency to the secure version". In other ecosystems, "Dependabot can't update an indirect or transitive dependency if doing so would also require updating the parent dependency." — [GitHub Docs](https://docs.github.com/en/code-security/dependabot/dependabot-security-updates/about-dependabot-security-updates)
- Validation: compatibility scores are "the percentage of CI runs that passed" for the same update in other public repositories. Dependabot does not run your tests. Its PRs trigger your own Actions workflows. Grouped security updates work per ecosystem only. — [GitHub Docs](https://docs.github.com/en/code-security/dependabot/dependabot-security-updates/about-dependabot-security-updates)
- CLI: `dependabot update go_modules dependabot/cli` runs an update job and `dependabot test -f input.yml` runs a smoke test. The CLI requires valid GitHub build attestations for the updater and proxy images before it starts containers. — [dependabot/cli README](https://github.com/dependabot/cli)

#### Guided remediation and other package-manager fixers

**google/osv-scanner** (`osv-scanner fix`, "guided remediation"): https://github.com/google/osv-scanner
- Metadata: Go · Apache-2.0 · 11,579★ · pushed 2026-11-20. — [repo](https://github.com/google/osv-scanner)
- What it does: resolves "the entire transitive graph (leveraging deps.dev) to determine the minimal changes required", ranks direct-dependency upgrades by how many transitive vulnerabilities they fix, and edits manifests and lockfiles. It is marked experimental and "might change or be removed with only a minor version update". — [guided-remediation.md](https://github.com/google/osv-scanner/blob/main/docs/guided-remediation.md)
- Strategies: `in-place` (npm `package-lock.json` only), `relax`/relock (npm `package.json`, regenerates the lockfile with `npm install --package-lock-only`, "potentially breaking"), and `override` (Maven `pom.xml`, adds `<dependencyManagement>` overrides that also force transitive versions). — [guided-remediation.md](https://github.com/google/osv-scanner/blob/main/docs/guided-remediation.md)
- Major versions: `--upgrade-config=[pkg:]major|minor|patch|none` sets the maximum SemVer bump per package. The default is `major`. For example, `--upgrade-config=minor` disallows any major bump. — [guided-remediation.md](https://github.com/google/osv-scanner/blob/main/docs/guided-remediation.md)
- Agent-friendly flags: `--format json`, `--vulns` (target specific OSV IDs), `--apply-top=N` ("particularly useful when scripting to test the outcome of specific patches"), `--max-depth`, `--min-severity`, `--ignore-dev`. Non-interactive mode "can be used in scripts to automatically apply and test remediation patches". — [guided-remediation.md](https://github.com/google/osv-scanner/blob/main/docs/guided-remediation.md)
- Example output: "Can fix 25/55 matching vulnerabilities by changing 21 dependencies … UNFIXABLE-VULNS: 30" (in-place, npm). — [guided-remediation.md](https://github.com/google/osv-scanner/blob/main/docs/guided-remediation.md)
- Limits: does not reinstall `node_modules`. Ignores npm `overrides` and `osv-scanner.toml`. `peerDependencies` are not handled properly. npm workspaces are only partly supported. Maven properties in groupId/artifactId and profiles are limited. Running it on untrusted projects is risky because package managers may run scripts. — [guided-remediation.md](https://github.com/google/osv-scanner/blob/main/docs/guided-remediation.md)

**pypa/pip-audit**: https://github.com/pypa/pip-audit
- Metadata: Python · Apache-2.0 · 1,409★ · pushed 2026-11-19. The `--fix` flag "automatically upgrade[s] dependencies with known vulnerabilities". With `--fix`, `--dry-run` reports what would change without doing it. — [README](https://github.com/pypa/pip-audit)

**rustsec/rustsec** (`cargo audit fix`): https://github.com/rustsec/rustsec
- Metadata: Rust · NOASSERTION · 1,991★ · pushed 2026-11-20. `cargo audit fix` "fix[es] vulnerable dependency requirements" and must be installed with `--features=fix`. — [cargo-audit README](https://github.com/rustsec/rustsec/tree/main/cargo-audit)

**SocketDev/socket-cli**: https://github.com/SocketDev/socket-cli
- Metadata: TypeScript · MIT · 339★ · pushed 2026-11-21. Commands: `socket fix` ("Fix CVEs in dependencies"), `socket patch` (scan for, download and apply Socket security patches to `node_modules`), and `socket optimize` (replace dependencies with `@socketregistry` overrides). — [README](https://github.com/SocketDev/socket-cli)

**lockgraph/yarn-audit-fix**: https://github.com/lockgraph/yarn-audit-fix
- Metadata: TypeScript · MIT · 198★ · pushed 2026-09-29. Describes itself as "The missing `yarn audit fix`". — [repo](https://github.com/lockgraph/yarn-audit-fix)

**updatecli/updatecli**: https://github.com/updatecli/updatecli
- Metadata: Go · Apache-2.0 · 1,024★ · pushed 2026-11-21. Describes itself as "A Declarative Update Policy Engine". It is a general update tool, not CVE-driven. — [repo](https://github.com/updatecli/updatecli)

**seal-community/cli** (open client for the closed Seal Security service): https://github.com/seal-community/cli
- Metadata: no language or license detected · 34★ · pushed 2026-11-09. "A CLI tool to scan and fix your project's open-source vulnerabilities using Seal packages." A secondary source says it supports only npm. — [repo](https://github.com/seal-community/cli); [appsecsanta (secondary)](https://appsecsanta.com/seal-security)

#### OpenRewrite (Java, Maven/Gradle, also npm)

**openrewrite/rewrite** and recipe modules: https://github.com/openrewrite/rewrite
- Metadata: rewrite is Java · Apache-2.0 · 4,003★ · pushed 2026-11-21 ("Automated mass refactoring of source code"). `rewrite-java-dependencies` is Java · Apache-2.0 · 18★ · pushed 2026-11-20. `rewrite-maven-plugin` has no detected license · 190★ · pushed 2026-11-20. `rewrite-gradle-plugin` has no detected license · 90★ · pushed 2026-11-10. — [rewrite](https://github.com/openrewrite/rewrite), [rewrite-java-dependencies](https://github.com/openrewrite/rewrite-java-dependencies), [maven plugin](https://github.com/openrewrite/rewrite-maven-plugin)
- `org.openrewrite.java.dependencies.DependencyVulnerabilityCheck` ("Find and fix vulnerable dependencies") ships in the `rewrite-java-security` artifact. Its options include `overrideTransitive` (by default only direct dependencies are upgraded) and `maximumUpgradeDelta` (patch/minor/major, with patch reported as the default). The docs disagree with themselves on the `overrideTransitive` default. — [OpenRewrite docs](https://docs.openrewrite.org/recipes/java/dependencies/dependencyvulnerabilitycheck); [Maven Central rewrite-java-security](https://central.sonatype.com/artifact/org.openrewrite.recipe/rewrite-java-security); search-result summary of [workshop page](https://openrewrite.github.io/migration-engineering-with-openrewrite/docs/secure-your-projects/find-and-fix-vulnerable-dependencies)
- Example invocation from the workshop: `-P "scope=runtime" -P "overrideTransitive=True" -P "maximumUpgradeDelta=minor"`. — [OpenRewrite workshop](https://openrewrite.github.io/migration-engineering-with-openrewrite/docs/secure-your-projects/find-and-fix-vulnerable-dependencies)
- Related recipes listed in the docs: "Upgrade transitive Gradle or Maven dependencies", "Find and fix vulnerable npm dependencies" and "Use VulnCheck Exploit Intelligence to fix vulnerabilities". — [docs: UpgradeTransitiveDependencyVersion](https://docs.openrewrite.org/recipes/java/dependencies/upgradetransitivedependencyversion), [npm DependencyVulnerabilityCheck](https://docs.openrewrite.org/recipes/nodejs/dependencyvulnerabilitycheck), [VulnCheck recipe](https://docs.openrewrite.org/recipes/vulncheck/fixvulncheckvulnerabilities)
- The public GitHub repo `openrewrite/rewrite-java-security` is archived, with 0★ and a last push on 2024-12-27, even though the artifact is still published. The DependencyVulnerabilityCheck source is not in `rewrite-java-dependencies` (path lookup returned 404). — [repo](https://github.com/openrewrite/rewrite-java-security)

#### SAST autofix codemods (code-level, deterministic)

**pixee/codemodder-python**: https://github.com/pixee/codemodder-python
- Metadata: Python · AGPL-3.0 · 43★ · pushed 2026-11-20. CLI (`codemodder /path`, `--dry-run`, `--list`) and library (`codemodder.run(path, dry_run=True)`). Codemods are made of a Detector, Transformer(s) and Metadata, and a plugin system supports custom codemods. The semgrep optional dependency is still recommended. The API is "relatively stable" as of v0.80.0, with no backward-compatibility guarantee before 1.0. — [README](https://github.com/pixee/codemodder-python)

**pixee/codemodder-java**: https://github.com/pixee/codemodder-java
- Metadata: Java · AGPL-3.0 · 42★ · pushed 2026-11-21. Runs core codemods from a release zip or `./gradlew :core-codemods:run --args='--output my.codetf --dry-run /path'`, so output is in CodeTF format. It needs the Semgrep CLI, and some tests integrate with OpenAI. — [README](https://github.com/pixee/codemodder-java)

**pixee/pixee-cli** (client for the commercial Pixee platform): https://github.com/pixee/pixee-cli
- Metadata: no language detected · NOASSERTION · 31★ · pushed 2026-11-17. GitHub describes it as "binaries, container image, and coding-agent skills for the Pixee platform. Source lives in pixee-cli-private." It needs a Pixee server and token. It ships as a coding-agent plugin whose skills are licensed separately under Apache-2.0. — [README](https://github.com/pixee/pixee-cli)

**mobb-dev/bugsy** (community edition of the commercial Mobb): https://github.com/mobb-dev/bugsy
- Metadata: TypeScript · MIT · 67★ · pushed 2026-08-31. `npx mobbdev scan` runs Checkmarx or Snyk. `npx mobbdev analyze --scan-file` ingests a Checkmarx, CodeQL, Fortify or Snyk report, "produces the code fixes and redirects the user to the fix report page on the Mobb platform". The community edition "only analyzes public GitHub repositories". It also runs as an MCP server (`npx mobbdev mcp`), which needs a Mobb API key. — [README](https://github.com/mobb-dev/bugsy)

**Generic codemod engines** (useful for agent-written, deterministic rewrites):
- `codemod/codemod`: Rust · Apache-2.0 · 1,129★ · pushed 2026-11-20. "The CLI for codemods … First-class ast-grep support." — [repo](https://github.com/codemod/codemod)
- `ast-grep/ast-grep`: Rust · MIT · 16,650★ · pushed 2026-11-21. "CLI tool for code structural search, lint and rewriting." — [repo](https://github.com/ast-grep/ast-grep)
- `comby-tools/comby`: OCaml · Apache-2.0 · 2,691★ · pushed 2026-11-06. Structural search-and-replace for "~every language". — [repo](https://github.com/comby-tools/comby)
- `meta/jscodeshift`: JavaScript · MIT · 10,050★ · pushed 2026-11-14. "A JavaScript codemod toolkit." — [repo](https://github.com/meta/jscodeshift)

#### Container image patching

**project-copacetic/copacetic** (`copa`): https://github.com/project-copacetic/copacetic
- Metadata: Go · Apache-2.0 · 1,760★ · pushed 2026-11-20. The community follows the CNCF Code of Conduct and uses a channel on the CNCF Slack. Its formal CNCF status was not verified. — [README](https://github.com/project-copacetic/copacetic)
- How it works: a buildkit-based CLI that "directly patch[es] container images without full rebuilds", using scanner reports from tools such as Trivy (report-driven) or package metadata in the image (comprehensive update). It applies package-manager updates as an extra patch layer. Anyone can patch third-party images, not only the publisher. — [README](https://github.com/project-copacetic/copacetic)
- App-level patching (experimental, `COPA_EXPERIMENTAL=1`): pip, npm (including global packages) and Go modules, selected with `--pkg-types os,library`. `--library-patch-level patch|minor|major` defaults to `patch` and prefers patch over minor over major. It expects public registries only and does not yet pass credentials for private Go, npm, PyPI or NuGet sources. — [app-level-patching.md](https://github.com/project-copacetic/copacetic/blob/main/website/docs/app-level-patching.md)
- Ubuntu Chiseled images are supported, with caveats: native `manifest.wall` images allow comprehensive updates only. — [README](https://github.com/project-copacetic/copacetic)
- GitHub Action `project-copacetic/copa-action`: Shell · MIT · 34★ · pushed 2025-12-10 (close to stale). — [repo](https://github.com/project-copacetic/copa-action)

**Rebuild-from-source alternative** (Wolfi/Chainguard open tooling):
- `wolfi-dev/os` (Shell · NOASSERTION · 1,316★ · pushed 2026-11-20): "Main package repository for production Wolfi images". `chainguard-dev/melange` (Go · Apache-2.0 · 630★ · pushed 2026-11-20): "build APKs from source code". `chainguard-dev/apko` (Go · Apache-2.0 · 1,707★ · pushed 2026-11-20): "Build OCI images from APK packages directly without Dockerfile". — [wolfi-dev/os](https://github.com/wolfi-dev/os), [melange](https://github.com/chainguard-dev/melange), [apko](https://github.com/chainguard-dev/apko)

#### Supply-chain hardening and mitigation tools (pinning)
- `suzuki-shunsuke/pinact` (Go · MIT · 1,258★ · pushed 2026-11-20): pins versions of GitHub Actions and reusable workflows and can update and verify them. — [repo](https://github.com/suzuki-shunsuke/pinact)
- `sethvargo/ratchet` (Go · Apache-2.0 · 974★ · pushed 2026-07-18): "securing CI/CD workflows with version pinning". — [repo](https://github.com/sethvargo/ratchet)
- `stacklok/frizbee` (Go · Apache-2.0 · 187★ · pushed 2026-11-17): "Throw a tag at it and it comes back with a checksum" (pins tags to digests). — [repo](https://github.com/stacklok/frizbee)
- `step-security/secure-repo` (Go · AGPL-3.0 · 335★ · pushed 2026-11-19): "Orchestrate GitHub Actions Security". — [repo](https://github.com/step-security/secure-repo)
- `step-security/harden-runner` (TypeScript · Apache-2.0 · 1,305★ · pushed 2026-11-18): an EDR-like agent for Actions runners that "integrates with Secure Registry to apply package cooldowns and block known compromised packages". — [repo](https://github.com/step-security/harden-runner)

### Inferences
- The default "patch a vulnerable dependency" path for the agent is `osv-scanner fix --format json --vulns <ID> --upgrade-config=minor` for npm and Maven, with `--apply-top=1` to try candidates one at a time. Run build and tests after each, then re-scan. Escalate to `relax` or a major bump only when no smaller fix exists. For other ecosystems, use `pip-audit --fix`, `cargo audit fix`, `dependabot update <ecosystem> <repo>` (Dependabot CLI) or Renovate with `osvVulnerabilityAlerts`.
- Renovate and Dependabot make sense as the PR-opening backend if the team wants the familiar bot PR format. For a hackathon demo, though, calling OSV-Scanner or ecosystem fixers directly and opening the PR with `gh pr create` keeps the agent in control of validation and of the PR body (report stage).
- Copacetic is the best ready-made reaction for "a CVE in a running container image". Feed it a Trivy JSON report and push the patched tag. This is a mitigation even when no source change is possible (third-party images).
- Codemodder, Bugsy and Pixee CLI target SAST findings (code-level CWE fixes), not advisory-driven dependency CVEs. Bugsy and Pixee CLI depend on closed backends, so only codemodder runs fully open.
- OpenRewrite's vulnerability recipe looks like it moved out of open development: the public repo is archived and the artifact is still published. Its license should be checked before relying on it.
- Licensing: Renovate, codemodder, secure-repo and BunkerWeb are AGPL-3.0. That is fine for internal or hackathon use, but it matters if the agent is later offered as a hosted service.

### Gaps
- Renovate's handling of transitive vulnerabilities through lockfile maintenance or lockfile-only updates was not verified. The `transitiveRemediation` option that existed in older versions is absent from current docs, and I did not confirm when or why it was removed.
- Dependabot docs do not say whether security updates will cross a major version when the minimum patched version is a new major.
- The exact license of `rewrite-java-security` (Apache-2.0, Moderne source-available or proprietary) was not verified. The docs page is rendered by JavaScript and fetching it returned empty.
- The Snyk CLI's `snyk fix` and Semgrep autofix were not verified, so they are left out of the inventory.
- Seal CLI's supported ecosystems come only from a secondary source.

## Q2. LLM and agent patch generation: which DARPA AIxCC cyber reasoning systems were open-sourced, which components are reusable outside the competition harness, and which research patching agents have code and reported success rates?

### Takeaway
All seven AIxCC finalist CRSs were released under OSI licenses. Only a few are realistically reusable today:
- **Trail of Bits Buttercup**: maintained standalone version that runs on a laptop.
- **OpenSSF's OSS-CRS**: a maintained orchestration framework that runs CRSs, including Claude Code, Codex, Gemini CLI and Copilot CLI patching agents and an ensemble, against any OSS-Fuzz-format project, with LLM budgets and LiteLLM routing.
- **FuzzingBrain**: actively maintained.
- **Shellphish PatcherY**: the patcher pulled out of their CRS as a standalone CLI.
- **PatchAgent**: a Python library from USENIX Security 2025.

Everything else is an archived competition snapshot tied to Azure or competition APIs. All of these require a crashing PoV (proof of vulnerability) and an OSS-Fuzz-style build (C/C++/Java), so they fit the case "we have a reproducer" rather than "an advisory just dropped for a library we depend on". Reported success: in the AIxCC final, systems patched 43 of 63 synthetic vulnerabilities (68%). Off-the-shelf coding agents fix about 57–71% of AIxCC crashes. About 20% or more of patches that pass automated checks are semantically wrong.

### Cited Findings

#### AIxCC final: facts
- Final results (DEF CON 33, August 2025): 63 synthetic vulnerabilities (corrected from 70). Teams found 54 (86%) and patched 43 (68%). They also found 18 real non-synthetic vulnerabilities and provided 11 patches for them. Average time to patch was about 45 minutes and cost about $152 per task. Prizes: Team Atlanta $4M, Trail of Bits $3M, Theori $1.5M. Other finalists: all_you_need_is_a_fuzzing_brain, Shellphish, 42-b3yond-6ug and Lacrosse. "All seven finalist CRSs" were to be released under an OSI-approved license, four of them initially at archive.aicyberchallenge.com. — [DARPA AIxCC results](https://www.darpa.mil/news/2025/aixcc-results)
- From the SoK on AIxCC (Zhang, Park, Fleischer, Kim et al., arXiv 2602.07666, 7 Feb 2026):
  - Patching designs: Atlantis ensembles eight patcher agents (ReAct workflows, autonomous agents, multi-agent, Aider, SWE-agent) and stops at the first valid patch. Buttercup is multi-agent (root-cause analysis, patch writing, context retrieval, reflection) and favours mid-tier models. RoboDuck uses a nested ReAct loop and can submit patches without a PoV. FuzzingBrain is a single agent with 23 strategies, LLM-as-judge and post-patch fuzzing, and can submit patches without a PoV. ARTIPHISHELL combines an agentic patcher with a one-shot patcher assisted by program analysis. BugBuster is a single agent with 16 configurations. Lacrosse uses a DSPy workflow that escalates from cheap to expensive models.
  - Validation: all teams ran the PoV, a build check and project tests, except BugBuster, which skips tests. AT, FB and SP add LLM-as-judge, and FB and SP add post-patch fuzzing.
  - Patch score and accuracy: AT 171.0 (83.8%), TB 100.9 (79.2%), TI 101.6 (31.7%), FB 68.8 (23.3%), SP 54.3 (100%, attributed to strict filtering), 42 at 14.2 (bug in patch submission), LC 4.9. — [arXiv 2602.07666](https://arxiv.org/html/2602.07666v1)
- Conflict on Atlantis's patcher count: the SoK says eight patcher agents. A Team Atlanta blog post (search snippet only) says validation time "forced Atlantis-Patching to limit itself to six agents", with each agent able to use a different LLM through LiteLLM. — [SoK](https://arxiv.org/html/2602.07666v1); [Team Atlanta blog](https://team-atlanta.github.io/blog/post-crs-patch-integration)

#### AIxCC CRS repos

**trailofbits/buttercup** (maintained standalone): https://github.com/trailofbits/buttercup
- Metadata: Python · AGPL-3.0 · 1,758★ · pushed 2026-11-02. The competition snapshots are `trailofbits/afc-buttercup` (Python · AGPL-3.0 · 98★ · pushed 2025-07-14 · **archived**) and `trailofbits/asc-buttercup` (12★ · pushed 2025-07-15 · **archived**). — [repo](https://github.com/trailofbits/buttercup); gh API
- Components: Orchestrator, Seed Generator, Fuzzer (on oss-fuzz), Program Model and Patcher. Targets are C and Java repos that are "OSS-Fuzz compatible … and have existing fuzzing harnesses". Minimum hardware is 8 cores, 16 GB RAM and 100 GB disk. It is deployed locally on Kubernetes (`make setup-local`, `make deploy`, `make send-libpng-task`) and has a web UI, SigNoz and optional LangFuse. It has an LLM budget setting and "works best" with both OpenAI and Anthropic, but needs at least one key from OpenAI, Anthropic or Google. A guide covers writing custom challenges. — [README](https://github.com/trailofbits/buttercup)
- Patcher: "seven distinct AI agents". It iterates until the PoV and its duplicates no longer trigger and other functionality is preserved. The standalone version "runs on a typical laptop". The competition versions are "not actively maintain[ed]". — [Trail of Bits blog, 2025-08-08](https://blog.trailofbits.com/2025/08/08/buttercup-is-now-open-source/)

**Team-Atlanta/aixcc-afc-atlantis** (winner): https://github.com/Team-Atlanta/aixcc-afc-atlantis
- Metadata: C · NOASSERTION on GitHub, though the README says MIT · 664★ · pushed 2025-11-25 (nearly stale). The implementation lives in `example-crs-webservice/` with deployment in `example-crs-architecture/`. The semifinal version is `Team-Atlanta/aixcc-asc-atlantis` (51★ · pushed 2025-08-06). — [README](https://github.com/Team-Atlanta/aixcc-afc-atlantis); gh search
- Post-competition reimplementations for OSS-CRS: `Team-Atlanta/crs-claude-code` (Python · MIT · 7★ · pushed 2026-06-08, "Claude Code sandbox agent for autonomous vulnerability patching in oss-crs"), `crs-codex` (Python · MIT · 2★ · pushed 2026-05-08), `crs-copilot-cli` (MIT · 0★ · pushed 2026-04-16), `crs-gemini-cli` (MIT · 0★ · pushed 2026-05-09) and `crs-patch-ensemble` (Python · no license · 0★ · pushed 2026-05-09). Team Atlanta calls these "clean reimplementations for OSS-CRS, not the exact code used in the evaluation". — gh API; [Team Atlanta 2026 post](https://team-atlanta.github.io/blog/post-patch-2026-ensemble/)

**ossf/oss-crs** (OpenSSF orchestration framework, the most reusable piece): https://github.com/ossf/oss-crs
- Metadata: Python · MIT · 187★ · pushed 2026-11-18. It is a "standard orchestration framework for building and running LLM-based autonomous bug-finding and bug-fixing systems". Any OSS-Fuzz-format project works as a target. Multiple CRSs can be combined in one ensemble campaign, with per-CRS CPU and LLM budgets. It runs locally now ("Azure (coming soon)").
- CLI: `uv run oss-crs prepare | build-target | run --compose-file … --fuzz-proj-path … --target-harness …`. It supports LiteLLM proxy routing.
- Examples include `atlantis-multilang` (LLM harness generation) and `crs-claude-code`, the bug-fixing (patching) CRS, run with `--incremental-build` and authenticated by `CLAUDE_CODE_OAUTH_TOKEN`. Harness detection is "heuristic". — [README](https://github.com/ossf/oss-crs)
- `Team-Atlanta/shellphish-oss-crs` (Python · no license · 3★ · pushed 2026-05-30) ports ARTIPHISHELL's fuzzing pipelines (AFL++, libFuzzer, DiscoveryGuy, AIJON, Grammar, Jazzer, QuickSeed) to OSS-CRS. Its README pipeline table lists no patching pipeline. — [README](https://github.com/Team-Atlanta/shellphish-oss-crs)

**theori-io/aixcc-afc-archive** ("Robo Duck", 3rd place): https://github.com/theori-io/aixcc-afc-archive
- Metadata: Python · AGPL-3.0 · 274★ · pushed 2025-08-05 · **archived**. The README says it "will NOT be supported" and that it "can easily spend $1,000 or more in under an hour". It runs as a Docker image (`ghcr.io/theori-io/crs:latest`) with a REST API (`POST /v1/task/` on port 1324) and needs Anthropic, OpenAI, Google and Azure credentials, with model maps in TOML. Agent traces are at theori-io.github.io/aixcc-public. — [README](https://github.com/theori-io/aixcc-afc-archive), [aixcc-public](https://github.com/theori-io/aixcc-public)

**fuzzingbrain/afc-crs-all-you-need-is-a-fuzzing-brain** (4th place): https://github.com/fuzzingbrain/afc-crs-all-you-need-is-a-fuzzing-brain
- Metadata: Python · Apache-2.0 · 154★ · pushed 2026-11-17. FBv2 (the paper, arXiv 2509.07225) needs an OSS-Fuzz target with a harness and metered API keys from Anthropic, OpenAI or Gemini, and is run as `python -m fuzzingbrain.main --config task.json --budget-limit 20`. FBv3 drives the `claude` and `codex` CLIs on subscriptions, writes its own harness for any C/C++ repo, and produces `report.md`. "Nothing is reported that has not crashed a real build." The README warns that OSS-Fuzz recipes cloning dependencies at `master` can break builds. — [README](https://github.com/fuzzingbrain/afc-crs-all-you-need-is-a-fuzzing-brain)

**shellphish/artiphishell** and **shellphish/PatcherY**: https://github.com/shellphish/artiphishell, https://github.com/shellphish/PatcherY
- Metadata: artiphishell is Python · MIT · 143★ · pushed 2025-08-27 (**stale**). Its README covers only the official Azure, Tailscale and competition-API deployment and points to a private wiki for development. — [README](https://github.com/shellphish/artiphishell)
- PatcherY (Python · BSD-2-Clause · 13★ · pushed 2025-10-04, **stale**) is "An LLM-driven program patcher for fixing vulnerabilities automatically. Originally in Artiphishell." It is pip-installable. CLI: `patchery --generate-verified-patch --src-root … --run-script … --lang … --report-file … --output-path out.patch`. Verification passes include a compile pass, and a ranker orders multiple verified patches. Its test container is about 8 GB. — [README](https://github.com/shellphish/PatcherY)

**42-b3yond-6ug/42-b3yond-6ug-crs** ("BugBuster"): https://github.com/42-b3yond-6ug/42-b3yond-6ug-crs
- Metadata: Python · GPL-3.0 · 31★ · pushed 2025-08-19 (**stale**). A snapshot that "may contain … dependencies on permission-restricted resources (e.g., Docker images hosted in our private registry)". Deployed with Terraform and Kubernetes. — [README](https://github.com/42-b3yond-6ug/42-b3yond-6ug-crs)

**siftech/afc-crs-lacrosse**: https://github.com/siftech/afc-crs-lacrosse
- Metadata: C++ · MIT · 11★ · pushed 2025-08-24 (**stale**). Azure-only deployment: three Standard_D128ds_v6 VMs through Terraform, with competition keys held in Azure Key Vault. — [README](https://github.com/siftech/afc-crs-lacrosse)

#### Research patching agents with code (2024–2026)
- **PatchAgent** (`cla7aye15I4nd/PatchAgent`: Python · Apache-2.0 · 126★ · pushed 2026-02-25), USENIX Security 2025. It repaired 92.13% of 178 real-world vulnerabilities (OSS-Fuzz and Huntr sources), described as "over 90%" in the abstract. Features: an LSP-based code navigation agent, patch verification, C/C++/Java support, and ASan/MSan/UBSan/TSan/Jazzer reports. Python API: `PatchTask([OSSFuzzPoC(...)], OSSFuzzBuilder(...)).repair(agent_generator())`. Docker image `ghcr.io/cla7aye15i4nd/patchagent`. Fixes were upstreamed to assimp, libssh2, hdf5 and the Linux kernel. Runner-up for the Technical Impact Award at CSAW ARC 2025. — [README](https://github.com/cla7aye15I4nd/PatchAgent); [USENIX](https://www.usenix.org/conference/usenixsecurity25/presentation/yu-zheng); [paper PDF](https://cs.uwaterloo.ca/~m285xu/assets/publication/patch_agent-paper.pdf)
- **SAN2PATCH** (`acorn421/san2patch`: Python · MIT · 16★ · pushed 2025-06-11, **stale**; benchmark repo `acorn421/san2patch-benchmark`: 6★), USENIX Security 2025. It patches "using only sanitizer logs and source code" with tree-of-thought prompting across comprehension, localization, fix strategy and generation. Results: 79.5% on VulnLoc (ExtractFix 43%, VulnFix 51%), 63% on SAN2VULN (27 new vulnerabilities) and 81.8% of buffer overflows fixed with functionality preserved. — [USENIX](https://www.usenix.org/conference/usenixsecurity25/presentation/kim-youngjoon); [repo](https://github.com/acorn421/san2patch)
- **PatchPilot** (`ucsb-mlsec/PatchPilot`: Python · MIT · 26★ · pushed 2025-06-05, **stale**): "A Stable and Cost-Efficient Agentic Patching Framework". — [repo](https://github.com/ucsb-mlsec/PatchPilot)
- **AutoCodeRover** (`AutoCodeRoverSG/auto-code-rover`: Python · NOASSERTION · 3,105★ · pushed 2026-11-01): a general program-improvement agent that reports 46.2% pass@1 on SWE-bench Verified at under $0.7 per task. It is not security-specific. — [repo](https://github.com/AutoCodeRoverSG/auto-code-rover)
- Benchmark context (results only):
  - **SEC-bench** (NeurIPS 2025; `SEC-bench/SEC-bench`, MIT, 107★): SWE-agent, OpenHands and Aider reach "at most 34.0%" on vulnerability patching and 18.0% on PoC generation. — [arXiv 2506.11791](https://arxiv.org/abs/2506.11791v2); [repo](https://github.com/SEC-bench/SEC-bench)
  - **PatchEval** (`bytedance/PatchEval`, Apache-2.0, 237★): the best LLM or agent repairs only 23.0% (53/230). — search-result summary of [arXiv 2511.11019](https://arxiv.org/html/2511.11019v1); [repo](https://github.com/bytedance/PatchEval)
  - **ContraFix** (arXiv 2605.17450) evaluates on SEC-bench's 200 C/C++ instances, with code on figshare rather than GitHub. — search-result summary of [arXiv 2605.17450](https://arxiv.org/pdf/2605.17450)

#### Other open LLM remediation frameworks and prior-art prototypes
- **openai/codex-security** (TypeScript · Apache-2.0 · 14,239★ · pushed 2026-11-21): the npm package `@openai/codex-security` provides a CLI, TypeScript SDK and GitHub Action. It can "validate candidate findings, generate patches, and verify existing fixes", import third-party scanner findings, and export SARIF, JSON or CSV. CI uses `OPENAI_API_KEY` or `CODEX_API_KEY`, and the Action uses the secret `CODEX_SECURITY_API_KEY`. Scans support OpenAI, Amazon Bedrock, OpenRouter, Fireworks AI and Cheaper Inference. — [README](https://github.com/openai/codex-security)
- **patched-codes/patchwork** (Python · AGPL-3.0 · 1,580★ · pushed 2026-08-24): a self-hosted CLI agent with "patchflows" such as **AutoFix** and **DependencyUpgrade** (these need the `security` extra, which installs semgrep and depscan). It has steps such as "create PR" and runs locally or in CI with "your preferred LLMs". — [README](https://github.com/patched-codes/patchwork)
- Hackathon-scale prototypes for comparison (all verified, low maturity):
  - `Kokenya/autopatch` (Python · MIT · 0★ · pushed 2026-11-04): "Scanner alerts in, verified pull requests out … (Meta hackathon)".
  - `deenojo/Vulnerability-Remediation-Agent` "Patchwarden" (Python · no license · 0★ · pushed 2026-11-20): "smallest-safe fix PRs, in-place container patching (Copa + Sigstore), deterministic policy gate".
  - `lenaxia/k8s-mechanic` (Go · Apache-2.0 · 60★ · pushed 2026-11-20): opens GitOps PRs with fixes, redacts secrets before LLM calls, and requires a human in the loop.
  - Sources: [autopatch](https://github.com/Kokenya/autopatch), [Patchwarden](https://github.com/deenojo/Vulnerability-Remediation-Agent), [k8s-mechanic](https://github.com/lenaxia/k8s-mechanic)

### Inferences
- For the patch stage when a reproducer exists (a CVE with a PoC, or a fuzz crash in their own C/C++/Java code), the cheapest reusable path is PatchAgent's Python API or PatcherY's CLI. Both take source plus a crash or sanitizer report and return a verified diff. OSS-CRS's `crs-claude-code` and the other `crs-*` patchers suit an ensemble. All of them assume an OSS-Fuzz-style build and harness, so they do not fit Python/JS web apps or dependency-only CVEs.
- OSS-CRS supports LiteLLM proxy routing, so a team could probably point its LLM-backed CRSs at Mistral models through a LiteLLM proxy. I did not test this. The `crs-claude-code` example depends on the Claude Code CLI, which only talks to Anthropic-compatible backends.
- Full CRSs (Atlantis, RoboDuck, ARTIPHISHELL, Lacrosse, BugBuster) are archival and tied to Azure or the competition. They are better read for design patterns (ensembles, LLM-as-judge, post-patch fuzzing, gating patches without a PoV) than run.
- Research success rates (PatchAgent 92%, SAN2PATCH 79.5%) come from curated C/C++ memory-safety datasets with sanitizer oracles. Benchmarks with independent oracles (SEC-bench ≤34%, PatchEval 23%) are much lower. The agent's report should cite which kind of evidence backs a patch.

### Gaps
- I found no published patch success rates for PatchPilot on security benchmarks. Its README describes it as an agentic patching framework, and I did not read the paper.
- The SoK appendix tables with per-team patch submission and acceptance counts were not visible in the fetched portion.
- Whether the ARTIPHISHELL patcher (PatcherY) has been ported to OSS-CRS is unclear. The port's README lists only discovery and fuzzing pipelines.
- AgenticRepair (arXiv 2607.29422) and VulnResolver (arXiv 2601.13933) appeared in search results, but their results and code were not verified.

## Q3. General coding agents for security fixes: do OpenHands, SWE-agent, Aider, Mistral Vibe, Claude Code or Codex CLI have security-fix modes, GitHub Actions or headless CI use that produces a PR, and which are model-agnostic or support Mistral natively?

### Takeaway
Every major coding agent now runs headlessly and most ship a GitHub Action. None ships a dedicated "fix this CVE" mode. The security-specific pieces are review or scan tools (claude-code-security-review), separate products (Codex Security CLI/SDK, which does generate and verify patches) or third-party wrappers (Team Atlanta's `crs-*`). Team Atlanta's 2026 benchmark found off-the-shelf Claude Code, Codex CLI, Gemini CLI and Copilot CLI correctly fix about 57–71% of AIxCC crashes. A three-agent ensemble beat any single agent, and about 20% of patches that pass validation are still semantically wrong. For Mistral, Mistral Vibe is the native choice: Apache-2.0, `vibe --prompt` with JSON output, budgets and exit codes, plus its own GitHub Action, powered by Devstral 2. Goose lists Mistral as a provider. Aider, OpenHands, SWE-agent and mini-swe-agent reach Mistral through LiteLLM or "any LLM" settings. Claude Code and Gemini CLI are tied to their own vendors' models.

### Cited Findings

#### Evidence that coding agents can patch vulnerabilities
- Team Atlanta's "Patching Vulnerabilities with Coding Agents in 2026" setup: 10 configurations (Claude Code v2.1.25, Codex CLI v0.98.0, Gemini CLI v0.28.2 and Copilot CLI v0.0.406/409, crossed with Opus 4.5, Opus 4.6, GPT-5.2 Codex, GPT-5.3 Codex and Gemini 3 Pro) were run on 63 crashes from 24 projects (14 C, 10 Java) from the AIxCC final, with default settings and no custom prompts. Each patch was applied, compiled, tested against the project's test suite and replayed against the crash input, with up to three attempts and failures fed back to the agent. The 630 passing patches were then reviewed manually. — [Team Atlanta](https://team-atlanta.github.io/blog/post-patch-2026-ensemble/)
- Team Atlanta's results:
  - Best configuration: about 45/63 (about 71%) correct and about 80% semantic correctness. Weakest: about 36/63 (about 57%).
  - 2025 baseline (Claude Code v1.0.88 with Claude 3.7 Sonnet): 33/63 (about 52%).
  - Ensembles of N=3 to 10 nearly always beat every single agent, and N=3 gave the best average.
  - About 20% of the best configuration's patches are semantically incorrect, which the authors call "the most dangerous failure mode". The most common problems were altered functionality and patching the symptom instead of the root cause.
  - OpenHands, Aider and SWE-agent were not evaluated. — [Team Atlanta](https://team-atlanta.github.io/blog/post-patch-2026-ensemble/)
- SoK manual review found semantic issues in 20 of 53 patches from the configuration it labels "CC" (37.7%). — [arXiv 2602.07666](https://arxiv.org/html/2602.07666v1). Team Atlanta describes the SoK baseline as Claude Code v1.0.88 with Claude 3.7 Sonnet scoring 33/63, which matches 53 − 20 = 33 and suggests "CC" means Claude Code. — [Team Atlanta](https://team-atlanta.github.io/blog/post-patch-2026-ensemble/)
- SEC-bench: SWE-agent, OpenHands and Aider reach at most 34.0% on vulnerability patching. — [arXiv 2506.11791](https://arxiv.org/abs/2506.11791v2)

#### Agent-by-agent records

**mistralai/mistral-vibe**: https://github.com/mistralai/mistral-vibe
- Metadata: Python · Apache-2.0 · 5,443★ · pushed 2026-11-20. Described as a "Minimal CLI coding agent by Mistral". Installed with `uv tool install mistral-vibe`. It signs in with a Mistral account or API key. Mistral does not accept pull requests to the repo. — [README](https://github.com/mistralai/mistral-vibe)
- Headless mode: `vibe --prompt "…"` (or `-p` with stdin, or `--prompt-file`) with `--auto-approve`/`--yolo`, `--max-turns`, `--max-price DOLLARS`, `--max-tokens`, `--time-limit`, `--output text|json|streaming`, `--output-dir DIR` (writes `export.json` with usage and cost, plus the session journal), `--agent`, `--model`, `--enabled-tools` and `--disabled-tools`.
- Exit codes: 0 finished, 1 usage or config error, 2 infrastructure failure, 3 stopped early (turn, token or price limit, deadline, refusal), 4 aborted.
- Without `--auto-approve`, a tool call that would need approval is denied. An agent TOML can allowlist bash commands, for example only `pytest` and `npm test`. — [programmatic-mode.md](https://github.com/mistralai/mistral-vibe/blob/main/docs/programmatic-mode.md)
- GitHub Action: `action.yml` at the repo root, "Download, install, and run Mistral Vibe", with inputs `prompt` and an API key ("API Key for AI Studio"). The docs folder also includes `acp-setup.md` (Agent Client Protocol) and an experimental agent socket and run server. — [action.yml](https://github.com/mistralai/mistral-vibe/blob/main/action.yml); [docs](https://github.com/mistralai/mistral-vibe/tree/main/docs)
- Models: Devstral 2 (123B, modified MIT license) and Devstral Small 2 (24B, Apache 2.0), launched 2025-12-09 with Vibe CLI. Mistral reports 72.2% and 68.0% on SWE-bench Verified. VentureBeat reads the modified MIT license as barring companies with more than $20M monthly revenue without a commercial license. — [Mistral announcement](https://mistral.ai/news/devstral-2-vibe-cli/); [VentureBeat](https://venturebeat.com/ai/mistral-launches-powerful-devstral-2-coding-model-including-open-source)

**OpenHands/OpenHands**: https://github.com/OpenHands/OpenHands
- Metadata: TypeScript · MIT · 93,942★ · pushed 2026-11-21. Related repos: `OpenHands/software-agent-sdk` (Python · MIT · 1,416★ · pushed 2026-11-21, SDK plus REST Agent Server), `OpenHands/OpenHands-CLI` (MIT · 276★ · pushed 2026-10-22) and `All-Hands-AI/openhands-resolver` (MIT · 135★ · pushed 2024-11-18 · **archived**). — gh API
- "Bring your own model: use with any LLM". It can also run Claude Code, Codex, Gemini, Pi, OpenCode or any agent speaking the Agent Client Protocol. — [README](https://github.com/OpenHands/OpenHands)
- GitHub Action resolver: putting the `fix-me` label on an issue or PR (or writing `@openhands-agent` in a comment) makes OpenHands try a fix. It opens a (draft) PR on success, or pushes a branch and comments on failure. — [OpenHands docs](https://docs.openhands.dev/openhands/usage/run-openhands/github-action); [OpenHands blog](https://www.openhands.dev/blog/open-source-coding-agents-in-your-github-fixing-your-issues); [PyPI openhands-resolver 0.3.0](https://pypi.org/project/openhands-resolver/0.3.0)

**SWE-agent/SWE-agent** and **mini-swe-agent**: https://github.com/SWE-agent/SWE-agent
- Metadata: SWE-agent is Python · MIT · 20,842★ · pushed 2026-11-16. It "takes a GitHub issue and tries to automatically fix it, using your LM of choice" and "can also be employed for offensive cybersecurity". mini-swe-agent is Python · MIT · 9,916★ · pushed 2026-11-16, a "100 line AI agent" that claims more than 74% on SWE-bench Verified. — [SWE-agent](https://github.com/SWE-agent/SWE-agent), [mini-swe-agent](https://github.com/SWE-agent/mini-swe-agent)
- PR output: `sweagent run --env.repo.github_url=… --problem_statement.github_url=<issue>`. The run config has `actions.open_pr` (an OpenPRHook) and `actions.apply_patch_locally`. — [run_single.py](https://github.com/SWE-agent/SWE-agent/blob/main/sweagent/run/run_single.py); [docs](https://github.com/SWE-agent/SWE-agent/blob/main/docs/usage/hello_world.md)

**Aider-AI/aider**: https://github.com/Aider-AI/aider
- Metadata: Python · Apache-2.0 · 50,204★ · pushed 2026-05-22. Activity has slowed (6 months since last push) but it is not stale. — gh API
- Scripting: `aider --message "…" file`, `--yes`, auto-commits on by default, and a Python API. It can lint and test automatically and fix the failures. It uses LiteLLM to connect to providers. — [scripting docs](https://github.com/Aider-AI/aider/blob/main/aider/website/docs/scripting.md); [lint-test](https://github.com/Aider-AI/aider/blob/main/aider/website/docs/usage/lint-test.md); [LLM docs](https://github.com/Aider-AI/aider/blob/main/aider/website/docs/llms/other.md)

**anthropics/claude-code**, **claude-code-action** and **claude-code-security-review**:
- claude-code: TypeScript · no open license on GitHub · 156,509★ · pushed 2026-11-21. claude-code-action: TypeScript · MIT · 10,031★ · pushed 2026-11-21, a "general-purpose … action for GitHub PRs and issues that can answer questions and implement code changes". It runs on your own runner, takes `prompt` and `claude_args`, produces structured JSON outputs and includes a "Security-Focused Reviews" solution. It supports the Anthropic API, AWS Bedrock, Google Vertex AI and Microsoft Foundry. — [claude-code-action README](https://github.com/anthropics/claude-code-action)
- claude-code-security-review: Python · MIT · 7,045★ · pushed 2026-02-11. It analyses PR diffs for vulnerabilities, comments on the PR and filters false positives. It needs an Anthropic API key. This is detection and review only: the README describes no fix generation. — [README](https://github.com/anthropics/claude-code-security-review)

**openai/codex** and **codex-action**:
- codex: Rust · Apache-2.0 · 136,021★ · pushed 2026-11-21. Non-interactive mode is documented on the developers site. codex-action: JavaScript · Apache-2.0 · 1,310★ · pushed 2026-11-18. It runs `codex exec` with `prompt` or `prompt-file`, a sandbox or permission profile and extra `codex-args`. It needs an OpenAI or Azure OpenAI key. Its README example is a PR review bot. — [codex exec.md](https://github.com/openai/codex/blob/main/docs/exec.md); [codex-action README](https://github.com/openai/codex-action)
- The security-specific open component is `openai/codex-security` (see Q2), which generates and verifies patches.

**Others**:
- `google-gemini/gemini-cli` (TypeScript · Apache-2.0 · 108,963★ · pushed 2026-11-21) with the Action `google-github-actions/run-gemini-cli` (Apache-2.0 · 2,129★ · pushed 2026-11-19). — [gemini-cli](https://github.com/google-gemini/gemini-cli); [run-gemini-cli](https://github.com/google-github-actions/run-gemini-cli)
- `anomalyco/opencode` (TypeScript · MIT · 228,314★ · pushed 2026-11-21), formerly sst/opencode: "The open source coding agent". The repo includes a Mistral provider integration (a `patches/@ai-sdk%2Fmistral` patch and Mistral provider assets in the tree). — [repo](https://github.com/anomalyco/opencode)
- `aaif-goose/goose` (Rust · Apache-2.0 · 56,842★ · pushed 2026-11-20), formerly block/goose. Headless runs use `goose run -t "…"`, with a CI/CD integration guide. Mistral AI is listed as a native provider, alongside LiteLLM, Ollama and OpenRouter. — [headless guide](https://github.com/aaif-goose/goose/blob/main/documentation/docs/tutorials/headless-goose.md); [providers](https://github.com/aaif-goose/goose/blob/main/documentation/docs/getting-started/providers.md)
- `cline/cline` (TypeScript · Apache-2.0 · 71,800★ · pushed 2026-11-21): "Autonomous coding agent as an SDK, IDE extension, or CLI". — [repo](https://github.com/cline/cline)
- `GitHubSecurityLab/seclab-taskflow-agent` (MIT · 288★ · pushed 2026-11-06), with taskflows in `GitHubSecurityLab/seclab-taskflows` (MIT · 90★). These are security auditing and GHSA variant-analysis taskflows with custom MCP servers, not remediation. They default to the Copilot API, with other endpoints set through `AI_API_ENDPOINT`. — [seclab-taskflows README](https://github.com/GitHubSecurityLab/seclab-taskflows)

### Inferences
- For a Mistral hackathon, a strong "patch" step is Mistral Vibe in programmatic mode inside a container:
  - `vibe --prompt-file task.md --agent fixer --output json --max-price 2 --time-limit 1800 --output-dir out/`
  - Give the agent a bash allowlist limited to the build, test and PoC commands, and branch on the documented exit codes.
  - Then validate outside the agent (build, tests, scanner re-run, PoC replay) and open the PR with `gh`.
  - The repo's own `action.yml` covers the CI variant.
- Following Team Atlanta, running two or three different agent and model combinations (for example Vibe with Devstral 2, Aider with Mistral through LiteLLM, and OpenHands with "any LLM") and keeping only patches that pass validation should beat any single agent. Cost grows linearly.
- Claude Code, Codex CLI, Gemini CLI and Copilot CLI are the only general agents with published AIxCC-crash patching numbers (about 57–71%), but they do not run Mistral models natively. They are optional fallbacks if the team relaxes the Mistral-only constraint.
- No agent's security mode should be trusted as a fixer. claude-code-security-review only comments. Codex Security does produce patches, but it is OpenAI-centric, with OpenRouter as a possible route to other models.

### Gaps
- Whether Mistral Vibe can call non-Mistral providers (or local Devstral through Ollama or vLLM) was not confirmed. The programmatic docs mention model aliases but no provider list was reviewed.
- Whether Codex CLI can target Mistral's API through a custom OpenAI-compatible provider was not verified. The current `docs/config.md` does not mention Mistral.
- No measured results were found for OpenHands, Aider, SWE-agent or Vibe with Devstral on AIxCC-style crash patching. Only SEC-bench's ≤34% aggregate exists for the first three.
- Gemini CLI headless flags and opencode GitHub integration commands were not checked in their docs.

## Q4. Mitigation without a code patch: virtual patching, WAF rules, feature flags or config, dependency pinning and overrides. Is there open-source automation that generates these from an advisory?

### Takeaway
Open-source enforcement engines are mature: OWASP CRS, Coraza, ModSecurity, CrowdSec AppSec, open-appsec, BunkerWeb and Snuffleupagus for PHP. CrowdSec maintains a hub of curated per-CVE virtual-patch rules (`crowdsecurity/vpatch-CVE-…`) that an agent can install with one command. I found no mature open-source tool that turns an advisory into a validated WAF rule automatically. Such work exists only as research, a small stale repo (WAFSmith) or commercial products. Dependency-level mitigations (overrides and pins) are automated deterministically by OSV-Scanner (Maven overrides), Dependabot (NuGet transitive pins), OpenRewrite (`overrideTransitive`), Socket (`optimize` overrides) and the GitHub Actions pinning tools. I found no open-source automation for advisory-to-feature-flag or config mitigations.

### Cited Findings
- `crowdsecurity/crowdsec` (Go · MIT · 15,731★ · pushed 2026-11-20): "Open-source IDS/IPS, WAF and bot detection". `crowdsecurity/hub` (Python · MIT · 268★ · pushed 2026-11-21) holds its scenarios and rules. — [crowdsec](https://github.com/crowdsecurity/crowdsec), [hub](https://github.com/crowdsecurity/hub)
- CrowdSec's virtual-patching rules:
  - The collection is `crowdsecurity/appsec-virtual-patching`. Per-CVE rules are named `crowdsecurity/vpatch-CVE-YYYY-NNNN` and installed with, for example, `cscli appsec-rules install crowdsecurity/vpatch-CVE-2022-35914`.
  - The rules are "always … blocking rules" evaluated in-band, target specific vulnerabilities with "nearly zero false positive chance", and are recommended alongside the OWASP CRS collection.
  - Test with a request to `/.env`, which should return 403. — [CrowdSec docs: vpatch and CRS](https://docs.crowdsec.net/docs/appsec/vpatch_and_crs); [hub rule example](https://app.crowdsec.net/hub/author/crowdsecurity/waf-rules/vpatch-CVE-2022-35914)
- Other engines:
  - `coreruleset/coreruleset` (Python · Apache-2.0 · 3,365★ · pushed 2026-11-21): "OWASP CRS (Official Repository)".
  - `corazawaf/coraza` (Go · Apache-2.0 · 4,043★ · pushed 2026-11-18): "golang modsecurity compatible web application firewall library".
  - `owasp-modsecurity/ModSecurity` (C++ · Apache-2.0 · 9,883★ · pushed 2026-11-18): WAF engine for Apache, IIS and Nginx.
  - `openappsec/openappsec` (C++ · Apache-2.0 · 1,752★ · pushed 2026-09-06): an ML-based engine that "preemptively and automatically prevents threats".
  - `bunkerity/bunkerweb` (Python · AGPL-3.0 · 11,297★ · pushed 2026-11-20): an open-source, cloud-native WAF.
  - `jvoisin/snuffleupagus` (PHP · LGPL-3.0 · 850★ · pushed 2026-11-20): a PHP security module, "Killing bugclasses and virtual-patching the rest!"
  - Sources: [CRS](https://github.com/coreruleset/coreruleset), [Coraza](https://github.com/corazawaf/coraza), [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity), [open-appsec](https://github.com/openappsec/openappsec), [BunkerWeb](https://github.com/bunkerity/bunkerweb), [Snuffleupagus](https://github.com/jvoisin/snuffleupagus)
- Generating rules from advisories:
  - `tankeehock/wafsmith` (JavaScript · MIT · 10★ · pushed 2025-11-17, **stale**): "A LLM based rule management framework to design and develop good rules for your WAF". — [repo](https://github.com/tankeehock/wafsmith)
  - A web search found "no clearly mature, fully automatic open-source tool that turns a CVE advisory directly into ModSecurity rules". The research and commercial examples it found all keep human review or validation before deployment. — search synthesis over [arXiv 2504.08176](https://arxiv.org/html/2504.08176v1), [Edgescan (commercial)](https://www.edgescan.com/features/ai-powered-waf-rule-generation/), [SpiderLabs arachni2modsec (old, non-LLM)](https://www.levelblue.com/blogs/spiderlabs-blog/modsecurity-advanced-topic-of-the-week-automated-virtual-patching-script)
  - A Substack write-up describes an "AutoDefender" pipeline: advisory plus patch diff, then a vulnerable environment, a validated PoC exploit and finally a WAF rule. It points to virtualpatch.io. Whether the code is open was not confirmed. — [Substack](https://orikabeli.substack.com/p/ai-virtual-patching)
- Dependency-level mitigations without upgrading the direct dependency:
  - OSV-Scanner's `override` strategy writes `<dependencyManagement>` overrides for Maven. — [osv-scanner docs](https://github.com/google/osv-scanner/blob/main/docs/guided-remediation.md)
  - Dependabot pins NuGet transitive dependencies through a direct reference. — [GitHub Docs](https://docs.github.com/en/code-security/dependabot/dependabot-security-updates/about-dependabot-security-updates)
  - OpenRewrite has `overrideTransitive`. — [OpenRewrite docs](https://docs.openrewrite.org/recipes/java/dependencies/dependencyvulnerabilitycheck)
  - `socket optimize` applies `@socketregistry` overrides and `socket patch apply` patches `node_modules`. — [socket-cli](https://github.com/SocketDev/socket-cli)
  - Copa adds a patch layer to an image without a rebuild. — [copacetic](https://github.com/project-copacetic/copacetic)
- Supply-chain compromise mitigations: pinact, ratchet and frizbee pin actions, workflows and images to immutable versions. harden-runner can "block known compromised packages" and apply package cooldowns. Renovate refuses to propose updates that OSV flags as malicious. — [pinact](https://github.com/suzuki-shunsuke/pinact), [ratchet](https://github.com/sethvargo/ratchet), [frizbee](https://github.com/stacklok/frizbee), [harden-runner](https://github.com/step-security/harden-runner), [Renovate docs](https://github.com/renovatebot/renovate/blob/main/docs/usage/configuration-options.md)

### Inferences
- A practical "mitigate" step for the agent:
  - If the exposed asset is behind a WAF the team controls and CrowdSec's hub has `vpatch-<CVE>`, install that rule. Hub coverage for a given CVE must be checked at runtime.
  - Otherwise, have the LLM draft a narrowly scoped Coraza or ModSecurity rule. Test that it blocks a PoC request and passes a benign request set, using CRS's own test tooling or replayed traffic. Present it for human approval rather than deploying automatically. This mirrors what every research and commercial system does.
- For supply-chain compromise signals (a malicious package version or a hijacked action), the deterministic mitigations are a version pin or override plus lockfile regeneration (OSV-Scanner or ecosystem tools) and SHA-pinning of actions (pinact or ratchet). These are fast, auditable and easy to roll back.
- Feature-flag and config mitigations need project-specific knowledge, such as which flag disables the vulnerable endpoint. An LLM can propose them from the advisory text plus the codebase, but no off-the-shelf automation was found.

### Gaps
- I could not confirm which arXiv paper describes AWS's internal "RuleForge", which generates rules from Nuclei templates, or that the system is internal-only. A search result summarised it, but I did not open the paper.
- Open-source feature-flag platforms (OpenFeature, Unleash, Flagsmith) were not researched for advisory-driven automation.
- I did not check what share of recent KEV or high-profile CVEs have CrowdSec vpatch rules, or how fast they are published.

## Q5. Closed-source reference points (one line each, all CLOSED)

### Takeaway
Big vendors in 2025–2026 converged on "agent proposes, validates, human approves". Examples: DeepMind CodeMender, GitHub's agentic Copilot Autofix, OpenAI Codex Security (formerly Aardvark) and Anthropic Claude Code Security. Separately, a "backport the fix into the version you already run" market emerged (Seal, Root.io, now owned by Aikido, and Chainguard Libraries). That approach targets the major-version-upgrade problem directly.

### Cited Findings
- **Google DeepMind CodeMender** (CLOSED, announced 2025-10-06): an AI agent that had upstreamed 72 security fixes at launch. It uses an LLM-based critique to check its changes, all patches are human-reviewed before submission, and it is powered by Gemini Deep Think. There is no public release, only a stated goal to release it eventually. — [DeepMind blog](https://deepmind.google/discover/blog/introducing-codemender-an-ai-agent-for-code-security/)
- **GitHub Copilot Autofix and agentic autofix** (CLOSED): agentic autofix for code scanning alerts reached GA on 2026-10-15 for GitHub Code Security or Advanced Security customers on GHEC. The agent explores the codebase, proposes a fix and re-runs CodeQL to validate it before opening a PR. — [GitHub changelog](https://github.blog/changelog/2026-10-15-agentic-autofix-for-code-scanning-alerts-general-availability); [GitHub Docs](https://docs.github.com/en/code-security/concepts/code-scanning/autofix-for-code-scanning)
- **Azure DevOps** (CLOSED): a Microsoft DevOps blog post dated 2026-10-21 is titled "Introducing agentic autofix for code and dependencies". Only the title was seen. — [Microsoft devblog](https://devblogs.microsoft.com/devops/introducing-agentic-autofix-for-code-and-dependencies/)
- **Snyk Agent Fix** (CLOSED): an "AI security agent" that generates and validates code fixes. The vendor claims fixes are "85%-accurate", which is unverified marketing. — [Snyk page](https://snyk.io/solutions/secure-ai-generated-code/)
- **OpenAI Codex Security, formerly Aardvark** (CLOSED cloud service, with an open Apache-2.0 CLI/SDK client, see Q2): "Aardvark is now Codex Security" as of 2026-03-06, in research preview. It attaches a Codex-generated patch to each finding for one-click patching. — [OpenAI](https://openai.com/index/introducing-aardvark); [SecurityWeek](https://www.securityweek.com/openai-rolls-out-codex-security-vulnerability-scanner/)
- **Anthropic Claude Code Security** (CLOSED, launched 2026-02-20 as a limited research preview for Enterprise and Team customers): scans codebases, proposes patches, and changes nothing without human approval. — [Anthropic](https://www.anthropic.com/news/claude-code-security); [Help Net Security](https://www.helpnetsecurity.com/2026/02/23/anthropic-claude-code-security-scan/)
- **Seal Security** (CLOSED service, open npm CLI): "sealed" packages with backported fixes, rebuilt from the version you already run. Trivy can read Seal's feed, which Trivy labels experimental. — [TechCrunch 2024](https://techcrunch.com/2024/02/13/seal-security-wants-to-make-open-source-vulnerability-remediation-easy); [Trivy docs](https://trivy.dev/docs/dev/guide/coverage/others/seal/)
- **Root.io** (CLOSED, acquired by Aikido Security, announced 2026-06-30): multi-agent research, writing and testing of backported patches for the exact versions customers run, now sold as "Aikido Libraries". A report says patches ship in 15–40 minutes and that more than 80% of analysed cases are remediated without manual changes. Gartner named Root an emerging vendor in "automated vulnerability remediation". — [SiliconANGLE](https://siliconangle.com/2026/06/30/aikido-acquires-root-patch-open-source-without-forced-upgrades/); [Help Net Security](https://www.helpnetsecurity.com/?p=376454)
- **Chainguard** (CLOSED products; Wolfi, melange and apko are open, see Q1): Chainguard Libraries offers CVE remediation for a subset of Python libraries, covering critical and high CVEs only. It runs upstream test suites before and after each fix and publishes advisories in a public VEX feed. — [Chainguard docs](https://edu.chainguard.dev/chainguard/libraries/cve-remediation/)
- **Mobb** and **Pixee** (CLOSED platforms; Bugsy and codemodder are open, see Q1): Mobb ingests Checkmarx, CodeQL, Fortify and Snyk results and produces fixes. Pixee is an "agentic AppSec platform" that writes fixes. — [Bugsy README](https://github.com/mobb-dev/bugsy); [pixee-cli README](https://github.com/pixee/pixee-cli)
- **Edgescan WAF 2.0** (CLOSED): generates vendor-specific WAF rules from validated findings, with human review. — [Edgescan](https://www.edgescan.com/features/ai-powered-waf-rule-generation/)

### Inferences
- The closed products' validation patterns can be copied in open source: re-run the scanner after the fix (Copilot), run upstream tests before and after (Chainguard), use an LLM critic for regressions (CodeMender), and require human approval (everyone). These map directly onto the agent's patch, report and escalate stages.
- Backport-in-place vendors exist because major-version upgrades are the main blocker in practice. An open alternative for a hackathon is an LLM backport: ask the agent to port the upstream fix commit (from the advisory's references) onto the pinned version and validate it with tests. No open-source tool for this was found.

### Gaps
- No independent evaluations of CodeMender, Snyk Agent Fix, Seal or Root patch quality were found. All figures are vendor-reported.
- Docker Hardened Images' current licensing or pricing was not verified. A search returned no relevant result.

## Q6. What remains hard or unsolved for automated vulnerability patching?

### Takeaway
Six problems remain open:
- **Semantic correctness.** Roughly 20–46% of patches that pass build, tests and PoC replay are still wrong or alter behaviour.
- **Transitive dependencies.** Coverage is ecosystem-specific and partial.
- **Major-version and breaking upgrades.** The best LLM approach fixes 27% of breaking-update build failures.
- **Proving no regression.** It depends on test suites the target may not have.
- **Validation cost.** Builds take minutes to hours, and LLM spend can reach $1,000 or more per hour for competition-tuned CRSs.
- **Patching without a PoV.** It is risky, so competitors gated it.

### Cited Findings
- Patch correctness beyond "PoC no longer crashes":
  - The SoK says "patches passing automated checks can still be semantically incorrect". Manual review found semantic issues in 20/53 (37.7%) and 26/57 (45.6%) of patches from two evaluated configurations. Failure modes include the wrong root cause (for example a hard-coded iteration limit to stop an infinite loop), incomplete fixes, changed functionality, new bugs and missing domain knowledge. "Automated patch accuracy remains an open challenge." — [arXiv 2602.07666](https://arxiv.org/html/2602.07666v1)
  - Team Atlanta found about 20% of the best configuration's patches semantically incorrect, which "automation cannot detect". Of 145 semantically incorrect patches, 55 altered functionality and 38 patched the symptom rather than the root cause. — [Team Atlanta](https://team-atlanta.github.io/blog/post-patch-2026-ensemble/)
- Patching without a PoV: only three AIxCC teams tried it, and they limited volume or delayed submission because of the risk. — [arXiv 2602.07666](https://arxiv.org/html/2602.07666v1)
- Validation cost and time:
  - Validating a patch "in large codebases takes minutes if not hours (e.g., 10+ minutes for nginx)". — [Team Atlanta blog, search snippet](https://team-atlanta.github.io/blog/post-crs-patch-integration)
  - The AIxCC average was about 45 minutes and about $152 per task. — [DARPA](https://www.darpa.mil/news/2025/aixcc-results)
  - Theori's CRS "can easily spend $1,000 or more in under an hour". — [Theori README](https://github.com/theori-io/aixcc-afc-archive)
- Build fragility: "a target that built last month may not build today: an OSS-Fuzz recipe that clones a dependency at `master` picks up whatever is there now." — [FuzzingBrain README](https://github.com/fuzzingbrain/afc-crs-all-you-need-is-a-fuzzing-brain)
- Transitive dependencies:
  - Renovate's OSV mode covers direct dependencies only (except uv). — [Renovate docs](https://github.com/renovatebot/renovate/blob/main/docs/usage/configuration-options.md)
  - Dependabot cannot update transitive dependencies that require a parent update outside npm and NuGet. — [GitHub Docs](https://docs.github.com/en/code-security/dependabot/dependabot-security-updates/about-dependabot-security-updates)
  - OSV-Scanner `fix` supports only npm and Maven, ignores npm `overrides`, mishandles `peerDependencies` and only partly supports workspaces. — [osv-scanner docs](https://github.com/google/osv-scanner/blob/main/docs/guided-remediation.md)
- Major-version and breaking upgrades:
  - Byam (KTH, arXiv 2505.07522) repairs client code broken by dependency updates. On the BUMP benchmark (103 breaking Java updates) the best model (o3-mini) repaired 27% of failed builds and removed 78% of individual errors. Scope is limited to compilation errors. — search-result summary of [arXiv 2505.07522](https://arxiv.org/abs/2505.07522)
  - BUMP dataset: `chains-project/bump` (MIT · 26★ · pushed 2026-06-25). — [repo](https://github.com/chains-project/bump)
  - OSV-Scanner calls `relax` "potentially breaking". — [osv-scanner docs](https://github.com/google/osv-scanner/blob/main/docs/guided-remediation.md)
  - Copa recommends `patch` level as the default. — [Copa docs](https://github.com/project-copacetic/copacetic/blob/main/website/docs/app-level-patching.md)
- Proving no regression:
  - Dependabot's compatibility score comes from other repositories' CI, not yours. — [GitHub Docs](https://docs.github.com/en/code-security/dependabot/dependabot-security-updates/about-dependabot-security-updates)
  - Chainguard runs full upstream test suites before and after a fix. — [Chainguard](https://edu.chainguard.dev/chainguard/libraries/cve-remediation/)
  - The SoK notes functional tests missed some behavioural changes, and BugBuster skipped project tests altogether. — [arXiv 2602.07666](https://arxiv.org/html/2602.07666v1)
- Bot misbehaviour: Renovate warns of "flapping/looping" vulnerability fixes when alerts are wrong and recommends checking automerged fixes. — [Renovate docs](https://github.com/renovatebot/renovate/blob/main/docs/usage/configuration-options.md)
- Generalisation: benchmarks with independent oracles show low agent success (SEC-bench ≤34% patching; PatchEval best 23.0%), compared with 79–92% on curated memory-safety datasets. — [SEC-bench](https://arxiv.org/abs/2506.11791v2); [PatchEval (search summary)](https://arxiv.org/html/2511.11019v1); [PatchAgent](https://www.usenix.org/conference/usenixsecurity25/presentation/yu-zheng); [SAN2PATCH](https://www.usenix.org/conference/usenixsecurity25/presentation/kim-youngjoon)

### Inferences
- The agent's validation gate should run, in order: build, existing tests, scanner re-run (OSV-Scanner, Trivy or CodeQL), PoC replay when one exists, then an LLM critic asked "is this a root-cause fix, and did behaviour change?". Even after all of this, the agent should escalate to a human, because about 20% of fully validated patches can still be wrong.
- The report stage should state the evidence level honestly: "tests passed" versus "PoC no longer reproduces" versus "no PoC available; scanner no longer flags", along with upgrade size (patch, minor or major) and whether the change was a transitive override.
- Major-version bumps, unfixable transitive vulnerabilities and patches without a PoV are the natural escalation triggers. Mitigations (WAF rule, pin or override, Copa image patch) can be applied as a stopgap while humans decide.

### Gaps
- No quantitative study was found on how often vulnerability-fix PRs from Dependabot or Renovate break builds in practice.
- The SoK's Section VIII (lessons and future directions) was only partly read, because the fetch was truncated at 100k characters.
