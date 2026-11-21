# Benchmarks, datasets and vulnerable environments for evaluating and demoing a security incident response agent (state as of 2026-11-21)

Scope: evaluation resources and demo targets only, for an agent that ingests a vulnerability signal, assesses exposure, mitigates, patches (verified PR), reports (incident report / VEX) and escalates. Every GitHub repo below was checked with `gh api repos/OWNER/REPO` on 2026-11-21. "Stale" means no push in 12+ months (before 2025-11-21). Leaderboard numbers are as published. Where the source is the benchmark maintainer, a vendor or an aggregator, that is said.

## Q1. Which agentic security benchmarks with code on GitHub test vulnerability reproduction, exploitability assessment or patching from a CVE or description? Task formats, sizes, metrics, best published results

### Takeaway
PoC reproduction and patching are well covered by maintained, Docker-based benchmarks: PatchEval-Verified, SEC-bench / SEC-bench Pro, CyberGym / CyberGym-E2E, CVE-Bench, BountyBench, ARVO and Vul4J. Most are C/C++ and derived from OSS-Fuzz, so the closest fit for an npm/PyPI-oriented agent is PatchEval-Verified (Go/JS/Python, 230 Dockerized CVEs), with SecBench.js as a JS exploit corpus. Frontier agents now score about 65 to 90% on several of these benchmarks, and a November 2026 audit found inconsistencies in 22.4% of CyberGym tasks. Headline scores are saturating and need careful reading.

### Cited Findings

#### Verified repo metadata (gh api, 2026-11-21)

| Resource | Repo | Stars | Last push | License | Status |
|---|---|---|---|---|---|
| CyberGym | [sunblaze-ucb/cybergym](https://github.com/sunblaze-ucb/cybergym) | 1,053 | 2026-08-28 | Apache-2.0 | active |
| CyberGym-E2E | [sunblaze-ucb/cybergym-e2e](https://github.com/sunblaze-ucb/cybergym-e2e) | 110 | 2026-11-18 | Apache-2.0 | active |
| ExploitGym | [sunblaze-ucb/exploitgym](https://github.com/sunblaze-ucb/exploitgym) | 1,312 | 2026-11-14 | Apache-2.0 | active |
| CyberBinGym | [sunblaze-ucb/cyberbingym](https://github.com/sunblaze-ucb/cyberbingym) | 4 | 2026-11-11 | MIT | active |
| SEC-bench | [SEC-bench/SEC-bench](https://github.com/SEC-bench/SEC-bench) | 107 | 2026-01-27 | MIT | active |
| SEC-bench Pro | [SEC-bench/SEC-bench-Pro](https://github.com/SEC-bench/SEC-bench-Pro) | 71 | 2026-09-21 | MIT | active |
| SecVerifier (SEC-bench helper) | [SEC-bench/SecVerifier](https://github.com/SEC-bench/SecVerifier) | 8 | 2025-06-20 | MIT | stale |
| CVE-Bench (UIUC, exploitation) | [uiuc-kang-lab/cve-bench](https://github.com/uiuc-kang-lab/cve-bench) | 318 | 2026-09-24 | Apache-2.0 | active |
| BountyBench | [bountybench/bountybench](https://github.com/bountybench/bountybench) | 115 | 2025-07-24 | Apache-2.0 | stale (16 months) |
| ARVO (generator) | [n132/ARVO](https://github.com/n132/ARVO) | 117 | 2026-09-14 | BSD-2-Clause | active |
| ARVO-Meta (dataset) | [n132/ARVO-Meta](https://github.com/n132/ARVO-Meta) | 121 | 2026-11-21 | BSD-2-Clause | active |
| PatchEval | [bytedance/PatchEval](https://github.com/bytedance/PatchEval) | 237 | 2026-10-19 | Apache-2.0 | active |
| VulnRepairEval | [WWILLV/VulnRepairEval](https://github.com/WWILLV/VulnRepairEval) | 0 | 2025-10-11 | none | stale; PoCs withheld |
| SecRepoBench | [ai-sec-lab/SecRepoBench](https://github.com/ai-sec-lab/SecRepoBench) | 10 | 2026-09-03 | MIT | active |
| SecureVibeBench (ex-SecureAgentBench) | [iCSawyer/SecureVibeBench](https://github.com/iCSawyer/SecureVibeBench) | 21 | 2026-11-19 | MIT | active (old repo [iCSawyer/SecureAgentBench](https://github.com/iCSawyer/SecureAgentBench) is archived) |
| Vul4J | [tuhh-softsec/Vul4J](https://github.com/tuhh-softsec/Vul4J) | 148 | 2026-10-27 | GPL-3.0 | active |
| CVEfixes | [secureIT-project/CVEfixes](https://github.com/secureIT-project/CVEfixes) | 379 | 2024-07-30 | NOASSERTION | stale |
| MegaVul | [Icyrockton/MegaVul](https://github.com/Icyrockton/MegaVul) | 160 | 2025-01-12 | GPL-3.0 | stale |
| CVE-Genie | [BUseclab/cve-genie](https://github.com/BUseclab/cve-genie) | 109 | 2026-02-12 | Apache-2.0 | active |
| CyberSecEval 4 / AutoPatchBench | [meta-llama/PurpleLlama](https://github.com/meta-llama/PurpleLlama) | 4,487 | 2026-11-20 | NOASSERTION | active |
| CyberSOCEval data | [CrowdStrike/CyberSOCEval_data](https://github.com/CrowdStrike/CyberSOCEval_data) | 25 | 2025-09-22 | NOASSERTION | stale |
| CTIBench (moved from xashru/cti-bench) | [maveryn/cti-bench](https://github.com/maveryn/cti-bench) | 95 | 2026-05-07 | NOASSERTION | active |
| ExCyTIn-Bench | [microsoft/SecRL](https://github.com/microsoft/SecRL) | 165 | 2026-11-16 | MIT | active |
| SecBench.js | [cristianstaicu/SecBench.js](https://github.com/cristianstaicu/SecBench.js) | 47 | 2026-08-20 | none (no license file) | active |
| OpenSSF CVE Benchmark | [ossf-cve-benchmark/ossf-cve-benchmark](https://github.com/ossf-cve-benchmark/ossf-cve-benchmark) | 175 | 2024-03-12 | MIT | stale |
| OSS-Fuzz vulns (OSV feed) | [google/oss-fuzz-vulns](https://github.com/google/oss-fuzz-vulns) | 195 | 2026-11-20 | CC-BY-4.0 | active |
| Cybench (CTF) | [andyzorigin/cybench](https://github.com/andyzorigin/cybench) | 360 | 2026-10-17 | Apache-2.0 | active |
| NYU CTF Bench | [NYU-LLM-CTF/NYU_CTF_Bench](https://github.com/NYU-LLM-CTF/NYU_CTF_Bench) | 189 | 2025-09-22 | GPL-2.0 | stale |
| BaxBench (secure codegen) | [logic-star-ai/baxbench](https://github.com/logic-star-ai/baxbench) | 111 | 2026-01-30 | MIT | active |
| A.S.E / AICGSecEval (secure codegen) | [Tencent/AICGSecEval](https://github.com/Tencent/AICGSecEval) | 667 | 2026-05-25 | NOASSERTION | active |
| SecCodeBench (secure codegen) | [alibaba/sec-code-bench](https://github.com/alibaba/sec-code-bench) | 136 | 2026-10-12 | Apache-2.0 | active |
| PrimeVul (detection) | [DLVulDet/PrimeVul](https://github.com/DLVulDet/PrimeVul) | 283 | 2024-09-07 | MIT | stale |
| FailSafe Swarm results on CVE-Bench | [failsafe-security/failsafe-swarm](https://github.com/failsafe-security/failsafe-swarm) | 66 | 2026-08-14 | MIT | vendor results repo |
| AIxCC exemplar challenge | [aixcc-public/challenge-001-exemplar](https://github.com/aixcc-public/challenge-001-exemplar) | 59 | 2024-04-03 | MIT | stale |
| AIxCC nginx challenge | [aixcc-public/challenge-004-nginx-cp](https://github.com/aixcc-public/challenge-004-nginx-cp) | 5 | 2024-09-14 | not checked | stale |
| AIxCC finals OSS-Fuzz fork | [aixcc-finals/oss-fuzz-aixcc](https://github.com/aixcc-finals/oss-fuzz-aixcc) | 3 | 2025-09-10 | not checked | stale |
| AIxCC winner CRS (Team Atlanta) | [Team-Atlanta/aixcc-afc-atlantis](https://github.com/Team-Atlanta/aixcc-afc-atlantis) | 664 | 2025-11-25 | NOASSERTION | nearly stale |
| AIxCC 2nd place CRS (Trail of Bits) | [trailofbits/buttercup](https://github.com/trailofbits/buttercup) | 1,758 | 2026-11-02 | AGPL-3.0 | active |

None of the repos above is archived, except SecureAgentBench (moved to SecureVibeBench) and kozmer/log4j-shell-poc (see Q3). These repos were not found and are not listed as repos: `aixcc-sc/*` (the org returns 404), `ARVO-AI/ARVO`, `aisleinc/HoF-Bench` (exists only as a Hugging Face dataset), and a GitHub repo for the NAACL 2025 "CVE-Bench" repair benchmark.

#### Vulnerability reproduction / PoC generation (exploitability evidence from a description)
- **CyberGym (ICLR 2026).** 1,507 real-world vulnerabilities across 188 projects (from ARVO and OSS-Fuzz). The primary task (Level 1) gives the agent a text description plus the unpatched codebase and asks for a PoC that reproduces the vulnerability. The paper reported top agent+model combinations at about 20% and the discovery of 34 zero-days and 18 historically incomplete patches — [arXiv 2506.02548](https://arxiv.org/abs/2506.02548); [ICLR 2026 proceedings](https://proceedings.iclr.cc/paper_files/paper/2026/hash/c876a2935a90aff21874e14c07dc3e33-Abstract-Conference.html)
- CyberGym success definition: a PoC counts only if it triggers the bug on the pre-patch build and not on the post-patch build. Level 0 is no description (only 3.5% reproducible). Level 2 adds a stack trace, Level 3 adds the ground-truth patch. The leaderboard labels "dynamic" (agent ran the binary) and "test-time mem." runs — [CyberGym leaderboard page](https://www.cybergym.io/cybergym/)
- CyberGym reproducibility cost: the binary-only server data is about 130 GB, the full download is about 240 GB, and the full compile-environment Docker images are about 10 TB. A 10-task subset (5 easy, 5 hard) is provided. The README warns never to expose the server publicly and ships a Squid domain-allowlist firewall — [sunblaze-ucb/cybergym README](https://github.com/sunblaze-ucb/cybergym)
- CyberGym saturation and reliability: a November 2026 audit of all 1,507 tasks flagged 338 (22.4%) as having inconsistent task materials. On one full Level-1 GLM-5.3 run, 1,286 differential passes (85.3%) dropped to 78.8% when the PoC also had to hit the intended defect — [arXiv 2611.25790](https://arxiv.org/abs/2611.25790)
- Third-party aggregators report CyberGym top scores of 83.8% to 88.9% in 2026 (e.g., a July 2026 snapshot: 86.9% top, "GPT-5.6 Sol" 84.5%). These attributions conflict across aggregators and were not checked against vendor system cards — [BenchLM CyberGym page](https://www.benchlm.ai/benchmarks/cyberGym); [benchmarklist.com](https://benchmarklist.com/benchmarks/cybergym/)
- **SEC-bench (NeurIPS 2025).** Builds Docker-reproducible C/C++ vulnerability instances from OSV/CVE records automatically, at $0.87 per instance, with two tasks: PoC generation and vulnerability patching. At release the best agents reached 18.0% on PoC and 34.0% on patching — [arXiv 2506.11791](https://arxiv.org/abs/2506.11791). The paper verifies 200 CVE instances — [arXiv PDF](https://arxiv.org/pdf/2506.11791)
- SEC-bench leaderboard. Patching: AgenticRepair + GPT-5.2 75% and AgenticRepair + GPT-5-mini 50% (University of Melbourne, 2026-01-15), OpenHands + Claude-3.7-Sonnet 34%. PoC (poc-san mode): OpenHands + Claude-3.7-Sonnet 18%. OSS-Fuzz instances were added in December 2025. Pre-built eval images are on Docker Hub, and the README recommends more than 200 GB of disk — [sec-bench.github.io](https://sec-bench.github.io/); [SEC-bench README](https://github.com/SEC-bench/SEC-bench)
- **SEC-bench Pro (May 2026).** 344 verified long-horizon cases across V8, SpiderMonkey and the Linux kernel. In the paper, Codex + GPT-5.5 solves 58% overall and GLM-5 solves 13 of 344. OpenAI used it for GPT-5.5-Cyber and GPT-5.6 evaluations — [arXiv 2605.26548](https://arxiv.org/abs/2605.26548); [SEC-bench-Pro README](https://github.com/SEC-bench/SEC-bench-Pro)
- SEC-bench Pro overall leaderboard (183 instances: V8 103 + Firefox 80). Top entries are vendor-reported: Gemini 4 Neon 90.5%, GPT-6.2 Sol 88.34%, GPT-6 Cyber 87.02%. Harness runs: Opus 5 (max) with AWS Continuum 71.6%, Opus 5 with Claude Code 64.5%, GPT-5.5 (xhigh) with Codex 46.4%. Open-weight agents: GLM-5 3.8%, Kimi K2.5 2.2%, MiniMax M2.5 0%. Linux tasks need an x86-64 host with `/dev/kvm` — [sec-bench.github.io](https://sec-bench.github.io/); [leaderboards.yaml](https://github.com/SEC-bench/sec-bench.github.io/blob/main/data/leaderboards.yaml); [SEC-bench-Pro README](https://github.com/SEC-bench/SEC-bench-Pro)
- **CVE-Genie.** A multi-agent framework that turns a CVE entry into a rebuilt vulnerable environment plus a verifiable exploit. It reproduced about 51% (428 of 841) of CVEs published in 2024 to 2025, at an average of $2.77 per CVE, and is proposed as a way to generate CVE benchmarks — [arXiv 2509.01835](https://arxiv.org/abs/2509.01835); [BUseclab/cve-genie](https://github.com/BUseclab/cve-genie)
- **HoF-Bench (July 2026).** 95 public AI-discovered CVEs (from AISLE's Hall of Fame) across 8 repos pinned at vulnerable commits. Detectors get scope but no CVE text, and a blinded judge requires the same code path, root cause and impact. A minimal analyzer using small/open models rediscovers up to 65 of 95 (68%). Distributed only on Hugging Face — [arXiv 2607.27030](https://arxiv.org/abs/2607.27030); [HF dataset](https://huggingface.co/datasets/aisleinc/HoF-Bench)

#### Patching benchmarks (closest to "open a PR with a verified fix")
- **PatchEval.** 1,000 vulnerabilities from CVEs reported 2015 to 2025 in Go, JavaScript and Python, covering 65 CWEs. 230 CVEs have runtime sandboxes for security tests plus functionality tests — [arXiv 2511.11019](https://arxiv.org/abs/2511.11019)
- **PatchEval-Verified (released 2026-07-24).** 230 CVEs with revised PoC tests that check whether the vulnerability is still exploitable, without requiring the official patch's implementation. Two stages: generate patches with a CLI agent, then evaluate in Docker. Pass@1 leaderboard from the maintainer README: Codex + gpt-5.6-sol 193/230 (83.91%), Codex + gpt-5.5 81.30%, Codex + DeepSeek-V4-Flash-0731 80.43%, Trae + seed-2.1-turbo 72.17%, Opencode + GLM 5.2 66.96%, Opencode + qwen3.7 plus 62.61%. No Mistral model is listed — [bytedance/PatchEval README](https://github.com/bytedance/PatchEval)
- **CyberGym-E2E (June 2026).** 920 real-world vulnerabilities across 139 projects. Modes: end-to-end (code only; find the bug, write `poc.bin` and `fix.patch`) and patch-only (given the crash log and PoC). Staged validation: S1 the agent's PoC crashes the unpatched build, S2 the patch fixes it, S3 the project tests pass (S1 to S3 = end-to-end success), S4 the ground-truth PoC is also fixed — [arXiv 2606.04460](https://arxiv.org/abs/2606.04460); [cybergym-e2e README](https://github.com/sunblaze-ucb/cybergym-e2e)
- CyberGym-E2E results on 920 tasks ($10 and 90 minutes per task unless noted):

  | Model + harness | Patch-only | End-to-end (S3) | S4 |
  |---|---|---|---|
  | GPT-5.4 + Codex | 87.1% | 65.9% | 22.2% |
  | Opus 4.6 + Claude Code, no budget cap | 85.8% | 62.6% | 26.2% |
  | Opus 4.6 + Claude Code | 84.1% | 37.9% | 15.7% |
  | Gemini 3.1 Pro + Gemini CLI | 83.0% | 43.8% | 20.5% |

  The dataset was repacked on 2026-11-16 to fix a task-material leak — [RDI blog](https://rdi.berkeley.edu/blog/cybergym-e2e); [cybergym-e2e README](https://github.com/sunblaze-ucb/cybergym-e2e)
- **BountyBench.** 25 real systems with 40 bug bounties ($10 to $30,485, covering 9 of the OWASP Top 10) and three tasks: Detect, Exploit, Patch. With up to three attempts: Codex CLI + o3-high 12.5% Detect and 90% Patch; Codex CLI + o4-mini 90% Patch; Claude Code 87.5% Patch and 57.5% Exploit; custom agent + Claude 3.7 Sonnet Thinking 67.5% Exploit. Environments were set up by hand (servers, databases). The repo is stale — [arXiv 2505.15216](https://arxiv.org/abs/2505.15216); [bountybench repo](https://github.com/bountybench/bountybench)
- **VulnRepairEval.** A repair counts as successful only if the original working PoC exploit fails on the patched code. 23 Python CVEs (2017 to 2024), curated from 400+ CVEs and about 2,500 PoC sources. The best of 12 LLMs fixed 5 of 23 (21.7%). PoC exploits are restricted to vetted researchers, and the harness needs 64 GB of disk and 16 GB of RAM — [arXiv 2509.03331](https://arxiv.org/abs/2509.03331); [VulnRepairEval README](https://github.com/WWILLV/VulnRepairEval)
- **AutoPatchBench (CyberSecEval 4).** Asks an agent to fix C/C++ crashes found by fuzzing. Full set 142 cases, lite 120, samples 20. Needs Podman, and the first run builds 200+ container images over several hours — [PurpleLlama CybersecurityBenchmarks README](https://github.com/meta-llama/PurpleLlama/blob/main/CybersecurityBenchmarks/README.md)
- **CVE-Bench (NAACL 2025 repair benchmark; different from UIUC's CVE-Bench).** 509 CVEs from 4 languages and 120 repos. SWE-agent repairs at most 21%. No GitHub repo was found or verified — [ACL Anthology](https://preview.aclanthology.org/setup/2025.naacl-long.212)
- **Vul4J.** Java vulnerabilities with human patches and Proof-of-Vulnerability (PoV) tests. A Docker build on 2026-05-20 completed all 129 entries: 79 reproduced via PoV tests and 50 are SpotBugs-only entries — [Vul4J README](https://github.com/tuhh-softsec/Vul4J)
- **SecBench.js (ICSE 2023).** 600 server-side npm vulnerabilities with executable exploits: prototype pollution 192, ReDoS 98, command injection 101, path traversal 169, arbitrary code injection 40. Folders are named by vulnerable package and version, so a patch can be validated by checking that the exploit no longer works. There is no license file — [SecBench.js README](https://github.com/cristianstaicu/SecBench.js)

#### Exploitation benchmarks (offense-side evidence of exploitability; lower priority for a defender agent)
- **CVE-Bench (UIUC, ICML 2025 spotlight).** 40 critical-severity web-application CVEs run as Docker services, graded by 8 outcomes (DoS, file access, RCE, database modification or access, admin login, privilege escalation, outbound request). Zero-day and one-day settings. Built on Inspect, amd64 recommended. v2.0.0 (2025-10-30) followed the Agentic Benchmark Checklist, and v2.1.0 (2026-01-12) replaced arbitrary file upload with RCE. The original paper reported at most 13% — [cve-bench README](https://github.com/uiuc-kang-lab/cve-bench); [arXiv 2503.17332](https://arxiv.org/abs/2503.17332)
- A vendor (FailSafe) self-reports 62.5% zero-day and 70% one-day pass@1 on CVE-Bench v2.1.0 with a DeepSeek-V4 / Kimi pipeline, graded by CVE-Bench's oracle — [failsafe-swarm README](https://github.com/failsafe-security/failsafe-swarm)
- **ExploitGym.** Exploit development on real vulnerabilities in userspace programs, V8 and the Linux kernel. Ships a controller, a firewall and an LLM proxy. Task counts and results were not retrieved — [exploitgym README](https://github.com/sunblaze-ucb/exploitgym)
- **CyberBinGym.** 100 curated samples. Each gives a pair of vulnerable and patched binaries and scores proof-of-crash and/or exploitability against a victim service in a one-day setting. Uses public Docker images, including `n132/arvo`, and Inspect — [cyberbingym README](https://github.com/sunblaze-ucb/cyberbingym)
- **Cybench** (40 tasks from four CTF competitions) and **NYU CTF Bench** are CTF-style, not CVE-driven — [cybench README](https://github.com/andyzorigin/cybench); [NYU_CTF_Bench](https://github.com/NYU-LLM-CTF/NYU_CTF_Bench)

#### Reproducible vulnerability datasets (raw material for building your own eval)
- **ARVO (EuroS&P 2026).** More than 6,100 reproducible OSS-Fuzz vulnerabilities across 311 projects. Reproduces 81% of them and locates patches with 89.4% accuracy. Each record has Docker images for the vulnerable and fixed versions, a PoC, the fix and the expected crash output, in `arvo.db`. The README reports more than 20M Docker Hub pulls — [arXiv 2606.17283](https://arxiv.org/abs/2606.17283); [ARVO-Meta README](https://github.com/n132/ARVO-Meta); [ARVO README](https://github.com/n132/ARVO)
- **CVEfixes v1.0.8.** Covers CVEs up to 2024-07-23: 12,107 fixing commits in 4,249 projects, 11,873 CVEs, 272 CWEs, with code before and after for 51,342 files and 138,974 functions. Released on Zenodo. Stale — [CVEfixes README](https://github.com/secureIT-project/CVEfixes)
- **MegaVul.** 17,380 C/C++ vulnerabilities from 992 repos, 169 CWE types, January 2006 to October 2023. Java support was added later. Stale — [arXiv 2406.12415](https://arxiv.org/abs/2406.12415); [MegaVul README](https://github.com/Icyrockton/MegaVul)
- **OpenSSF CVE Benchmark.** More than 200 real JS/TS CVEs for scoring SAST tools. It also analyzes the patched versions so false-positive rates can be measured. Stale — [ossf-cve-benchmark README](https://github.com/ossf-cve-benchmark/ossf-cve-benchmark)

#### Triage / ingest-side benchmarks (CVE understanding, severity, SOC)
- **CTIBench (NeurIPS 2024 Datasets and Benchmarks spotlight).** 4,610 examples: CTI-MCQ 2,500; CTI-RCM 1,000 (CVE to CWE root-cause mapping); CTI-VSP 1,000 (predict the CVSS v3.1 vector string); CTI-ATE 60; CTI-TAA 50. On Hugging Face as AI4Sec/cti-bench — [cti-bench README](https://github.com/maveryn/cti-bench); [arXiv 2406.07599](https://arxiv.org/abs/2406.07599)
- **ExCyTIn-Bench.** Threat investigation over 57 Microsoft Sentinel log tables with 7,542 generated questions. Best reward in the paper was 0.606. The repo chart was updated with Claude Opus 4.5 and GPT-5.1 in November 2025 — [arXiv 2507.14201](https://arxiv.org/abs/2507.14201); [microsoft/SecRL](https://github.com/microsoft/SecRL)
- **CyberSOCEval (Meta + CrowdStrike, part of CyberSecEval 4).** Malware analysis and threat-intelligence reasoning. The authors say current LLMs are far from saturating it — [arXiv 2509.20166](https://arxiv.org/abs/2509.20166); [CyberSOCEval_data](https://github.com/CrowdStrike/CyberSOCEval_data)

#### Secure code generation (adjacent; low fit for incident response)
- **SecRepoBench (LLM4Code'26).** 318 repo-level code-completion tasks in 27 C/C++ repos, 15 CWEs. Evaluated 29 LLMs and 15 agents (Aider, OpenHands, Claude Code) run inside ARVO containers — [arXiv 2504.21205](https://arxiv.org/abs/2504.21205); [SecRepoBench README](https://github.com/ai-sec-lab/SecRepoBench)
- **SecureVibeBench (ACL 2026).** 105 C/C++ tasks from 41 OSS-Fuzz projects that reconstruct where a human introduced a vulnerability. Best agent: 23.8% of solutions both correct and secure. v0.2 (2026-10-29) adds a PyPI package and Harbor-format tasks — [arXiv 2509.22097](https://arxiv.org/abs/2509.22097); [SecureVibeBench README](https://github.com/iCSawyer/SecureVibeBench)
- BaxBench (secure backend generation), A.S.E (repo-level tasks built from real CVE patches) and SecCodeBench also measure secure generation, not incident response — [baxbench](https://github.com/logic-star-ai/baxbench); [AICGSecEval](https://github.com/Tencent/AICGSecEval); [sec-code-bench](https://github.com/alibaba/sec-code-bench)

#### "Security subsets of SWE-bench"
- No official security subset of SWE-bench was found in a targeted search. The closest SWE-bench-style security benchmarks are separate projects: SEC-bench ([arXiv 2506.11791](https://arxiv.org/abs/2506.11791)), the NAACL 2025 CVE-Bench ([ACL Anthology](https://preview.aclanthology.org/setup/2025.naacl-long.212)), PatchEval ([arXiv 2511.11019](https://arxiv.org/abs/2511.11019)) and SecureVibeBench, which calls itself the first SWE-bench-level secure-coding benchmark ([README](https://github.com/iCSawyer/SecureVibeBench)).

#### AIxCC challenge sets
- The AIxCC final used 53 challenge projects in C and Java, derived from real open-source projects with synthetic vulnerabilities inserted. All finalist cyber reasoning systems (CRSs) are being open-sourced, with some artifacts subject to DARPA's release timeline — [SoK: DARPA's AIxCC, arXiv 2602.07666](https://arxiv.org/html/2602.07666v1); [DARPA AIxCC results](https://darpa.mil/news/2025/aixcc-results)
- What is publicly verifiable on GitHub: the 2024 exemplar challenges (Linux kernel, nginx) under `aixcc-public`, a finals OSS-Fuzz fork under `aixcc-finals`, and the CRSs of Team Atlanta (winner) and Trail of Bits (Buttercup, second place) — repos in the table above; [Trail of Bits blog](https://blog.trailofbits.com/2025/08/09/trail-of-bits-buttercup-wins-2nd-place-in-aixcc-challenge/)

### Inferences
- For a hackathon agent that patches npm/PyPI projects, **PatchEval-Verified** is the best ready-made patch metric: Go/JS/Python, 230 Dockerized CVEs, exploit-based validation, and a two-stage "generate with any CLI agent, then evaluate" flow. A 20 to 40 CVE JS/Python subset should fit a hackathon compute budget. That budget estimate is an inference, not a published figure.
- **SEC-bench (patch split)** and **CyberGym-E2E patch-only** are good if the team wants C/C++ coverage or comparability with frontier-lab numbers. Their disk and compute footprint (200+ GB, OSS-Fuzz builds) is heavy for a weekend.
- CyberGym Level 1 is near saturation in late 2026 (about 79 to 85% on a full run) and has documented task-material issues. Treat it as a capability reference, not a differentiator.
- None of the benchmarks evaluates the whole incident-response loop (ingest, then exposure, mitigation, PR, VEX report and escalation). CyberGym-E2E (find, PoC, patch) and BountyBench (detect, exploit, patch) come closest on the vulnerability side.
- No Mistral model appears in the PatchEval-Verified table or the SEC-bench / SEC-bench Pro leaderboards that were retrieved, so a Mistral-based result on any of them would be new.

### Gaps
- The official CyberGym leaderboard renders dynamically and could not be read. 2026 top scores are known only from aggregators, which conflict on model attribution.
- Per-model numbers from the original PatchEval paper, the SecRepoBench leaderboard, ExploitGym results and A.S.E dataset size were not retrieved.
- SEC-bench Pro's top entries come from vendor announcements linked in its leaderboard YAML and were not independently reproduced.
- Could not confirm whether DARPA has published the full AIxCC final challenge set and telemetry.
- No GitHub repo found for the NAACL 2025 CVE-Bench repair benchmark. VADER (a human-evaluated vulnerability assessment and remediation benchmark) could not be found or verified.

## Q2. Is there any benchmark or dataset specifically for exposure/reachability decisions ("is project X affected by CVE Y?") or VEX-justification accuracy?

### Takeaway
No. No public, labeled benchmark of useful size exists for project-level "affected / not affected" verdicts or VEX-justification accuracy. NVIDIA's blueprint ships only a 3-case smoke fixture. The 54-case SCARVA set (November 2026) has no public release that could be found. The nearest public datasets cover adjacent problems: affected-version identification in C/C++ and Java, call-graph reachability, and agreement between tools rather than correctness. This gap is worth stating, and the team should fill it with a small hand-labeled set.

### Cited Findings
- **NVIDIA AI Blueprint: Vulnerability Analysis.** A three-stage multi-agent workflow: CVE Researcher and Container Analyzer in parallel, then an Exploitability Analyzer (is the code present, reachable, exploitable), then a VEX Categorizer. Outputs are `affected` / `not_affected` with justifications such as `code_not_present`, `code_not_reachable`, `requires_configuration`, `requires_dependency`, `requires_environment`, `compiler_protected`, `runtime_protected`, `perimeter_protected`, plus an `unknown` fail-safe — [vulnerability-analysis README](https://github.com/NVIDIA-AI-Blueprints/vulnerability-analysis)
- NVIDIA's evaluation set `morpheus_2506_eval_test.csv` has only three reviewed cases for `nvcr.io/nvidia/morpheus/morpheus:25.06-runtime`: GHSA-53q9-r3pm-6pq6 = vulnerable, GHSA-ph84-rcj2-fxxm = code_not_reachable, CVE-2024-9287 = code_not_reachable. The README calls it "a smoke/regression fixture, not a statistically representative benchmark" — [eval CSV](https://github.com/NVIDIA-AI-Blueprints/vulnerability-analysis/blob/main/src/vuln_analysis/data/eval_datasets/morpheus_2506_eval_test.csv); [README, Evaluating the Workflow](https://github.com/NVIDIA-AI-Blueprints/vulnerability-analysis)
- NVIDIA's `accuracy` evaluator reports exact VEX-justification accuracy, binary vulnerable/not-vulnerable accuracy, precision, recall, F1 and a confusion matrix. It scores three policies for uncertain predictions: exclude them, count them as wrong, or map them to vulnerable. The README advises keeping all three visible so a favorable treatment does not hide regressions — [README](https://github.com/NVIDIA-AI-Blueprints/vulnerability-analysis)
- NVIDIA also ships an LLM-as-judge (`cve_report_judge.py`) that compares generated CVE research reports with gold reports on `technical_details` and `completeness`, each scored 0 to 5. There is one gold report (CVE-2024-5187) — [cve_report_judge.py](https://github.com/NVIDIA-AI-Blueprints/vulnerability-analysis/blob/main/src/vuln_analysis/eval/evaluators/cve_report_judge.py)
- **SCARVA (arXiv, 2026-11-19).** An agentic supply-chain exposure assessment framework: an ANALYST agent plus independent JUDGE agents that audit recorded tool calls. It is evaluated on 54 manually curated cases balanced across exploitable, non-exploitable and vulnerability-free projects. Best ANALYST (Qwen 3.8): 82% balanced accuracy. Best JUDGE (Claude Opus 5.5): agrees with human annotators on 94% of claim checks. No dataset or code URL appears on the abstract page — [arXiv 2611.26131](https://arxiv.org/abs/2611.26131)
- **Affected-version identification ("Vulnerability-Affected Versions Identification: How Far Are We?").** A benchmark of 1,128 C/C++ vulnerabilities used to evaluate 12 tools. No tool exceeds 45.0% accuracy, and ensembles stay below 60%. The benchmark is released on the authors' website — [arXiv 2509.03876](https://arxiv.org/abs/2509.03876)
- **Cross-version exploit applicability (2026).** A dataset of 259 exploits for 128 Java libraries, run across 28,150 historical versions (61 CWEs). Related tools: Diffploit migrates exploits across versions, and ATTAIN analyzes exploit failures to judge affected versions — [arXiv 2603.25997](https://arxiv.org/abs/2603.25997); [arXiv 2511.12950](https://arxiv.org/abs/2511.12950); [arXiv 2606.09060](https://arxiv.org/abs/2606.09060)
- **"Vexed by VEX tools".** Compares 7 VEX-generating container scanners (Trivy, Grype, DepScan, Scout, Snyk, OSV, Vexy) on three container datasets using Jaccard and Tversky similarity. It finds low consistency between tools, driven mainly by differences in vulnerability databases. It measures agreement, not ground truth — [arXiv 2503.14388](https://arxiv.org/abs/2503.14388)
- **SCA tool comparison.** 9 SCA tools run on OpenMRS (Maven + npm) report different vulnerable dependencies — [arXiv 2108.12078](https://arxiv.org/abs/2108.12078). A Maven study across 3M packages with whole-program call graphs finds that dependency-level reasoning inflates the number of projects counted as affected — [arXiv 2301.07972](https://arxiv.org/abs/2301.07972)
- **Reachability caveats.** More than 26% of vulnerable functions are not among the functions modified by the fixing patch, so patch-diff-based reachability can miss them (VFArchē) — [arXiv 2506.18050](https://arxiv.org/abs/2506.18050). FIKA generates executable traces with an LLM to show that a third-party call site is really executable, on 8 Java projects — [arXiv 2604.20015](https://arxiv.org/abs/2604.20015)
- **Jelly (Aarhus).** A JS/TS static analyzer for call graphs, library usage patterns and "vulnerability exposure analysis". It can compare static and dynamic call graphs for precision and recall, but no labeled exposure benchmark ships with it — [jelly README](https://github.com/cs-au-dk/jelly). Eclipse Steady (Java, static + dynamic reachability) is stale (last push 2023-12-04) — [eclipse-steady/steady](https://github.com/eclipse-steady/steady)
- **Usable label sources (weak labels, not benchmarks):**
  - SAP project-kb: manually curated vulnerability-fix statements for open-source Java, plus Prospector for mining fix commits; Apache-2.0, active — [SAP/project-kb](https://github.com/SAP/project-kb)
  - Aqua VEX Hub: crawls OpenVEX/CSAF VEX documents from OSS repos (the `.vex/` directory) and organizes them by PURL; 40 stars, last push 2026-03-23 — [aquasecurity/vexhub](https://github.com/aquasecurity/vexhub)
  - Format examples only: CycloneDX bom-examples (includes VEX; last push 2025-10-21, stale) and openvex/examples (last push 2023-10-11, stale) — [CycloneDX/bom-examples](https://github.com/CycloneDX/bom-examples); [openvex/examples](https://github.com/openvex/examples)
- **Red Hat VEX.** Red Hat began publishing VEX for all CVEs in February 2025. Later in 2025 it said it would stop publishing "not affected" VEX files generated solely from CVE references and would remove existing ones gradually. Its justification labels include `component_not_present`, `vulnerable_code_not_present` and `vulnerable_code_not_in_execute_path`. These are vendor product-level statements, not application-level ground truth — [Red Hat Security Data Changelog](https://access.redhat.com/articles/5554431); [Red Hat VEX blog](https://redhat.com/en/blog/vulnerability-exploitability-exchange-vex-beta-files-now-available)
- **Ground truth for version and package matching (ingest step).** All active, verified on 2026-11-21:
  - GitHub Advisory Database (2,564 stars, CC-BY-4.0) — [github/advisory-database](https://github.com/github/advisory-database)
  - OSV (3,079 stars, Apache-2.0) — [google/osv.dev](https://github.com/google/osv.dev)
  - CISA KEV mirror — [cisagov/kev-data](https://github.com/cisagov/kev-data)
  - OpenSSF malicious-packages (643 stars, Apache-2.0) — [ossf/malicious-packages](https://github.com/ossf/malicious-packages)
  - Datadog malicious packages dataset (396 stars, Apache-2.0) — [DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset)

### Inferences
- The exposure step (dependency present, version in range, reachable, configured or deployed vulnerably) is the least benchmarked part of the pipeline. The team will need its own labeled set, and a small one built well is a credible hackathon contribution in itself.
- A practical design combines SCARVA's balance (exploitable / non-exploitable / vulnerability-free) with NVIDIA's CSV schema (`vuln_id, target, ground_truth_label` using VEX justifications) and accuracy evaluators. For example, take 30 to 60 project×advisory pairs from vulhub apps, the goof repos and OSV ranges. Then add hard negatives:
  - version just outside the range
  - vulnerable package present only as a devDependency
  - vulnerable function never imported
  - Next.js CVE-2025-29927 when middleware is not used for authentication
- Version-range checks alone are unreliable. Affected-version tools stay below 45 to 60% accuracy even on C/C++, and scanners disagree with each other. A credible exposure verdict should cite evidence (lockfile line, import or call site, configuration) that a judge can check, which is SCARVA's design point.

### Gaps
- No public npm/PyPI dataset with application-level VEX justifications was found. Could not check whether SCARVA's 54 cases or the NVIDIA team's larger internal evaluation data (if any) will be released.
- Did not verify whether the affected-versions benchmark (arXiv 2509.03876) is hosted on GitHub. It was not listed as a repo.
- No study found that reports accuracy for LLM-generated VEX statements against human-reviewed labels at scale.

## Q3. Which demo targets and recent CVEs/incidents make convincing, reproducible end-to-end hackathon demos?

### Takeaway
vulhub is the strongest substrate: 21.5k stars, MIT, 495 docker-compose environments across 155 apps. It includes React2Shell, Next.js CVE-2025-29927, Log4Shell and several 2026 KEV entries (Langflow, ActiveMQ, Tomcat, GitLab, WordPress), plus n8n "Ni8mare". For supply chain, the verified May 2026 Mini Shai-Hulud wave that trojanized `@mistralai/mistralai` (npm 2.2.2 to 2.2.4) and `mistralai` (PyPI 2.4.6) fits a Mistral hackathon well. It can be demoed from lockfiles alone, without ever installing malware.

### Cited Findings

#### Verified demo repos (gh api, 2026-11-21)

| Target | Repo | Stars | Last push | License | Status |
|---|---|---|---|---|---|
| vulhub (docker-compose CVE environments) | [vulhub/vulhub](https://github.com/vulhub/vulhub) | 21,513 | 2026-10-17 | MIT | active |
| OWASP Juice Shop | [juice-shop/juice-shop](https://github.com/juice-shop/juice-shop) | 14,503 | 2026-11-20 | MIT | active |
| DVWA | [digininja/DVWA](https://github.com/digininja/DVWA) | 14,062 | 2026-11-17 | GPL-3.0 | active |
| WebGoat | [WebGoat/WebGoat](https://github.com/WebGoat/WebGoat) | 9,493 | 2026-11-16 | NOASSERTION | active |
| OWASP NodeGoat | [OWASP/NodeGoat](https://github.com/OWASP/NodeGoat) | 2,084 | 2024-06-15 | Apache-2.0 | stale |
| OWASP WrongSecrets | [OWASP/wrongsecrets](https://github.com/OWASP/wrongsecrets) | 1,480 | 2026-11-20 | AGPL-3.0 | active |
| OWASP RailsGoat | [OWASP/railsgoat](https://github.com/OWASP/railsgoat) | 930 | 2026-09-08 | MIT | active |
| snyk-labs nodejs-goof | [snyk-labs/nodejs-goof](https://github.com/snyk-labs/nodejs-goof) | 549 | 2026-11-11 | Apache-2.0 | active |
| snyk-labs java-goof | [snyk-labs/java-goof](https://github.com/snyk-labs/java-goof) | 105 | 2026-11-05 | none | active |
| snyk-labs kubernetes-goof | [snyk-labs/kubernetes-goof](https://github.com/snyk-labs/kubernetes-goof) | 68 | 2026-08-05 | none | active |
| snyk-labs tj-actions goof | [snyk-labs/tj-changed-files-action-goof](https://github.com/snyk-labs/tj-changed-files-action-goof) | 1 | 2026-07-10 | none | active |
| snyk-labs toxicskills-goof (malicious agent skills) | [snyk-labs/toxicskills-goof](https://github.com/snyk-labs/toxicskills-goof) | 19 | 2026-06-28 | none | active |
| snyk-labs mcp-server-npm-goof | [snyk-labs/mcp-server-npm-goof](https://github.com/snyk-labs/mcp-server-npm-goof) | 8 | 2026-09-02 | NOASSERTION | active |
| snyk uv-goof (vulnerable uv/Python projects) | [snyk/uv-goof](https://github.com/snyk/uv-goof) | 1 | 2026-09-21 | MIT | active |
| snyk-labs docker-goof / php-goof | [docker-goof](https://github.com/snyk-labs/docker-goof), [php-goof](https://github.com/snyk-labs/php-goof) | 37 / 27 | 2024-08-12 / 2023-12-19 | none | stale |
| Damn Vulnerable Python Web App | [anxolerd/dvpwa](https://github.com/anxolerd/dvpwa) | 198 | 2026-11-09 | MIT | active |
| Vulnerable Flask App | [we45/Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App) | 35 | 2026-02-07 | none | active |
| Datadog vulnerable Java app | [DataDog/vulnerable-java-application](https://github.com/DataDog/vulnerable-java-application) | 24 | 2026-10-30 | Apache-2.0 | active |
| Log4Shell vulnerable app | [christophetd/log4shell-vulnerable-app](https://github.com/christophetd/log4shell-vulnerable-app) | 1,143 | 2024-04-26 | Apache-2.0 | stale |
| Log4Shell PoC | [kozmer/log4j-shell-poc](https://github.com/kozmer/log4j-shell-poc) | 1,842 | 2024-02-12 | MIT | archived |
| xz backdoor demo (xzbot) | [amlweems/xzbot](https://github.com/amlweems/xzbot) | 3,559 | 2024-04-03 | none | stale |
| React2Shell original PoC | [lachlan2k/React2Shell-CVE-2025-55182-original-poc](https://github.com/lachlan2k/React2Shell-CVE-2025-55182-original-poc) | 1,066 | 2025-12-05 | none | static PoC |

#### vulhub coverage
- The vulhub tree has 495 environment directories across 155 apps. 33 of them carry 2025 or 2026 CVE IDs, including:
  - react/CVE-2025-55182
  - next.js/CVE-2025-29927
  - langflow/CVE-2026-33017 and CVE-2025-3248
  - n8n/CVE-2026-21858 and CVE-2025-68613
  - activemq/CVE-2026-34197
  - tomcat/CVE-2026-34486 and CVE-2025-24813
  - gitlab/CVE-2026-85706 and CVE-2026-97229
  - wordpress/CVE-2026-63030
  - vite/CVE-2026-39363, CVE-2025-30208 and CVE-2025-32395
  - ingress-nginx/CVE-2025-1974
  - erlang/CVE-2025-32433
  - spring/CVE-2025-41242

  Older classics include log4j/CVE-2021-44228 and spring/CVE-2022-22965. There is no xz environment — [vulhub/vulhub](https://github.com/vulhub/vulhub) (git tree listing, 2026-11-21)

#### React2Shell (CVE-2025-55182)
- Pre-authentication RCE in React Server Components 19.0.0, 19.1.0, 19.1.1 and 19.2.0 (react-server-dom-parcel, -turbopack, -webpack). Published 2025-12-03 by the Meta CNA, CVSS 3.1 base score 10.0 — [CVE.org API record](https://cveawg.mitre.org/api/cve/CVE-2025-55182)
- GHSA-fv66-9v8q-g76r fixed versions: 19.0.1, 19.1.2 and 19.2.1 — [OSV GHSA-fv66-9v8q-g76r](https://osv.dev/vulnerability/GHSA-fv66-9v8q-g76r)
- The Next.js-specific CVE-2025-66478 was REJECTED on 2025-12-03 as a duplicate of CVE-2025-55182 — [CVE.org API record](https://cveawg.mitre.org/api/cve/CVE-2025-66478)
- Added to CISA KEV on 2025-12-05, marked "Known" for ransomware use — [cisagov/kev-data](https://github.com/cisagov/kev-data) (catalog 2026.11.20)
- vulhub's environment starts a vulnerable Next.js 15.5.6 server with `docker compose up -d` — [vulhub react/CVE-2025-55182](https://github.com/vulhub/vulhub/tree/HEAD/react/CVE-2025-55182)

#### Next.js middleware bypass (CVE-2025-29927, GHSA-f82v-jwr5-mffw)
- Versions before 14.2.25 and 15.2.3 that use middleware for authentication can be bypassed with the `x-middleware-subrequest` header. vulhub runs Next.js 15.2.2 with a login-protected dashboard. Not in KEV — [vulhub next.js/CVE-2025-29927](https://github.com/vulhub/vulhub/tree/HEAD/next.js/CVE-2025-29927); [OSV GHSA-f82v-jwr5-mffw](https://osv.dev/vulnerability/GHSA-f82v-jwr5-mffw)

#### Log4Shell (CVE-2021-44228, GHSA-jfh8-c2jp-5v3q)
- Affects Log4j2 2.0-beta9 through 2.15.0, excluding 2.12.2, 2.12.3 and 2.3.1. In KEV since 2021-12-10, marked "Known" for ransomware use. vulhub has log4j/CVE-2021-44228 — [OSV CVE-2021-44228](https://osv.dev/vulnerability/CVE-2021-44228); [cisagov/kev-data](https://github.com/cisagov/kev-data); [vulhub](https://github.com/vulhub/vulhub)

#### xz backdoor (CVE-2024-3094, GHSA-rxwq-x6h5-x525)
- Malicious code in the distributed xz 5.6.0 and 5.6.1 tarballs, published 2024-03-29. Not in KEV. No vulhub environment. `amlweems/xzbot` provides notes, a honeypot and an exploit demo but is stale and unlicensed — [OSV CVE-2024-3094](https://osv.dev/vulnerability/CVE-2024-3094); [amlweems/xzbot](https://github.com/amlweems/xzbot)

#### tj-actions/changed-files (CVE-2025-30066, GHSA-mrrh-fwg8-r2c3)
- Tags v1 through v45.0.7 were affected on 2025-03-14. In KEV since 2025-03-18. The related reviewdog/action-setup compromise (CVE-2025-30154) entered KEV on 2025-03-24. Snyk maintains a demo goof repo — [OSV GHSA-mrrh-fwg8-r2c3](https://osv.dev/vulnerability/GHSA-mrrh-fwg8-r2c3); [cisagov/kev-data](https://github.com/cisagov/kev-data); [snyk-labs/tj-changed-files-action-goof](https://github.com/snyk-labs/tj-changed-files-action-goof)

#### npm supply-chain worms, 2025
- **Shai-Hulud wave 1 (September 2025).** Hit @ctrl/tinycolor 4.1.1 and 4.1.2 (MAL-2025-47141, 2025-09-15) — [OSV MAL-2025-47141](https://osv.dev/vulnerability/MAL-2025-47141). The preceding chalk/debug maintainer compromise included chalk 5.6.1 (MAL-2025-46969, 2025-09-08) — [OSV MAL-2025-46969](https://osv.dev/vulnerability/MAL-2025-46969)
- **Shai-Hulud 2.0.** Trojanized packages were uploaded 2025-11-21 to 2025-11-23: about 700 packages and more than 25,000 affected repositories (Wiz). It runs at the preinstall stage. Other sources report 600 to 800 packages and 27k to 30k repositories — [Wiz blog](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack); [The Register](https://www.theregister.com/2025/11/24/shai_hulud_npm_worm/)

#### npm/PyPI supply-chain incidents, 2026 (Unit 42 overview, published 2026-07-15)
Source for this section unless noted: [Unit 42 npm supply-chain monitoring](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/). Specific malicious versions were checked in OSV.
- **Axios compromise (March 2026).** Malicious axios 0.30.4 and 1.14.1 (MAL-2026-2307 / GHSA-fw8c-xr5c-95f9, published 2026-03-31) — [OSV MAL-2026-2307](https://osv.dev/vulnerability/MAL-2026-2307)
- **"Shai-Hulud: The Third Coming" (2026-04-22).** @bitwarden/cli@2026.4.0 (MAL-2026-3020). The payload is a preinstall Bun-based credential stealer that self-propagates — [OSV MAL-2026-3020](https://osv.dev/vulnerability/MAL-2026-3020)
- **Mini Shai-Hulud.** Three waves:
  - SAP CAP wave, 2026-04-29.
  - TanStack wave, 2026-05-11, attributed to TeamPCP: 373 malicious versions across 169 npm packages by end of day, plus PyPI packages. Initial access was a chain of `pull_request_target` "pwn request", Actions cache poisoning and OIDC token extraction. The payload includes a dead-man's switch. The affected list explicitly includes **@mistralai/mistralai**.
  - @antv wave, 2026-05-19: 639 versions of 323 packages in about an hour.
- **Mistral SDK versions in OSV:**
  - @mistralai/mistralai npm 2.2.2, 2.2.3, 2.2.4 (MAL-2026-3432 / GHSA-3q49-cfcf-g5fm, 2026-05-11) — [OSV MAL-2026-3432](https://osv.dev/vulnerability/MAL-2026-3432)
  - GHSA-jgg6-4rpr-wfh7, "broken dropper", covering @mistralai/mistralai, -azure and -gcp 1.7.1 to 1.7.3 and 2.2.2 to 2.2.4 (2026-05-18) — [OSV GHSA-jgg6-4rpr-wfh7](https://osv.dev/vulnerability/GHSA-jgg6-4rpr-wfh7)
  - PyPI mistralai 2.4.6 (MAL-2026-3608, 2026-05-12; GHSA-wx9m-wx4f-4cmg) — [OSV MAL-2026-3608](https://osv.dev/vulnerability/MAL-2026-3608); [OSV GHSA-wx9m-wx4f-4cmg](https://osv.dev/vulnerability/GHSA-wx9m-wx4f-4cmg)
  - TanStack malware advisory GHSA-g7cv-rxg3-hmpx is aliased to CVE-2026-45321 — [OSV GHSA-g7cv-rxg3-hmpx](https://osv.dev/vulnerability/GHSA-g7cv-rxg3-hmpx)
- **Red Hat "Miasma" (2026-06-01).** At least 32 @redhat-cloud-services packages, published with valid SLSA provenance from a compromised employee GitHub account.
- **AsyncAPI release-pipeline compromise (2026-07-14).** Five package versions.
- **ChainDrop (August 2026).** Started from the keyv maintainer's account. keyv 6.0.0 is malicious (MAL-2026-11524, 2026-08-04) — [OSV MAL-2026-11524](https://osv.dev/vulnerability/MAL-2026-11524). Reported scale varies:
  - StepSecurity: 444 packages and 2,212 versions in under 4 hours — [StepSecurity](https://stepsecurity.io/blog/chaindrop-npm-worm)
  - Elastic: more than 400 packages — [Elastic Security Labs](https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain)
  - TechRadar: more than 1,300 — [TechRadar](https://techradar.com/pro/security/new-chaindrop-worm-poisons-over-1-300-npm-packages-keyv-and-cacheable-among-those-hit)
  - The Singapore CSA advisory lists keyv 6.0.0, flat-cache 6.1.24, file-entry-cache 11.1.6, cacheable-request 13.0.20, cacheable 2.5.1 and @cacheable/memory 2.2.1 — [CSA AD-2026-009](https://csa.gov.sg/alerts-and-advisories/advisories/ad-2026-009)

#### 2026 KEV entries with vulhub environments (strong "new KEV entry" demo triggers)
The KEV catalog had 1,790 entries on 2026-11-20, 306 of them added in 2026 — [cisagov/kev-data](https://github.com/cisagov/kev-data)
- **Langflow CVE-2026-33017.** Unauthenticated RCE via the public flow build endpoint. Affects 1.8.2 and earlier, fixed in 1.9.0. In KEV since 2026-03-25. vulhub runs Langflow 1.8.1 with authentication enabled — [OSV GHSA-vwmf-pq79-vjvx](https://osv.dev/vulnerability/GHSA-vwmf-pq79-vjvx); [vulhub langflow/CVE-2026-33017](https://github.com/vulhub/vulhub/tree/HEAD/langflow/CVE-2026-33017)
- **n8n CVE-2026-21858 ("Ni8mare", CVSS 10.0).** Content-Type confusion in Form Webhooks leads to file read and then RCE. Affects 1.65.0 through 1.120.x. Not in KEV — [vulhub n8n/CVE-2026-21858](https://github.com/vulhub/vulhub/tree/HEAD/n8n/CVE-2026-21858); [OSV GHSA-v4pr-fm98-w9pg](https://osv.dev/vulnerability/GHSA-v4pr-fm98-w9pg). A separate n8n bug, CVE-2025-68613 (expression-injection RCE), entered KEV on 2026-03-11 — [OSV GHSA-v98v-ff95-f3cp](https://osv.dev/vulnerability/GHSA-v98v-ff95-f3cp)
- Other 2026 KEV additions with vulhub environments — [cisagov/kev-data](https://github.com/cisagov/kev-data); [vulhub](https://github.com/vulhub/vulhub):
  - ActiveMQ CVE-2026-34197 (2026-04-16)
  - Tomcat CVE-2026-34486 (2026-08-04)
  - GitLab CVE-2026-85706 (2026-09-11) and CVE-2026-97229 (2026-10-29)
  - WordPress CVE-2026-63030 (2026-07-21)
- npm-dependency KEV additions in 2026, useful for lockfile-exposure demos:
  - Vite CVE-2025-31125, a `server.fs.deny` bypass (added 2026-01-22) — [OSV GHSA-4r4m-qw57-chr8](https://osv.dev/vulnerability/GHSA-4r4m-qw57-chr8)
  - React Native Community CLI CVE-2025-11953, OS command injection (added 2026-02-05) — [OSV GHSA-399j-vxmf-hjvr](https://osv.dev/vulnerability/GHSA-399j-vxmf-hjvr)
- Recent KEV entries split on vulhub coverage. MongoDB CVE-2025-14847 (added 2025-12-29) has no vulhub environment; vulhub only has mongo-express. Erlang/OTP SSH CVE-2025-32433 (added 2025-06-09) does have one (erlang/CVE-2025-32433) — [cisagov/kev-data](https://github.com/cisagov/kev-data); [vulhub](https://github.com/vulhub/vulhub)

### Inferences
- **Best "classic CVE" demo: React2Shell.** It is famous, CVSS 10, in KEV with known ransomware use, and pins exact npm version ranges (good for lockfile exposure checks). The fix is a version bump (to 19.0.1, 19.1.2, 19.2.1 or a patched Next.js) that the agent can open as a PR. vulhub provides a one-command vulnerable target for the local "exploitable before, not after" check. Next.js CVE-2025-29927 pairs well with it to show configuration-dependent exposure: a project is only affected if it relies on middleware for authorization.
- **Best supply-chain demo: May 2026 Mini Shai-Hulud, TanStack wave.** It hit Mistral's own SDKs (npm @mistralai/mistralai 2.2.2 to 2.2.4, PyPI mistralai 2.4.6), which makes it memorable at a Mistral hackathon and maps cleanly to all six agent steps:
  1. Ingest the OSV MAL / GHSA record.
  2. Grep lockfiles and CI logs for the bad versions.
  3. Mitigate: pin to a safe version, block install scripts, rotate npm/GitHub/cloud tokens.
  4. Open a PR.
  5. Write an incident report and VEX.
  6. Escalate to humans for credential rotation.

  Never install the malicious versions. Put the version strings in a fixture lockfile instead.
- **"New KEV entry" trigger demo:** Langflow CVE-2026-33017 (an AI-tooling target, vulhub environment, 2026 KEV) or n8n Ni8mare. Both are relevant to AI-agent stacks and reproducible locally.
- The xz backdoor is a good story for ingestion and exposure (exact versions 5.6.0 and 5.6.1) but a weak live-demo target: no maintained environment, and the demo repo is unlicensed and stale.
- Juice Shop, DVWA and WebGoat are actively maintained but built around OWASP Top 10 application bugs, not dependency CVEs. nodejs-goof and java-goof (dependency-heavy, active) fit an "SCA, then exposure, then PR" demo better.

### Gaps
- Did not verify the exact Shai-Hulud wave 1 package count or the Axios incident's initial-access details. Unit 42 only references them.
- ChainDrop package counts conflict between sources (444 to more than 1,300), and ChainDrop details came from search summaries plus OSV, not from a fully fetched primary write-up.
- Did not read vulhub reproduction steps beyond the environment-setup sections, because running exploits was out of scope.
- Juice Shop's current challenge count was not verified.

## Q4. What do these resources imply for how the team should measure their agent?

### Takeaway
Measure each stage separately:
- Exposure verdicts: precision, recall and F1 on the "affected" class, plus exact VEX-justification accuracy, on a balanced hand-labeled set, with "unknown" reported under several policies.
- Patches: exploit fails after the patch AND tests pass (and ideally the ground-truth PoC also fails), on PatchEval-Verified or SEC-bench.
- Reports: a gold-report LLM judge plus VEX schema validity.
- Time and cost per advisory.

### Cited Findings
- Exploit-based patch validation is the norm now:
  - CyberGym, SEC-bench and CyberGym-E2E count a fix only if the PoC stops crashing on the patched build — [CyberGym leaderboard page](https://www.cybergym.io/cybergym/); [RDI CyberGym-E2E blog](https://rdi.berkeley.edu/blog/cybergym-e2e)
  - VulnRepairEval argues that non-exploit validation overestimates repair ability — [arXiv 2509.03331](https://arxiv.org/abs/2509.03331)
  - PatchEval-Verified rewrote its PoC tests so that correct alternative fixes are not rejected — [PatchEval README](https://github.com/bytedance/PatchEval)
- Validation stages change the numbers a lot. On CyberGym-E2E, GPT-5.4 + Codex scores 65.9% end-to-end (S3) but only 22.2% when the patch must also fix the ground-truth vulnerability (S4) — [RDI blog](https://rdi.berkeley.edu/blog/cybergym-e2e)
- Benchmark task materials can be wrong (22.4% of CyberGym tasks flagged). Checking that a PoC hits the intended defect lowered one run from 85.3% to 78.8% — [arXiv 2611.25790](https://arxiv.org/abs/2611.25790)
- For exposure, NVIDIA's evaluator reports exact justification accuracy, binary accuracy, precision, recall, F1 and a confusion matrix under three "unknown" policies — [NVIDIA README](https://github.com/NVIDIA-AI-Blueprints/vulnerability-analysis)
- SCARVA reports balanced accuracy on exploitable / non-exploitable / vulnerability-free cases, and validates JUDGE claim checks against human annotators (94% agreement) — [arXiv 2611.26131](https://arxiv.org/abs/2611.26131)
- For reports, NVIDIA's judge scores technical details and completeness (0 to 5) against gold reports — [cve_report_judge.py](https://github.com/NVIDIA-AI-Blueprints/vulnerability-analysis/blob/main/src/vuln_analysis/eval/evaluators/cve_report_judge.py)
- Published cost and time anchors:
  - CVE-Genie: $2.77 per reproduced CVE — [arXiv 2509.01835](https://arxiv.org/abs/2509.01835)
  - SEC-bench: $0.87 per constructed instance — [arXiv 2506.11791](https://arxiv.org/abs/2506.11791)
  - CyberGym-E2E: $10 and 90-minute budget per task — [RDI blog](https://rdi.berkeley.edu/blog/cybergym-e2e)
- Ingest/triage sub-skills have off-the-shelf metrics: CTIBench CTI-VSP (CVSS v3.1 vector prediction) and CTI-RCM (CVE to CWE) — [cti-bench README](https://github.com/maveryn/cti-bench)

### Inferences
- **Exposure (core metric).** Build 30 to 60 labeled project×advisory pairs, roughly balanced:
  - affected
  - not affected because the version is out of range
  - dependency absent, or dev-only
  - code not reachable
  - requires a configuration that is absent

  Report precision and recall on "affected" (missed exposures are the costly error), exact VEX-justification accuracy, and the share of "unknown" verdicts under all three policies. Use OSV/GHSA ranges as weak labels and hand-check the hard negatives.
- **Patch (core metric).** Measure the rate at which the PR builds, passes the existing tests, and makes the PoC or exploit test fail. On PatchEval-Verified (JS/Python subset) this is directly comparable to published Pass@1. Report pass@1 over repeated runs, because results vary between runs (the CyberGym leaderboard warns about this).
- **Mitigation and escalation.** No benchmark covers these. Use a checklist rubric per scenario: correct mitigation chosen (pin, upgrade, configuration change, token rotation); escalation triggered when confidence is low or the action is high-impact; no destructive actions. A judge model can score it against a human-written key.
- **Report.** Validate VEX output against the OpenVEX or CSAF schema (pass/fail). Then use an LLM judge against 3 to 5 gold incident reports (NVIDIA-style technical_details and completeness), and spot-check claim support as SCARVA does: every claim should cite a lockfile line, import or call site, or advisory.
- **Operations.** Measure wall-clock time to triage (signal ingested to verdict), time to PR, tokens and dollars per advisory, and human-escalation rate. Compare against the published per-task budgets above.
- **Suggested picks.**
  - Measurement: (1) PatchEval-Verified JS/Python subset for patching; (2) a custom exposure set built from vulhub, goof repos and OSV/MAL advisories, because no public exposure benchmark exists; optionally (3) CTIBench CTI-VSP/RCM for triage.
  - Live demo: (1) React2Shell (lockfile exposure, version-bump PR, local vulhub verification); (2) the May 2026 Mini Shai-Hulud wave affecting @mistralai/mistralai and mistralai, demoed from fixture lockfiles only.

### Gaps
- No published human baseline for exposure-verdict accuracy or time-to-triage was found to compare an agent against.
- No benchmark found that scores mitigation choice or escalation decisions, so these would be custom rubrics.
