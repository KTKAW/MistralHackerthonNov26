---
type: playbook
title: "A key or token is exposed"
signals: ["API key committed to a repository", "token pasted into a chat or an issue or a log", "secret found by a scan", ".env file shared or published", "unexpected spend on an AI or cloud account"]
severity: high
updated: 2026-11-21
reviewed: 2026-11-21
---

# A key or token is exposed

**Use when:** an API key, token, password or `.env` file was committed, pasted, logged, shipped inside an app or image, or found by a scan. Also when an account shows spend or activity nobody recognises.

**Assume until disproved:** the secret has been copied and will be used. Attackers look for secrets at scale: they ran TruffleHog over 1.8m Android apps. [Anthropic threat report, Sep 2026](../sources/anthropic-threat-intelligence-2026-09.md)

## Ask first

- Which provider, and which key? Identify it by name, provider and last four characters.
- Where was it exposed, and since when: public repository, private repository, chat, log, image, app?
- What can it do: which data, which actions, what spend limit?
- Who and what else uses the same key? Is it in a shared `.env` file?

## Contain

1. Revoke the key at the provider and issue a new one. Do this before anything else: rotate first. [Anthropic threat report, Sep 2026](../sources/anthropic-threat-intelligence-2026-09.md)
2. Do not count on deleting the file or the commit. The old value stays exposed; only revoking it ends the exposure. *(baseline)*
3. If it cannot be revoked yet, shrink it: lower the spend cap and narrow the scope. *(baseline)*

## Scope

1. Read the provider's usage and billing records since the exposure began. Look for use from odd locations. [Research report, Nov 2026](../sources/research-report-2026-11.md)
2. Search for the same value elsewhere: other repositories, dotfiles, `.env` files and images. [Research report, Nov 2026](../sources/research-report-2026-11.md)
3. Work out what else the same leak revealed: other secrets in the same file, or on the same machine. *(baseline)*
4. If the key was used by someone else, list what they read, created or changed with it. *(baseline)*

## Recover

1. Reissue as one scoped key per agent or service, each with a spend cap. [Research report, Nov 2026](../sources/research-report-2026-11.md)
2. Update every place that used the old key, then confirm that the old key now fails. *(baseline)*
3. Remove what an intruder created with it: resources, users, further keys. *(baseline)*

## Report

1. Tell the provider if the key was abused. *(baseline)*
2. If other people's personal data was within the key's reach, tell whoever is responsible for data protection. A legal duty to notify may apply. *(baseline)*

## Prevent the repeat

[Secrets and AI keys](../concepts/secrets-and-ai-keys.md) · [Agent containment](../concepts/agent-containment.md) · [Supply chain and dependency cooldown](../concepts/supply-chain-and-dependency-cooldown.md)

## Agent boundaries

- Never ask for, repeat or store the value of a secret. If someone pastes one to you, tell them that the paste is itself an exposure and that the key now needs rotating.
- If you are the agent that sweeps for exposed keys, you must hold none of them and have no outbound access. [Research report, Nov 2026](../sources/research-report-2026-11.md)
- A person revokes and reissues. You prepare the list of where the key is used.

## Precedents

- [Stolen AI keys, bulk token theft and fake Claude resellers](../advisories/2026-09-stolen-ai-keys-and-fake-resellers.md)
- [August 2026 npm worm](../advisories/2026-08-npm-worm.md)
- [Comment and Control](../advisories/2026-04-comment-and-control.md)
