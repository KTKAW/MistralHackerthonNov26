---
type: source
title: "Authlib: empty signatures validation in JWS JSON deserialization (GHSA-6v38-4h7w-rj9h)"
publisher: "GitHub Advisory Database, read through OSV"
url: https://osv.dev/vulnerability/GHSA-6v38-4h7w-rj9h
published: 2026-10-27
ingested: 2026-11-21
kind: advisory
read: full
---

# Authlib: empty signatures validation in JWS JSON deserialization (GHSA-6v38-4h7w-rj9h)

**In one line:** Authlib before 1.9.0 returns a JWS in JSON form as verified when its list of signatures is empty, so a caller with no key can forge a payload.

## What it says

- Identifiers: GHSA-6v38-4h7w-rj9h and CVE-2026-96760. Published on 27 October 2026 and reviewed by GitHub. Weakness class CWE-347. Rated critical, with the CVSS 3.1 vector `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`.
- Package: `authlib` on PyPI. Every version before 1.9.0 is affected; the last affected version is 1.8.0. Fixed in 1.9.0.
- The flawed function is `JsonWebSignature.deserialize_json()`. It starts by assuming the object is valid and only changes its mind inside the loop over signatures. With an empty list the loop never runs, so the payload comes back as verified and no key is consulted.
- Holding the correct key does not help the caller: the empty list is accepted either way. A genuine object still verifies and a tampered signature is still rejected, so a deployment looks healthy.
- Impact as the advisory puts it: any service that calls this function on input it did not produce will accept an attacker's payload as signed. Where the payload carries identity or authorisation claims, that is an authentication bypass by a remote caller with no credentials.
- The advisory includes a short reproduction and links the fixing pull request and the 1.9.0 release.

**What the feed returned for Authlib 1.8.0 on 21 November 2026**

- OSV listed 8 GitHub advisories for `authlib` 1.8.0. This is one of them.
- 6 of the 8 are fixed in 1.9.0. The other 2 are fixed only in 1.9.1: GHSA-8m4g-j4wp-wgcg (CVE-2026-114616) and GHSA-c73q-w75p-j82v (CVE-2026-116672).

## Caveats

- Read in full through OSV's API. The description is the reporter's, as reviewed by GitHub.
- The reproduction is not copied here. Read the original for it.
- The list of other advisories is a point-in-time answer. Ask the feed again: see [Feeds](../feeds.md).
