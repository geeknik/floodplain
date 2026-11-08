# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
discussions or pull requests.**

Report them privately through GitHub:

1. Go to the [Security tab](https://github.com/geeknik/floodplain/security) of this repository.
2. Click **Report a vulnerability** (or open
   <https://github.com/geeknik/floodplain/security/advisories/new> directly).
3. Describe the issue and submit. Only the maintainers can see the report.

Please include as much of the following as you can:

- The affected component (e.g. a module such as `modules/sfp_example.py`, the
  web UI, the CLI, the correlation engine, a Docker image).
- The Floodplain version (`VERSION` file or the web UI's About dialog) or
  commit.
- Steps to reproduce, a proof of concept, or the input/event data that
  triggers the issue.
- The impact as you understand it (what an attacker can do, and what they
  need — e.g. a malicious scan target, a crafted API response, network
  position, web UI access).

## What to expect

- We aim to acknowledge reports within a few days and to keep you informed as
  we investigate.
- We will work with you on a fix and a disclosure timeline, and publish a
  GitHub Security Advisory once a fix is available.
- With your permission, we are happy to credit you in the advisory.

## Bug bounty

**There is no bug bounty.** Floodplain is a community-maintained open source
project and cannot offer payment for reports. We are grateful for responsible
disclosure all the same.

## Supported versions

Security fixes are made on the `master` branch and included in the next
release. Only the latest release is supported.

| Version | Supported |
| ------- | --------- |
| Latest `0.x` release and `master` | Yes |
| Older releases | No |
| SpiderFoot releases (`v4.0` and earlier tags in this repository) | No — these are the upstream project's |

## Scope

In scope: vulnerabilities in Floodplain's own code and the images built from
this repository's Dockerfiles. Floodplain processes untrusted data by design
(scan targets, web content, third-party API responses), so issues where such
data leads to code execution, command or argument injection, SSRF, XSS in the
web UI, credential or API-key leakage, or resource exhaustion are especially
welcome.

Out of scope:

- Vulnerabilities in third-party services that Floodplain modules query, or
  in external tools wrapped by `sfp_tool_*` modules — please report those to
  the respective vendor or project.
- Findings that require an attacker to already control the Floodplain host,
  its configuration or its data directory.
- Reports from automated scanners without a demonstrated, exploitable impact.
- Dependency advisories that do not affect Floodplain (for example, a
  vulnerable function Floodplain never calls). These are still useful as
  regular issues.
