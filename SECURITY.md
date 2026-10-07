# Security Policy

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](https://github.com/GuardianVigil-Lab/vigil/security/advisories/new)
rather than a public issue. Include the version or commit, what you ran, and
what happened. We aim to acknowledge reports within five working days.

## Running Vigil safely

- **The REST API binds to `127.0.0.1` by default** and needs a bearer token
  (`VIGIL_API_TOKEN`) on every scan and report route. It refuses to bind a
  non-loopback address without one. Put it behind TLS if it leaves the host.
- **Scans are confined to `VIGIL_WORKSPACE_ROOT`.** A requested workspace that
  resolves outside it, including through a symlink, is refused.
- **Webhooks are off until `VIGIL_WEBHOOK_SECRET` is set**, and every delivery
  must carry a valid GitHub `X-Hub-Signature-256` or GitLab `X-Gitlab-Token`.
- **The Docker socket is root-equivalent on the host.** Mount it only for the
  batteries that start containers, and only on hosts where that is acceptable.
- **Only test systems you own or are authorised to test.** The `vapt` battery
  sends traffic to `TARGET_URL`.
