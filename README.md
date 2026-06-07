<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".assets/logo-inverse.svg">
    <img src=".assets/logo.svg" alt="PharosVPN" width="120" height="120">
  </picture>
</p>

# coxswain

> The ship's wheel — where you steer the fleet from.

**`coxswain` is the PharosVPN controller / management plane.** It is the source of
truth for the fleet, the admin Web UI, the certificate authority, the account &
profile-sync service, and the engine that drives every VPN node.

Part of the [PharosVPN](https://github.com/PharosVPN) platform — see
[`docs/DESIGN.md`](https://github.com/PharosVPN/docs/blob/main/DESIGN.md) for the
full architecture.

## Role

- **Private, behind NAT — zero inbound ports.** Every connection is
  coxswain-initiated *outbound*. The controller never appears in public DNS.
- **Drives the fleet.** Holds a long-lived mTLS/gRPC connection to each `node`
  node: pushes config and peers, receives a live event stream.
- **Issues credentials.** Holds the in-repo CA; mints node, relay, and
  per-user/device certificates.
- **Serves admins.** Embedded SvelteKit admin UI on localhost, live-updating
  over WebSocket, multi-admin safe via optimistic concurrency.
- **Serves users.** Account login + end-to-end-encrypted profile sync, reached
  by clients only through a `relay` relay (embedded by default).

## Reaching the dashboard

The admin Web UI binds to a **loopback address** (`ui.listen`, default
`127.0.0.1:8443`) and opens no inbound ports. The controller may run on a remote
droplet, so reach the dashboard one of two safe ways only:

- **SSH-forwarded loopback port** (recommended): `ssh -L 8443:127.0.0.1:8443
  user@controller` and open `http://localhost:8443`. The session cookie is sent
  over the loopback only; it is *not* marked `Secure` here, by design, so the
  browser still sends it over `http://localhost`.
- **A TLS-terminating reverse proxy** in front of the UI. Set
  `ui.behind_tls_proxy: true` so coxswain trusts the proxy's
  `X-Forwarded-Proto` header to mark the session cookie `Secure` for HTTPS
  requests. Leave it `false` (the default) on any direct/loopback deploy — an
  untrusted `X-Forwarded-Proto` is then ignored and can't flip cookie security.

**Do not** expose the dashboard over plain `http://` on a public interface: the
session cookie would travel unencrypted. Use TLS or an SSH-forwarded loopback
port.

## Stack

Go · SQLite (Goose migrations) · gRPC over mTLS · embedded SvelteKit 2 / Svelte 5
admin UI · SSH-based `node` agent onboarding.

## Status

🚧 Pre-alpha — scaffolding. See [BUILD.md](BUILD.md) for the build plan.

## License

Apache-2.0. Contributions under the DCO (`git commit -s`).
