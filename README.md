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
profile-sync service, and the engine that drives every VPN node. It is always-on:
it continuously reconciles the fleet, heals drift, and pushes config to nodes when
a profile or device changes.

Part of the [PharosVPN](https://github.com/PharosVPN) platform — see
[`docs/DESIGN.md`](https://github.com/PharosVPN/docs/blob/main/DESIGN.md) for the
full architecture.

## Role

- **Private, behind NAT — zero inbound ports.** Every connection is
  coxswain-initiated *outbound*. The controller never appears in public DNS.
- **Drives the fleet.** Holds a long-lived mTLS/gRPC connection to each `node`:
  pushes config and peers, receives a live event stream.
- **Always-on & self-healing.** A reconcile sweep checks every node on an
  interval and auto-heals drift (stale config) and stalled data planes;
  creating/removing a profile or device pushes to the affected nodes
  automatically; a controller restart re-reconciles the whole fleet.
- **Management API + audit.** Token-authenticated API with scoped, expiring,
  hashed-at-rest tokens (`readonly`/`monitor`/`admin`), plus a hash-chained,
  tamper-evident audit log of every CLI and API action (`cox audit verify`).
- **Monitoring & analytics.** Live connect/disconnect monitoring over a gRPC
  stream with persisted session history (per-session rx/tx), and an in-process
  anomaly engine (leaked-profile, impossible-travel, and more) raising alerts
  with severity + evidence. *(Per-session byte totals and the exfil rule are
  experimental / best-effort.)*
- **Issues credentials.** Holds the in-repo CA; mints node, relay, and
  per-user/device certificates.
- **Serves admins.** Embedded SvelteKit dashboard on localhost — fleet, paths,
  profiles, live sessions, alerts, audit log, and API tokens — live-updating
  over WebSocket, multi-admin safe via optimistic concurrency.
- **Serves users.** Account login + end-to-end-encrypted profile sync, reached
  by clients only through a `relay` (embedded by default).

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

Go · SQLite by default, optional pure-Go Postgres (pgx, selected by DSN) · gRPC
over mTLS · embedded SvelteKit 2 / Svelte 5 dashboard · SSH-based `node` agent
onboarding. One static binary (`CGO_ENABLED=0`, pure-Go incl. SQLite).

## Status

Pre-alpha platform; the controller is the most mature component. The always-on
reconcile, scoped tokens, tamper-evident audit log, live monitoring + session
history, anomaly alerts, the gRPC SIEM stream, the dashboard, and the optional
Postgres backend are shipped and live-tested on a real fleet. Per-session byte
totals and the exfil rule are experimental. See [BUILD.md](BUILD.md).

## License

Apache-2.0. Contributions under the DCO (`git commit -s`).
