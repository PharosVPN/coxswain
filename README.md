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
- **Drives the fleet.** Holds a long-lived mTLS/gRPC connection to each `buoy`
  node: pushes config and peers, receives a live event stream.
- **Issues credentials.** Holds the in-repo CA; mints node, relay, and
  per-user/device certificates.
- **Serves admins.** Embedded SvelteKit admin UI on localhost, live-updating
  over WebSocket, multi-admin safe via optimistic concurrency.
- **Serves users.** Account login + end-to-end-encrypted profile sync, reached
  by clients only through a `beacon` relay (embedded by default).

## Stack

Go · SQLite (Goose migrations) · gRPC over mTLS · embedded SvelteKit 2 / Svelte 5
admin UI · SSH-based `buoy` agent onboarding.

## Status

🚧 Pre-alpha — scaffolding. See [BUILD.md](BUILD.md) for the build plan.

## License

AGPL-3.0-or-later. Contributions under the DCO (`git commit -s`).
