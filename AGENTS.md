# Working on ssheep

Notes for an agent picking this repo up. Read this first, then
`docs/ARCHITECTURE.md`.

## What it is

Control machines ("sheep") from a machine you hold ("the master") through a blind
relay ("a connector"). One Go binary does all three roles.

**It is an early prototype and is not secure.** Do not present it otherwise.

## Layout

```
cmd/ssheep/         the CLI: argument parsing, one function per subcommand
internal/flock/     the roster: identity, keys, signing, node and flock ids
internal/invite/    single-use tickets (a key pair plus a signed roster)
internal/frame/     length-prefixed messages over a stream
internal/proto/     the envelope spoken to a connector
internal/netx/      pinned TLS: self-signed certs, fingerprint dialling
internal/tunnel/    the end-to-end session: X25519 + Ed25519 + AES-GCM
internal/connector/ the relay: challenge/response auth, flock registry, routing
internal/sheep/     the agent: links, exec, roster following
internal/master/    the operator side: list, run, publish
site/               the website, served at ssheep.xyz from shared hosting
deploy/             systemd units and how to run them
```

Dependencies: **none beyond the Go standard library.** Keep it that way. The
static binary with no dependencies is a feature, not an accident.

## Build, test, check

```sh
make build     # bin/ssheep
make check     # gofmt, vet, test, build
make cross     # static binaries for linux/darwin/windows, amd64/arm64 into dist/
```

`make check` must pass before anything is pushed. There are 30-odd tests; the
worthwhile ones are in `internal/flock` (signature round trips), `internal/tunnel`
(tamper/replay/ordering) and `internal/connector` (flock isolation, replay
protection, and the roster announcement).

## Conventions

- **Comments explain why, not what.** An unexpected decision deserves the reason.
  `internal/connector/connector.go` and `internal/master/master.go` are the best
  examples to follow.
- Errors are lowercase and prefixed with the package or command name
  (`flock: ...`, `sheep: ...`).
- Roles are `sheep`, `master` and `connector`. The emoji are 👑 and 🐑.
- Do not add a dependency, a config file format, or a subcommand without a
  concrete need. The whole pitch is that it stays small.

## Two traps that cost real time

**A roster is signed over compact JSON but saved pretty-printed.** Verification
compacts the bytes again before checking. If you change how rosters are written,
`TestRosterSurvivesDisk` is the test that will catch you.

**A failing `make check`-style step that silently does not install.** A build
step once ran `make build` without `install -m 0755 bin/ssheep /usr/local/bin/`,
so the machines kept running the old binary and a fix appeared not to work.
After deploying, verify the hash, do not assume.

## Test environment

A relay is live at `138.201.131.115:7000` (a Proxmox VM, `10.20.20.30`, on the
`hetzner` node). Test sheep run as VMs `230` and `231` on `dellpve` and
`dellpve2` at home. Details, including how to reach them and how to tear it all
down, are in `/root/PROJECTS.md`.

## Releasing

```sh
make cross
# then upload dist/* as assets on a GitHub release (bash3r777/ssheep)
```

`site/install.sh` downloads `ssheep-<os>-<arch>` from the latest release, so the
asset names must match `make cross`.
