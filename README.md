# ssheep

**One binary. One file. One key.**

Control a flock of machines — your own boxes, wherever they are — without opening
a port, without an account, and without trusting anybody's server. A machine can be
in as many flocks as you like.

> **Very early. Not secure.** A working prototype, published because it is useful,
> not because it is safe. There has been no audit. Do not use it for anything you
> would be upset to lose. Expect the protocol to change.

## Three things, one binary

| | | |
|---|---|---|
| 👑 | **master** | Holds a flock's key, mints invites, runs commands. Needs no reachable address — a laptop that is usually off will do. |
| 🐑 | **sheep** | A machine in the flock. Only ever dials *out*. Holds nothing but its own key. |
| 📡 | **connector** | A blind relay and address book. The only role needing a reachable address, and it can be any machine, including a sheep. |

The roster — a small signed file listing who is in the flock — is public and
replicated, so there is no database to lose. The only secret is the flock key,
needed only to add or remove a machine. Peers verify each other end to end: a
connector forwards ciphertext it can neither read nor forge.

## Install

```sh
curl -fsSL https://ssheep.xyz/install.sh | sh
```

Static binaries for Linux, macOS and Windows (amd64, arm64), or build it:

```sh
git clone https://github.com/bash3r777/ssheep && cd ssheep && make build
```

## Quick start

One command sets up a whole flock:

```sh
ssheep master flock "myflock"
```

It prints one line per machine. Paste each line on the machine it names — anything
with a shell, that has never seen ssheep:

```sh
curl -fsSL https://ssheep.xyz/install.sh | sh && ssheep sheep "<ticket>"
curl -fsSL https://ssheep.xyz/install.sh | sh && ssheep connector "<ticket>"
```

That is the whole setup. The connector works out its own address and tells the
flock, so there is no address or fingerprint to copy anywhere. Then:

```sh
ssheep see                   # every machine, live
ssheep run "myflock" -- uptime
```

Every default is overridable — the public relay it starts with, how many tickets
are minted, the connector's port. See `ssheep master -h`.

Add a second connector early. Machines try them in roster order and survive
losing any of them; one connector is a single point of failure.

## More than one flock

A machine is not tied to a flock. Run `ssheep master` again for a second one, and
hand a machine two tickets to put it in both:

```sh
ssheep master flock "work"
ssheep flock list            # every flock this machine knows
ssheep see "work"            # one flock
ssheep see                   # all of them
```

Each flock has its own key, its own roster, its own connectors and its own name for
the machine, and they live in `~/.ssheep/flocks/<name>/`. A relay and a connector
can serve several flocks at once; a machine can be a sheep in one and a connector in
another.

## Where to read more

- [ssheep.xyz](https://ssheep.xyz) — what it is, in one page
- [ssheep.xyz/about](https://ssheep.xyz/about) — how it works, for humans
- [ssheep.xyz/agents.txt](https://ssheep.xyz/agents.txt) — the same, for agents
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — the full design, and what is deliberately missing
- [deploy/README.md](deploy/README.md) — running a connector and a sheep under systemd

## Status

Early, but working end to end: identity, invites, connectors, failover across
more than one of them, many flocks on one relay, one machine in many flocks, the
relay path, `see`, `run`, and revocation across networks.

Known gaps: online/offline is reported per connector, so with several connectors a
machine connected to a different one can show as offline. There is no interactive
shell and no file transfer. Direct connections (IPv6, UPnP, hole punching) would
sit on top of the relay rather than replace it.

## Licence

GPL-3.0-or-later.
