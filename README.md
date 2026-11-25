# sshepard

**One binary. One file. One key.**

sshepard is the smallest way to coordinate, control and manage a flock of machines.

Drop one static binary on a machine, paste one line, and it is in the flock. The
flock itself is a small signed file you keep in git — the roster of who is in. The
only secret is your authority key, which you keep offline and never share.

- **No ports open.** Sheep and the shepherd only ever dial out.
- **No accounts, no service to sign up for.** You own the whole thing.
- **No dependencies on the machine.** No Python, no daemon install, no config files.
- **End-to-end encrypted.** A connector forwards ciphertext and cannot read it.
- **Works offline, forever.** The flock keeps running when nobody is reachable.

## The three roles, one binary

| Role | What it does | Holds secrets | Must be reachable |
|---|---|---|---|
| `shepherd` | Mints invites, issues commands, holds the authority key | yes — the flock key | no |
| `connector` | Address book and relay. Blind by design. | no | yes |
| `sheep` | Does the work | only its own key | no |

Roles are hats, not programs. A machine that happens to be reachable can also act
as a connector, so a flock with no VPS is possible.

## The model

- The **roster** is public and replicated. Anyone in the flock can hold a copy, so
  there is no database to back up and no server to restore.
- The **authority** is 32 bytes you keep in your pocket. It signs the roster.
- Every member has its own key. Private keys never leave the machine they belong to.
- Peers verify each other directly, so a compromised connector cannot impersonate anyone.

## Five verbs

```
sshepard init       create a flock
sshepard invite     mint a single-use invite for a new machine
sshepard see        show the flock, live
sshepard run        run a command on one machine or all of them
sshepard forget     revoke a machine
```

## Quick start

```sh
# On the machine that will be your shepherd
sshepard init --name myflock

# On the machine that will be reachable from everywhere
sshepard connector --listen :7000
#   -> prints a pin; add it:  sshepard invite ... see docs/ARCHITECTURE.md

# Add a machine
sshepard invite --name pi
#   -> prints a one-liner to paste on the new machine

# Use it
sshepard see
sshepard run --name pi -- uptime
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how it works underneath.

## Status

Early. Phase 0/1 of the plan: identity, invites, the connector, the relay path and
`run`. Direct connections (IPv6, UPnP, hole punching) and relay election come next;
they are optimisations on top of a working relay, never a replacement for it.

## License

GPL-3.0-or-later.
