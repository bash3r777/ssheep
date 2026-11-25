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

## The verbs

```
sshepard init               create a flock
sshepard connector          run an address book and relay
sshepard connector add      register a connector with the flock
sshepard connector list     show them, and whether they answer
sshepard invite             mint a single-use invite for a new machine
sshepard see                show the flock, live
sshepard run                run a command on one machine or all of them
sshepard forget             revoke a machine
```

## Quick start

```sh
# On the machine that will be your shepherd
sshepard init --name myflock

# On a machine that is reachable from everywhere
sshepard connector --listen :7000

# Register it. This reads its fingerprint from the connector itself, and
# publishes the roster so the connector knows the flock.
sshepard connector add --addr <that machine>:7000

# Add a machine
sshepard invite --name pi --out pi.ticket
#   copy pi.ticket and the binary across, then on the new machine:
#   sshepard sheep --invite-file pi.ticket --install-only

# Use it
sshepard see
sshepard run --name pi -- uptime
```

Add a second connector early. With only one, its bad day is the flock's bad
day — every machine tries the connectors in order and survives losing any of
them.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how it works underneath.

## Status

Early, but working end to end: identity, invites, connectors, the relay path,
`see`, `run` on one machine or all of them, revocation, and failover across
more than one connector.

Next: multi-flock connectors (so one relay can serve several flocks) and the
public relay pool, so a new user with no public IP anywhere can still join.
Direct connections — IPv6, UPnP, hole punching — sit on top of the relay rather
than replacing it: the relay stays as the fallback that always works.

## License

GPL-3.0-or-later.
