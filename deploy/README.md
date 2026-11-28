# Deploying ssheep

## Automatic relaying — usually nothing to do here

Every machine you join starts relaying for the flock by itself if it can be
reached, so you normally do not deploy a relay at all: you join sheep, and the
reachable ones take over. A new flock also starts with the project's public relay
in its roster, so the first machine can be behind anything. `ssheep see` shows
which machines are relaying.

What follows is for the times you want a machine to be *only* a relay — a box in a
datacenter with a public address, say — or to donate one to strangers.

## A dedicated relay

A machine whose whole job is relaying is enrolled with a connector ticket. It is
the one role that needs a reachable address.

```sh
install -m 0755 ssheep /usr/local/bin/ssheep
install -m 0644 deploy/ssheep-connector.service /etc/systemd/system/
systemctl daemon-reload
```

Then hand it the ticket that `ssheep master` printed (with `--connector 1`, since
none is printed by default):

```sh
curl -fsSL https://ssheep.xyz/install.sh | sh -s -- --ticket "<ticket>"
systemctl enable --now ssheep-connector
journalctl -u ssheep-connector | head
```

That is all. The service runs `ssheep connector`, which for an enrolled machine
means "serve a relay **and** tell the flock where it is". The state directory is
`SSHEEP_DIR=/var/lib/ssheep`, set in the unit. The relay works out its own
address by asking the flock what it looks like from outside, offers itself, and
the master accepts it on its next command. Nothing is copied by hand.

A relay can serve several flocks at once: install a ticket for each, and one relay
on one port serves them all.

Behind a NAT with no port forwarding that guess is wrong. The master will say so
and add nothing; then pass the truth:

```sh
ssheep connector "<ticket>" --addr <the address people really reach you at>:7000
```

**Run more than one.** Two relays on different networks turn a bad afternoon
into a non-event; every machine holds a link to each of them, and a master falls
through the list. A second ticket is `ssheep master "<flock>" --invite`.

Because a relay is blind, it is the least valuable machine in the flock.
If it is compromised, the attacker learns who talks to whom and nothing else. If
it is lost, nothing is lost with it: stand up another, and it registers itself
the same way.

## Donating a relay

A machine with a good network position can serve strangers. Start it with
`--public` and it will take on any flock whose roster proves itself, without
being told about a single one of them in advance.

```sh
ssheep connector --public --listen :7000 \
  --max-flocks 100 --max-conns 2000 --max-members 1000
```

What that means, stated plainly:

- It sees **metadata** for every flock it serves: which machines are talking,
  when, and what they are called. It never sees a command or its output.
- It forwards ciphertext it cannot inspect, so what it carries is not its
  business — but the bandwidth and the abuse complaints are.
- Limits are yours. Per-flock quotas do not exist yet, so a total cap is all
  there is to stop one flock being the noisy one.

A relay is a good citizen by default: no connection logs, and nothing written
about who talked to whom.

The connector unit already runs as a `DynamicUser` with a state directory. For a
public relay, add `--public` and the limits to `ExecStart`.

## A sheep

```sh
install -m 0755 ssheep /usr/local/bin/ssheep
useradd --system --home /var/lib/ssheep --create-home ssheep
install -m 0644 deploy/ssheep-sheep.service /etc/systemd/system/
systemctl daemon-reload

# one time: the ticket that `ssheep master` printed
ssheep join "<ticket>" --install-only

systemctl enable --now ssheep-sheep
```

The service runs `ssheep sheep`, with `SSHEEP_DIR=/var/lib/ssheep` set in the
unit. `--install-only` takes the ticket and exits. Without it, `ssheep join`
installs first if there is no identity yet, then serves — so the same line works
in a provisioning script on a fresh machine and as a no-op on one that is already
enrolled. It never overwrites an existing identity.

The sheep also relays for its flocks when it can be reached — same binary, same
service, nothing extra to configure. It listens on `--port` (7000 by default) and
offers itself to the flock; a machine that cannot be reached from the master just
stays a sheep. Pass `--addr` if a router forwards a different external port.

A machine can be a sheep in more than one flock: install another ticket and the
one process serves all of them.

## A shell on a sheep

Any machine in the flock can be logged into:

```sh
ssheep shell "<flock>" --name pi            # interactive
ssheep shell "<flock>" --name pi -- htop    # one command, with a terminal
```

Nothing has to be installed or opened on the sheep for this: there is no sshd, no
`authorized_keys`, and no port. It is ssh running inside the encrypted session the
flock already has.

**The shell runs as the user the agent runs as**, so this is worth one thought.
The system unit above runs it as a locked-down `ssheep` system user, which is the
right answer for a machine you only ever command — a shell there is a bare
environment with no dotfiles and no history. If you want a shell that feels like
*yours*, run the agent as yourself with a **user** unit instead:

```sh
mkdir -p ~/.config/systemd/user
cp deploy/ssheep-sheep.service ~/.config/systemd/user/
# drop User=, Group= and StateDirectory= and point SSEHEEP_DIR at your home
systemctl --user daemon-reload
systemctl --user enable --now ssheep-sheep
loginctl enable-linger "$USER"     # keep it running when you are not logged in
```

Then a shell from the master is your own environment, and nothing runs as root
anywhere.

## Verifying

```sh
ssheep see                              # every flock, and who is online
ssheep run "<flock>" --name sheep-1 -- uptime  # one machine
ssheep run "<flock>" -- uptime          # every sheep in a flock
```
