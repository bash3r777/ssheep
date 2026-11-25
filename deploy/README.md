# Deploying ssheep

## The connector

One machine in the flock has to be reachable. That is the connector, and it is
the only machine that needs a reachable address at all.

```sh
install -m 0755 ssheep /usr/local/bin/ssheep
install -m 0644 deploy/ssheep-connector.service /etc/systemd/system/
systemctl daemon-reload
```

Then hand it the ticket that `ssheep master` printed:

```sh
ssheep connector "<ticket>" --dir /var/lib/ssheep --install-only
systemctl enable --now ssheep-connector
journalctl -u ssheep-connector | head
```

That is all. The service runs `ssheep connector --dir /var/lib/ssheep`, which for
an enrolled machine means "serve a relay **and** tell the flock where it is". The
connector works out its own address by asking the flock what it looks like from
outside, offers itself, and the master accepts it on its next command. Nothing is
copied by hand.

Behind a NAT with no port forwarding that guess is wrong. The master will say so
and add nothing; then pass the truth:

```sh
ssheep connector "<ticket>" --addr <the address people really reach you at>:7000
```

**Run more than one.** Two connectors on different networks turn a bad afternoon
into a non-event; every sheep holds a link to each of them, and a master falls
through the list. A second ticket is `ssheep master --invite`.

Because the connector is blind, it is the least valuable machine in the flock.
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
ssheep sheep "<ticket>" --dir /var/lib/ssheep --install-only

systemctl enable --now ssheep-sheep
```

`--install-only` unpacks the ticket and exits. Without it, `ssheep sheep` installs
first if there is no identity yet, then serves — so the same line works in a
provisioning script on a fresh machine and as a no-op on one that is already
enrolled. It never overwrites an existing identity.

## Verifying

```sh
ssheep see                      # every machine, and whether it is online
ssheep run --name sheep-1 -- uptime  # one machine
ssheep run --all -- uptime      # all of them at once
```
