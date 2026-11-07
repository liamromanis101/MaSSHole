# *sshole detection lab

A small Docker lab for checking that MaSSHole (`MaSSHole.sh`) gives the right answer
for each kind of host. The script is detection-only, and nothing in this lab
sends an oversized password or attempts the bypass.

> **The `vulnerable`, `mitigated` and `compromised` containers run a genuinely
> unpatched sshd.** They sit on a private Docker bridge with no published
> ports. Don't expose them, don't run the lab on a shared Docker host, and tear
> it down when you've finished (`docker compose down`).

## What's in it

| IP | Service | What it is | Expected `--local` / `--remote` | Expected `--network` |
|---|---|---|---|---|
| 172.30.99.10 | `scanner` | Alpine with ssh client; run the script from here | – | – |
| 172.30.99.11 | `vulnerable` | OpenSSH 10.0p1 built from source on musl, no PAM, password auth on, `alpine:*` account, `bob` with SHA-512 hash | **VULNERABLE** (exit 1) | CANDIDATE |
| 172.30.99.12 | `patched` | Alpine's current `openssh-server` package | **PATCHED** (exit 0) | CANDIDATE ¹ |
| 172.30.99.13 | `mitigated` | Same build as `vulnerable`, `PasswordAuthentication no` | **AT RISK**: unpatched, conditions not met (exit 2) | NO_PASSWORD_AUTH |
| 172.30.99.14 | `pam` | Alpine `openssh-server-pam`, `UsePAM yes` | **NOT AFFECTED** (exit 0) | CANDIDATE ¹ |
| 172.30.99.15 | `debian` | Debian bookworm OpenSSH (glibc) | **NOT AFFECTED** (exit 0) | NOT_AFFECTED |
| 172.30.99.16 | `compromised` | `vulnerable` + a seeded `Accepted password for alpine` log line | **COMPROMISED** (exit 4) | CANDIDATE |
| 172.30.99.17 | – | nothing (left empty on purpose) | UNREACHABLE | NO_SSH |

¹ This is expected. An unauthenticated probe only sees the banner and the
offered auth methods. Alpine's fixed packages and PAM builds look the same as a
vulnerable host from outside, which is why `--network` reports *candidates*
and `--remote` is the confirmation step. See
[Why the network and remote scans disagree](#why-the-network-and-remote-scans-disagree).

Why build from source? Alpine's repositories only carry the fixed `openssh`
packages now, so an unpatched upstream build is the dependable way to get a
vulnerable sshd. `OPENSSH_VERSION` in `docker-compose.yml` can be changed to
any portable release before 10.6p2.

## Requirements

- Docker with Compose v2 (`docker compose version`)
- Internet access during the build (Alpine/Debian packages and the OpenSSH
  tarball from cdn.openbsd.org)
- About 2–3 minutes for the first build; the source compile is the slow part

## 1. Set up

The repository doesn't include any SSH keys. Generate your own lab key pair
first: the images copy it in at build time, so the build fails without it.
`keys/` is in `.gitignore`, so it won't be committed. Use a fresh key just for
the lab, never one of your real keys.

```sh
cd sshole-lab
mkdir -p keys results
ssh-keygen -t ed25519 -N '' -C sshole-lab -f keys/lab_ed25519   # lab-only key
chmod +x MaSSHole.sh
docker compose build
docker compose up -d
docker compose ps          # all seven services should be "running"
```

If `172.30.99.0/24` clashes with a network you use, change the subnet and the
`ipv4_address` lines in `docker-compose.yml`, and the addresses below.

## 2. Local mode (run inside each target)

```sh
for s in vulnerable patched mitigated pam debian compromised; do
  echo "=== $s"; docker compose exec -T "$s" sh /lab/MaSSHole.sh --local
  echo "exit=$?"
done
```

Compare the verdicts and exit codes with the table above.

## 3. Network mode (from the scanner)

```sh
docker compose exec scanner sh /lab/MaSSHole.sh --network \
    -s 172.30.99.10 -d 172.30.99.11-17 --user root,alpine,bob \
    --csv /lab/results/network.csv
```

Try the other destination forms too. They should all scan the same hosts:

```sh
docker compose exec scanner sh /lab/MaSSHole.sh --network -s eth0 -d 172.30.99.0/28
docker compose exec scanner sh /lab/MaSSHole.sh --network -d 172.30.99.11,172.30.99.15:22 -v
```

And check that a bad source is rejected (exit 3):

```sh
docker compose exec scanner sh /lab/MaSSHole.sh --network -s 10.9.9.9 -d 172.30.99.11
```

## 4. Remote mode (from the scanner)

The lab key is installed for `root` on every target and for `alpine` (with
passwordless `doas`) on the Alpine targets.

As root, across the whole range:

```sh
docker compose exec scanner sh /lab/MaSSHole.sh --remote \
    -s 172.30.99.10 -d 172.30.99.11-17 -l root --accept-new-hostkeys \
    --outdir /lab/results/reports --csv /lab/results/remote.csv
echo "exit=$?"     # expect 4: the worst result is the compromised host
```

As `alpine` with `doas`, like an Alpine cloud image (Alpine targets only):

```sh
docker compose exec scanner sh /lab/MaSSHole.sh --remote \
    -d 172.30.99.11-14,172.30.99.16 -l alpine --elevate doas --accept-new-hostkeys
```

The full per-host reports land in `results/reports/` on your machine.

## Why the network and remote scans disagree

Run steps 3 and 4 and you'll get two quite different tables for the same seven
hosts:

| Host | `--network` | `--remote` | Why they differ |
|---|---|---|---|
| .11 vulnerable | CANDIDATE | VULNERABLE | Network mode was right to flag it; remote confirms it (the `alpine:*` account is exposed). |
| .12 patched | CANDIDATE | OK: patched | Alpine's fix keeps the banner at `OpenSSH_10.0`; only the package revision shows it's fixed. |
| .13 mitigated | NO_PASSWORD_AUTH | AT_RISK | Both agree it can't be exploited as configured; remote also sees it's unpatched. |
| .14 pam | CANDIDATE | OK: PAM in use | PAM isn't visible from outside. |
| .15 debian | NOT_AFFECTED | OK: glibc | The `Debian-…` banner suffix gives it away, so both agree. |
| .16 compromised | CANDIDATE | COMPROMISED | The evidence is a log line on the host; nothing on the network shows it. |
| .17 | NO_SSH | UNREACHABLE | No host. |

Both tables are correct. From outside, .11, .12, .14 and .16 are
indistinguishable: same banner, password offered. Of those four candidates, two
are real problems and two are false positives. That's the gap remote mode fills.

This is the workflow to use on a real network: sweep with `--network`, then
confirm the CANDIDATE hosts with `--remote`. The
[script README](../README.md#why-network-and-remote-results-differ) explains
what each mode can and can't see.

## 5. Scanning from the host (Linux only)

On Linux the host can reach the bridge directly. Its address on the lab
network is the gateway, `172.30.99.1`:

```sh
./MaSSHole.sh --network -s 172.30.99.1 -d 172.30.99.11-17
./MaSSHole.sh --remote -d 172.30.99.11-17 -l root -i keys/lab_ed25519 --accept-new-hostkeys
```

Docker Desktop on macOS and Windows doesn't route to bridge networks, so use the
scanner container there.

## 6. Experiments worth trying

- **Fix the vulnerable host by config:** run
  `docker compose exec vulnerable sh -c "sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config && kill -HUP 1"`,
  then re-run the local check. It should drop from VULNERABLE (1) to AT RISK (2).
- **Remove the account precondition:**
  `docker compose exec vulnerable sed -i 's/^alpine:\*:/alpine:!:/' /etc/shadow`.
  The account is no longer reported as exposed.
- **Per-user Match rules:** add `Match User alpine` / `PasswordAuthentication no`
  to the end of `/etc/ssh/sshd_config` in `vulnerable`, then `kill -HUP 1`.
  The script evaluates Match blocks per account, so `alpine` should stop being
  reported as exposed.

Changes made with `exec` are lost when the container is recreated
(`docker compose up -d --force-recreate <service>`).

## 7. Tear down

```sh
docker compose down --rmi local     # removes containers, network and lab images
rm -rf keys results                 # optional
```

## Troubleshooting

- **Build fails with `"/keys/lab_ed25519.pub": not found`** (or a similar
  "failed to compute cache key" error). You haven't generated the lab key yet.
  Run the `mkdir` and `ssh-keygen` lines from step 1 inside `sshole-lab/`,
  then build again.
- **Build fails downloading the OpenSSH tarball.** Check your proxy, or
  download `openssh-10.0p1.tar.gz` yourself, verify it against the `.asc`
  signature from openssh.com, and change the `curl` step in
  `images/Dockerfile.alpine-source` to a `COPY`.
- **`Permission denied (publickey)` in remote mode.** The key in `keys/` must be
  the one that was there when you ran `docker compose build`. Rebuild after
  regenerating it.
- **`doas` errors with `--elevate doas`.** Use `-l root` instead; the doas
  config location differs between Alpine releases.
- **`ip` check fails for `-s`.** The address you gave isn't on the scanner;
  `docker compose exec scanner ip -brief addr` shows what it has.
