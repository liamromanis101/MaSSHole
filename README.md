# MaSSHole

**MaSSHole** (`MaSSHole.sh`) is a detection-only checker for **\*sshole (CVE-2026-123158)**, the OpenSSH
password-authentication bypass on musl-based Linux systems such as Alpine.

It can audit the machine it runs on, audit other machines over SSH, or probe
a whole address range without logging in. **It never sends a password and
never attempts the bypass.**

To try it against known-good and known-bad hosts first, see the
**[Docker test lab](sshole-lab/README.md)**.

---

## The vulnerability in brief

On musl libc, OpenSSH's own password check (used when sshd runs without PAM)
mishandles accounts whose `/etc/shadow` field is `*`, meaning "no password".
A password between 257 and 1024 bytes is accepted for those accounts. It was
fixed in OpenSSH **10.6p2**, and Alpine backported the fix to its stable branches.

A host is exposed when **all** of these are true:

| Condition | Typical on Alpine? |
|---|---|
| sshd is linked against **musl** libc | Yes |
| sshd runs **without PAM** (`openssh-server` package, or `UsePAM no`) | Yes, default package |
| **`PasswordAuthentication yes`** for the account | Yes, OpenSSH default |
| An account has `*` as its shadow password field and can log in | `root:*` by default, `alpine:*` on cloud images |
| At least one account has a SHA-256/512 (`$5$`/`$6$`) hash | Common |
| OpenSSH is **older than the fixed version** for that distro branch | Until you upgrade |

Root is usually protected by the default `PermitRootLogin prohibit-password`.
glibc distributions, PAM-enabled sshd, Dropbear and non-Linux systems are not
affected.

### Fixed versions

| Alpine branch | Fixed `openssh` package |
|---|---|
| edge | 10.6_p2-r0 |
| 3.24 | 10.3_p1-r2 |
| 3.23 | 10.2_p1-r1 |
| 3.22 | 10.0_p1-r11 |
| 3.21 | 9.9_p2-r1 |
| 3.20 | 9.7_p1-r6 |
| 3.16–3.19 | Patched too; check the Alpine advisory for exact versions |
| Upstream / other musl builds | OpenSSH 10.6p2 |

---

## Requirements

- Any POSIX `sh`. It works with BusyBox `ash` (Alpine), `dash` and `bash`, and
  needs only standard tools (`awk`, `sed`, `grep`).
- **Local mode:** run as root for complete results, because it reads
  `/etc/shadow` and runs `sshd -T`.
- **Network and remote modes:** an OpenSSH `ssh` client. `timeout` and `ip`
  are used when present.
- **Remote mode:** key-based SSH access to the targets (BatchMode is used), plus
  root or a passwordless `sudo`/`doas` rule on them.

## Install

```sh
chmod +x MaSSHole.sh
./MaSSHole.sh --help
```

Nothing needs installing on the targets for remote mode, because the script
is piped over SSH and run there.

---

## Modes

### `--local`: audit this machine

```sh
sudo ./MaSSHole.sh --local
```

It checks, in order:

1. Which sshd binary is running and its OpenSSH version.
2. Whether it's linked against musl (glibc means not affected).
3. The patch level: the installed Alpine package against the fixed version for
   your branch, or the upstream version for custom builds and other musl distros.
   It also warns if a running sshd predates an upgrade and needs a restart.
4. The effective config from `sshd -T`: PAM, `PasswordAuthentication`,
   `PermitRootLogin`, Allow/Deny rules.
5. The accounts with a `*` (or other short) shadow field. Each one is
   re-evaluated with `sshd -T -C user=…`, so `Match` blocks count.
6. **Indicators of compromise:** `Accepted password for <password-less account>`
   in `/var/log/messages*`, `auth.log*`, `secure*`, `logread` and `journalctl`.
   Skip this with `--no-logs`.

### `--remote`: audit other machines over SSH

Runs the local audit on each destination and collects the verdicts.

```sh
./MaSSHole.sh --remote -d 10.0.0.0/28 -l root
./MaSSHole.sh --remote -d 10.0.0.0/28 -l alpine --elevate doas -i ~/.ssh/fleet_key
```

When there is more than one host, full per-host reports are saved to
`masshole-reports-<timestamp>/`, or to the folder given with `--outdir`.

### `--network`: unauthenticated probe

Connects, reads the SSH banner, and asks the server which authentication methods
it offers to each probe user (using the SSH `none` method). No credentials are
sent.

```sh
./MaSSHole.sh --network -d 10.0.0.0/24 --csv scan.csv
```

From the outside, a fixed Alpine host looks identical to a vulnerable one,
because Alpine backports keep the old version string. Network mode therefore
reports **candidates**. Confirm them with `--remote` or `--local`.

### Why network and remote results differ

Expect the two modes to disagree on the same hosts. That's by design, not a
fault: they can see very different amounts.

| Condition | `--network` can see it? | `--remote` / `--local` can see it? |
|---|---|---|
| OpenSSH version | Partly: banner only, often without the `p1`/`p2` suffix | Yes |
| Distro (Debian/Ubuntu suffix) | Sometimes: only distros that add a banner suffix | Yes |
| musl or glibc | No | Yes |
| PAM in use | No | Yes, from `sshd -T` |
| Patched Alpine package (backport) | No: the version string doesn't change | Yes, from the apk database |
| Password auth offered | Yes, for the probe users | Yes, per account including `Match` rules |
| `*` accounts and SHA-256/512 hashes | No | Yes, from `/etc/shadow` |
| Signs of past compromise | No | Yes, from the logs |

So network mode can **rule hosts out** reliably (glibc distros, Dropbear,
password auth off, OpenSSH 10.7 and later), but it can only **flag** the rest
as candidates. Fixed Alpine hosts, PAM builds and already-compromised hosts all
look the same as a vulnerable host from outside. Remote mode separates them.

Typical results for the same host:

| Host | `--network` | `--remote` |
|---|---|---|
| Unpatched Alpine, password auth on | CANDIDATE | VULNERABLE |
| Patched Alpine package | CANDIDATE | OK (patched) |
| Alpine with PAM | CANDIDATE | OK (PAM in use) |
| Unpatched, `PasswordAuthentication no` | NO_PASSWORD_AUTH | AT_RISK (upgrade anyway) |
| Debian / Ubuntu | NOT_AFFECTED | OK (glibc) |
| Unpatched and already exploited | CANDIDATE | COMPROMISED |

**Suggested workflow:** sweep the range with `--network` (no credentials
needed), then run `--remote` against the CANDIDATE hosts to confirm. The
[lab](sshole-lab/README.md#why-the-network-and-remote-scans-disagree) shows
this with real output.

---

## Source and destination

| Option | Meaning |
|---|---|
| `-s, --source ADDR\|IFACE` | Local address (`ssh -b`) or interface (`ssh -B`, OpenSSH 8.9+) to send from. It is checked to exist before scanning. |
| `-d, --dest TARGETS` | Destinations; can be repeated. Comma- or space-separated. |
| `-f, --dest-file FILE` | Destinations from a file, one or more per line, with `#` comments. |
| `-p, --port N` | Default port. Network mode uses 22; remote mode uses your ssh config. |

Destination formats can be mixed freely:

```
host            host:2222          alpine@host        user@10.0.0.5:2222
10.0.0.5        [2001:db8::1]:22   2001:db8::1
10.0.0.0/24     (CIDR; network and broadcast addresses skipped below /31)
10.0.0.10-50    (last-octet range)
10.0.0.10-10.0.1.20   (full range)
```

## All options

| Option | Default | Description |
|---|---|---|
| `--local` / `--remote` / `--network` | – | Mode (required) |
| `-s, --source` | – | Source address or interface |
| `-d, --dest` / `-f, --dest-file` | – | Destinations |
| `-p, --port` | 22 / ssh config | Default SSH port |
| `-l, --login` | ssh config | Remote login user |
| `-i, --identity` | ssh config | Private key for remote logins |
| `--elevate sudo\|doas` | – | Run the remote audit with `sudo -n` / `doas -n` |
| `--accept-new-hostkeys` | off | Remote mode: `StrictHostKeyChecking=accept-new` |
| `--user LIST` | `root,alpine` | Usernames to probe in network mode |
| `-j, --jobs` | 10 | Hosts checked in parallel |
| `-t, --timeout` | 5 | Connect timeout in seconds |
| `--max-hosts` | 4096 | Safety cap on expanded destinations |
| `--csv FILE` | – | Write a CSV summary |
| `--outdir DIR` | auto for multi-host remote | Save full per-host reports |
| `-v, --verbose` | off | Show full per-host output in range scans |
| `--no-logs` | off | Skip the log search |

---

## Reading the results

### Statuses

| Status | Mode | Meaning |
|---|---|---|
| `COMPROMISED` | local/remote | A password login to a password-less account was found in the logs. Treat the host as compromised. |
| `VULNERABLE` | local/remote | All conditions are met; at least one account is exposed. |
| `AT_RISK` | local/remote | Unpatched but not all conditions currently met, patched but sshd needs a restart, or patch level unknown. |
| `OK` | remote | Patched, not affected, or PAM in use (the detail column says which). |
| `CANDIDATE` | network | OpenSSH older than 10.6p2 with no distro suffix, and password auth offered. Confirm remotely. |
| `NO_PASSWORD_AUTH` | network | Password auth not offered to the probe users. |
| `PATCHED` / `NOT_AFFECTED` | network | 10.6p2 or later, or glibc distro / Dropbear / non-Linux / not OpenSSH. |
| `NO_SSH` / `UNREACHABLE` / `TIMEOUT` | network/remote | No SSH service, connection failed, or timed out. |
| `ERROR` | any | Bad source address, SSH or elevation failure, or similar. |

### Exit codes

Range scans return the worst result across all hosts.

| Code | Meaning |
|---|---|
| 0 | Nothing affected |
| 1 | Vulnerable |
| 2 | At risk, or network candidate |
| 3 | Usage error, or no host answered |
| 4 | Indicators of compromise |

### Example: range scan

```
$ ./MaSSHole.sh --network -s 10.0.0.2 -d 10.0.0.1-6

HOST            PORT   STATUS           DETAIL
10.0.0.1        22     CANDIDATE        OpenSSH_10.0p2; password offered to: root alpine
10.0.0.2        22     NOT_AFFECTED     OpenSSH_9.6p1 Ubuntu-3ubuntu13 (glibc distro)
10.0.0.3        22     PATCHED          OpenSSH_10.6p2
10.0.0.4        22     NO_PASSWORD_AUTH OpenSSH_10.0p2; root=publickey alpine=publickey
10.0.0.5        22     NO_SSH           ssh: connect to host 10.0.0.5 port 22: Connection refused
10.0.0.6        22     NOT_AFFECTED     dropbear_2024.86

Summary: CANDIDATE=1 PATCHED=1 NOT_AFFECTED=2 NO_PASSWORD_AUTH=1 NO_SSH=1
```

---

## If a host is vulnerable

1. **Patch:** `apk upgrade openssh && rc-service sshd restart`. For custom
   builds, rebuild with OpenSSH 10.6p2 or later.
2. **Or mitigate at once:** set `PasswordAuthentication no`, then reload sshd.
   Cloud images configured by cloud-init usually have this already.
3. **Check for compromise:** if the log check finds anything, treat the host as
   compromised. Rebuild it rather than clean it, and rotate any credentials it
   held. Logs can be rotated or tampered with, so check your central logging too.
4. **Re-run the script** to confirm the verdict changed.

## Limitations

- **Network mode can't confirm anything.** It can only rule hosts out or flag
  candidates.
- **The 3.16–3.19 fixed versions aren't built in.** On those Alpine branches
  local mode reports the patch level as unknown.
- **`Match Address` rules are evaluated from one arbitrary address.**
  `Match Address`/`Host` rules that apply to specific clients may give a
  different answer for them.
- **Every network probe is a failed login.** Each one creates a failed-auth log
  entry on the target, one connection per `--user` name. Tell your SOC before
  scanning a range.
- **Scan only what you're authorised to.** Use it on systems you own or have
  permission to test.

## Testing

The **[\*sshole lab](sshole-lab/README.md)** is a Docker Compose environment
with a vulnerable host, a patched host, a mitigated host, a PAM host, a glibc
host and a "compromised" host on a private network, plus a scanner container.
Its README lists the expected result for every mode, so you can check the
script before pointing it at real systems.

## References

- [BleepingComputer: OpenSSH flaw lets attackers log into password-disabled Linux accounts](https://www.bleepingcomputer.com/news/security/openssh-flaw-lets-attackers-log-into-password-disabled-linux-accounts/)
- [The Hacker News: OpenSSH issues emergency fix](https://thehackernews.com/2026/11/openssh-issues-emergency-fix-for-flaw.html)
- [Konfirmity advisory: CVE-2026-123158](https://www.konfirmity.com/advisories/alpine-openssh-password-bypass-cve-2026-123158)
- [The Register: Get root on a musl Linux system…](https://www.theregister.com/a/5307910)

---

*MaSSHole version 1.3.0. Detection only; provided as-is for defensive use.*
