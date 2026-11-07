#!/bin/sh
# MaSSHole - detection-only checker for "*sshole" (CVE-2026-123158)
#
# OpenSSH sshd on musl libc (Alpine, Buildroot, Yocto, OpenWrt+OpenSSH...),
# built/run WITHOUT PAM, with PasswordAuthentication enabled, accepts an
# oversized password (257-1024 bytes) for accounts whose /etc/shadow field is
# "*" (no password). Fixed in OpenSSH 10.6p2 and in Alpine package backports.
#
# This script NEVER sends a password and never attempts authentication.
#
# Modes:
#   --local                    audit this host (run as root for full results)
#   --remote  -d TARGETS       run the local audit on hosts you can SSH into
#   --network -d TARGETS       unauthenticated probe: banner + offered auth methods
#
# TARGETS (destination): comma/space separated, any mix of
#   host  host:port  user@host  10.0.0.5  [2001:db8::1]:22
#   10.0.0.0/24   10.0.0.10-50   10.0.0.10-10.0.1.20
# or one-per-line in a file with -f. Source address/interface: -s.
#
# Exit codes:
#   0 not affected / patched / mitigated
#   1 VULNERABLE (all conditions met locally)
#   2 at risk or indeterminate (e.g. unpatched but conditions not all met,
#     sshd needs restart, network probe looks like a candidate)
#   3 usage or runtime error
#   4 indicators of compromise found in logs

set -u

SCRIPT_VERSION="1.3.0"
FIXED_UPSTREAM="10.6p2"
PROBE_ADDR="192.0.2.1"            # TEST-NET-1, used for sshd -T -C evaluation
PROBE_HOST="masshole.invalid"

# ---------------------------------------------------------------- output ----
if [ -t 1 ]; then
    C_R=$(printf '\033[31m'); C_G=$(printf '\033[32m'); C_Y=$(printf '\033[33m')
    C_B=$(printf '\033[1m');  C_0=$(printf '\033[0m')
else
    C_R=""; C_G=""; C_Y=""; C_B=""; C_0=""
fi
hdr()  { printf '\n%s== %s ==%s\n' "$C_B" "$*" "$C_0"; }
info() { printf '  [i] %s\n' "$*"; }
ok()   { printf '  %s[+]%s %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '  %s[!]%s %s\n' "$C_Y" "$C_0" "$*"; }
bad()  { printf '  %s[x]%s %s\n' "$C_R" "$C_0" "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 3; }

usage() {
    cat <<EOF
MaSSHole v$SCRIPT_VERSION - detect *sshole (CVE-2026-123158) conditions.
Detection only: no passwords are sent, no login is attempted.

Usage:
  $0 --local [--no-logs]
  $0 --network -d TARGETS [-s SOURCE] [options]
  $0 --remote  -d TARGETS [-s SOURCE] [-l USER] [--elevate doas|sudo] [options]

Modes:
  --local              Audit the machine this runs on (root recommended).
  --network            Unauthenticated probe: SSH banner and offered auth methods.
  --remote             SSH to each destination and run the local audit there
                       (needs key-based login; BatchMode is used).

Source and destination:
  -s, --source ADDR|IFACE   Local address (ssh -b) or interface (ssh -B) to send from.
  -d, --dest TARGETS        Destination(s); repeatable. Comma/space separated mix of:
                              host  host:port  user@host  10.0.0.5  [2001:db8::1]:2222
                              10.0.0.0/24  10.0.0.10-50  10.0.0.10-10.0.1.20
  -f, --dest-file FILE      Read destinations from FILE (one or more per line, # comments).
  -p, --port N              Default SSH port (network default 22; remote default
                            comes from your ssh config).

Options:
  -l, --login USER     Remote login user (or use user@host in the destination).
  -i, --identity FILE  Private key for --remote logins.
  --elevate CMD        Run the remote audit via sudo or doas (needs a NOPASSWD/nopass rule).
  --user LIST          Usernames to probe in --network mode (default: root,alpine).
  -j, --jobs N         Parallel hosts (default 10).
  -t, --timeout N      Connect timeout in seconds (default 5).
  --max-hosts N        Safety cap on expanded destinations (default 4096).
  --csv FILE           Write a CSV summary.
  --outdir DIR         Save full per-host reports (default for multi-host --remote).
  --accept-new-hostkeys  Remote mode: accept unknown host keys (StrictHostKeyChecking=accept-new).
  -v, --verbose        Show full per-host output in range scans.
  --no-logs            Skip searching logs for indicators of compromise.
  -h, --help           Show this help.

Examples:
  $0 --network -s 10.0.0.2 -d 10.0.0.0/24 --csv scan.csv
  $0 --network -s eth1 -d 192.168.1.10-60,192.168.1.200:2222
  $0 --remote  -s 10.0.0.2 -d 10.0.0.0/28 -l alpine --elevate doas
  $0 --remote  -f hosts.txt --outdir reports/

Exit codes (worst result across all hosts):
  0 none affected   1 vulnerable   2 at risk / candidate
  3 error / no host answered       4 indicators of compromise
EOF
}

# ------------------------------------------------------------- helpers ------
# "10.3p1" -> 100301 ; "9.9p2" -> 90902
ver_num() {
    echo "$1" | awk -F'[.p]' '{ printf "%d\n", $1*10000 + $2*100 + ($3==""?0:$3) }'
}

# ver_status VERSION -> patched | unpatched | ambiguous
# Banners from OpenSSH 10.x often omit the portable suffix ("OpenSSH_10.6"),
# and 10.6p1 (vulnerable) vs 10.6p2 (fixed) then look identical.
ver_status() {
    n=$(ver_num "$1")
    case "$1" in
        *p*) if [ "$n" -ge "$(ver_num "$FIXED_UPSTREAM")" ]; then echo patched; else echo unpatched; fi ;;
        *)   if   [ "$n" -ge 100700 ]; then echo patched
             elif [ "$n" -ge 100600 ]; then echo ambiguous
             else echo unpatched; fi ;;
    esac
}

# Fixed Alpine package per branch (from Alpine / OpenSSH advisories, 2026-11-05)
alpine_fixed_for_branch() {
    case "$1" in
        edge) echo "10.6_p2-r0" ;;
        3.24) echo "10.3_p1-r2" ;;
        3.23) echo "10.2_p1-r1" ;;
        3.22) echo "10.0_p1-r11" ;;
        3.21) echo "9.9_p2-r1" ;;
        3.20) echo "9.7_p1-r6" ;;
        *)    echo "" ;;
    esac
}

# Installed version of an apk package, read from the apk database
apk_installed_ver() {
    db=/lib/apk/db/installed
    [ -r "$db" ] || return 1
    awk -v p="$1" '
        /^P:/ { name = substr($0, 3) }
        /^V:/ { if (name == p) { print substr($0, 3); exit } }
        /^$/  { name = "" }' "$db"
}

# ---------------------------------------------------------- local audit -----
local_check() {
    DO_LOGS=$1
    IS_ROOT=no; [ "$(id -u)" = 0 ] && IS_ROOT=yes

    printf '%sMaSSHole local audit%s  host=%s  date=%s\n' "$C_B" "$C_0" \
        "$(hostname 2>/dev/null || uname -n)" "$(date -u '+%Y-%m-%dT%H:%MZ')"
    [ "$IS_ROOT" = yes ] || warn "Not running as root: shadow and sshd -T checks will be incomplete."

    # --- 1. sshd present -----------------------------------------------------
    hdr "1. OpenSSH server"
    SSHD=""
    for pid in $(pidof sshd sshd.pam 2>/dev/null); do
        exe=$(readlink "/proc/$pid/exe" 2>/dev/null); exe=${exe% (deleted)}
        [ -n "$exe" ] && [ -x "$exe" ] && { SSHD=$exe; break; }
    done
    [ -z "$SSHD" ] && SSHD=$(command -v sshd 2>/dev/null)
    for c in /usr/sbin/sshd /usr/sbin/sshd.pam /usr/local/sbin/sshd /sbin/sshd; do
        [ -z "$SSHD" ] && [ -x "$c" ] && SSHD=$c
    done
    if [ -z "$SSHD" ]; then
        if [ -x /usr/sbin/dropbear ] || command -v dropbear >/dev/null 2>&1; then
            info "Dropbear is present; Dropbear is not affected."
        fi
        hdr "Verdict"; ok "NOT AFFECTED (no OpenSSH sshd installed)."
        return 0
    fi
    SSHD_VER=$("$SSHD" -V 2>&1 | sed -n 's/.*OpenSSH_\([0-9][0-9]*\.[0-9][0-9]*\(p[0-9][0-9]*\)\{0,1\}\).*/\1/p' | head -n1)
    [ -z "$SSHD_VER" ] && SSHD_VER=$(ssh -V 2>&1 | sed -n 's/.*OpenSSH_\([0-9][0-9]*\.[0-9][0-9]*\(p[0-9][0-9]*\)\{0,1\}\).*/\1/p' | head -n1)
    info "sshd binary: $SSHD"
    info "OpenSSH version: ${SSHD_VER:-unknown}"

    # --- 2. C library --------------------------------------------------------
    hdr "2. C library"
    MUSL=unknown
    if ldd "$SSHD" 2>&1 | grep -qi musl || ls /lib/ld-musl-*.so.1 >/dev/null 2>&1; then
        MUSL=yes; bad "sshd is linked against musl libc."
    elif ldd --version 2>&1 | grep -qiE 'glibc|gnu libc|gnu c library'; then
        MUSL=no
        hdr "Verdict"; ok "NOT AFFECTED (glibc system)."
        return 0
    else
        warn "Could not determine C library; continuing as if musl."
    fi

    # --- 3. patch level ------------------------------------------------------
    hdr "3. Patch level"
    PATCHED=unknown
    ALPINE_BRANCH=""; PKGVER=""
    if [ -r /etc/alpine-release ]; then
        rel=$(cat /etc/alpine-release)
        case "$rel" in
            *_alpha*|*_beta*) ALPINE_BRANCH=edge ;;
            *) ALPINE_BRANCH=$(echo "$rel" | cut -d. -f1,2) ;;
        esac
        grep -qs '/edge/' /etc/apk/repositories && ALPINE_BRANCH=edge
        info "Alpine release $rel (branch: $ALPINE_BRANCH)"

        PKG=""
        for p in openssh-server openssh-server-pam; do
            v=$(apk_installed_ver "$p")
            [ -n "$v" ] && { PKG=$p; PKGVER=$v; info "Installed: $p-$v"; }
        done
        [ -z "$PKGVER" ] && warn "sshd is not from an Alpine package (custom build?)."
        FIXED=$(alpine_fixed_for_branch "$ALPINE_BRANCH")
        if [ -n "$PKGVER" ] && [ -n "$FIXED" ] && command -v apk >/dev/null 2>&1; then
            cmp=$(apk version -t "$PKGVER" "$FIXED" 2>/dev/null)
            if [ "$cmp" = "<" ]; then
                PATCHED=no; bad "$PKG $PKGVER is older than fixed $FIXED."
            else
                PATCHED=yes; ok "$PKG $PKGVER >= fixed $FIXED."
            fi
        elif [ -n "$PKGVER" ]; then
            warn "No fixed-version entry for branch '$ALPINE_BRANCH' in this script (3.16-3.19 were"
            warn "also patched). Check the Alpine advisory / secdb for your branch."
        fi
    fi
    if [ "$PATCHED" = unknown ] && [ -n "$SSHD_VER" ]; then
        vs=$(ver_status "$SSHD_VER")
        if [ "$vs" = patched ]; then
            PATCHED=yes; ok "OpenSSH $SSHD_VER >= $FIXED_UPSTREAM."
        elif [ "$vs" = ambiguous ]; then
            warn "OpenSSH $SSHD_VER: version string lacks the p1/p2 suffix; cannot tell 10.6p1 from 10.6p2."
        elif [ -z "$ALPINE_BRANCH" ] || [ -z "${PKGVER:-}" ]; then
            PATCHED=no; bad "OpenSSH $SSHD_VER < $FIXED_UPSTREAM (not from a distro package; no backport assumed)."
        fi
    fi

    # Running daemon started before an upgrade?
    STALE=no
    for pid in $(pidof sshd 2>/dev/null; pidof sshd.pam 2>/dev/null); do
        exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
        case "$exe" in *"(deleted)"*) STALE=yes ;; esac
    done
    if [ "$STALE" = yes ]; then
        warn "A running sshd uses a deleted/replaced binary: restart sshd to load the fix."
    elif [ -z "$(pidof sshd sshd.pam 2>/dev/null)" ]; then
        info "sshd does not appear to be running right now."
    fi

    # --- 4. PAM and effective configuration ---------------------------------
    hdr "4. sshd configuration"
    CFG=$("$SSHD" -T 2>/dev/null)
    if [ -z "$CFG" ]; then
        warn "sshd -T failed (need root / readable host keys). Falling back to config grep."
        PA=$(cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null \
             | awk 'tolower($1)=="passwordauthentication"{print tolower($2); exit}')
        PA=${PA:-yes}
        PRL=$(cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null \
             | awk 'tolower($1)=="permitrootlogin"{print tolower($2); exit}')
        PRL=${PRL:-prohibit-password}
        UP=$(cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null \
             | awk 'tolower($1)=="usepam"{print tolower($2); exit}')
        UP=${UP:-no}
    else
        PA=$(echo "$CFG"  | awk '$1=="passwordauthentication"{print $2}')
        PRL=$(echo "$CFG" | awk '$1=="permitrootlogin"{print $2}')
        UP=$(echo "$CFG"  | awk '$1=="usepam"{print $2}')
        # usepam is only printed when sshd was built with PAM support
        [ -z "$UP" ] && { UP=no; info "sshd built without PAM support."; }
    fi
    if [ "$UP" = yes ]; then
        ok "UsePAM yes: passwords are checked via PAM. Not affected."
        PAM_SAFE=yes
    else
        bad "UsePAM no / no PAM: sshd checks passwords itself via crypt()."
        PAM_SAFE=no
    fi
    if [ "$PA" = yes ]; then bad "PasswordAuthentication yes (global)."
    else ok "PasswordAuthentication $PA (global)."; fi
    info "PermitRootLogin $PRL"
    for k in allowusers allowgroups denyusers denygroups; do
        v=$(echo "$CFG" | awk -v k="$k" '$1==k{ $1=""; print }' | tr '\n' ' ')
        [ -n "${v# }" ] && info "$k:$v"
    done

    # --- 5. accounts ---------------------------------------------------------
    hdr "5. Accounts"
    SHORT=""; HASHES=0; REACHABLE=""
    if [ -r /etc/shadow ]; then
        HASHES=$(awk -F: '$2 ~ /^\$[56]\$/ {n++} END {print n+0}' /etc/shadow)
        if [ "$HASHES" -gt 0 ]; then
            bad "$HASHES account(s) have SHA-256/512 password hashes (a precondition)."
        else
            ok "No SHA-256/512 password hashes present (reported precondition not met)."
        fi
        SHORT=$(awk -F: 'length($2) > 0 && length($2) < 4 {print $1 ":" $2}' /etc/shadow)
        if [ -z "$SHORT" ]; then
            ok "No accounts with a '*' (or other <4 char) password field."
        else
            for entry in $SHORT; do
                u=${entry%%:*}; f=${entry#*:}
                sh_=$(awk -F: -v u="$u" '$1==u{print $7}' /etc/passwd)
                upa=$PA; uprl=$PRL
                if [ -n "$CFG" ]; then
                    ucfg=$("$SSHD" -T -C "user=$u,host=$PROBE_HOST,addr=$PROBE_ADDR" 2>/dev/null)
                    if [ -n "$ucfg" ]; then
                        upa=$(echo "$ucfg"  | awk '$1=="passwordauthentication"{print $2}')
                        uprl=$(echo "$ucfg" | awk '$1=="permitrootlogin"{print $2}')
                    fi
                fi
                reach=yes
                [ "$upa" = yes ] || reach=no
                [ "$u" = root ] && [ "$uprl" != yes ] && reach=no
                case "$f" in "*") tag="'*'" ;; *) tag="'$f' (locked/short)" ;; esac
                if [ "$reach" = yes ] && [ "$f" = "*" ]; then
                    bad "$u: field $tag, shell=$sh_, password auth allowed -> EXPOSED"
                    REACHABLE="$REACHABLE $u"
                else
                    extra=""; [ "$u" = root ] && extra=", permitrootlogin=$uprl"
                    info "$u: field $tag, shell=$sh_, passwordauth=$upa$extra (not exposed)"
                fi
                if [ "$reach" = yes ] && [ "$f" = "*" ]; then
                    case "$sh_" in */nologin|*/false)
                        warn "  $u has a non-login shell, but auth still succeeds (e.g. port forwarding)." ;;
                    esac
                fi
            done
            info "Match blocks evaluated for an arbitrary remote address ($PROBE_ADDR);"
            info "address-specific Match rules may differ for real clients."
        fi
    else
        warn "/etc/shadow not readable; cannot check account conditions."
    fi

    # --- 6. logs -------------------------------------------------------------
    IOC=no
    if [ "$DO_LOGS" = yes ] && [ -n "$SHORT" ]; then
        hdr "6. Indicators of compromise"
        users=$(for e in $SHORT; do printf '%s|' "${e%%:*}"; done); users=${users%|}
        pat="Accepted password for ($users) from"
        hits=$(
            for f in /var/log/messages* /var/log/auth.log* /var/log/secure* /var/log/sshd*; do
                [ -f "$f" ] || continue
                case "$f" in
                    *.gz) zcat "$f" 2>/dev/null ;;
                    *)    cat  "$f" 2>/dev/null ;;
                esac | grep -E "$pat" | sed "s|^|$f: |"
            done
            command -v logread >/dev/null 2>&1 && logread 2>/dev/null | grep -E "$pat" | sed 's|^|logread: |'
            command -v journalctl >/dev/null 2>&1 && journalctl -q --no-pager 2>/dev/null | grep -E "$pat" | sed 's|^|journal: |'
        )
        if [ -n "$hits" ]; then
            IOC=yes
            bad "Password logins to accounts that have no password were found:"
            echo "$hits" | head -n 50 | sed 's/^/      /'
            bad "Treat this host as compromised (advisory guidance)."
        else
            ok "No 'Accepted password' entries for password-less accounts in available logs."
            info "Logs may be rotated, shipped elsewhere, or tampered with; check your SIEM too."
        fi
    fi

    # --- verdict -------------------------------------------------------------
    hdr "Verdict"
    if [ "$IOC" = yes ]; then
        bad "INDICATORS OF COMPROMISE. Patch, then investigate/rebuild."; return 4
    fi
    if [ "$PAM_SAFE" = yes ]; then
        ok "NOT AFFECTED (PAM in use)."; return 0
    fi
    if [ "$PATCHED" = yes ]; then
        if [ "$STALE" = yes ]; then warn "PATCHED ON DISK, but restart sshd."; return 2; fi
        ok "PATCHED."; return 0
    fi
    if [ -n "$REACHABLE" ] && [ "$HASHES" -gt 0 ] && [ "$PATCHED" = no ]; then
        bad "VULNERABLE: exposed account(s):$REACHABLE"
        info "Fix: apk upgrade openssh && rc-service sshd restart"
        info "Mitigate now: set 'PasswordAuthentication no' and reload sshd."
        return 1
    fi
    if [ "$PATCHED" = no ]; then
        warn "UNPATCHED, but not all exploit conditions are currently met. Upgrade anyway."
        return 2
    fi
    warn "INDETERMINATE: patch level unknown. Review the findings above."
    return 2
}

# ----------------------------------------------------- target expansion ----
# Reads target specs on stdin (one or more per line, comma separated) and
# prints "user|host|port" lines. Supported specs:
#   host  host:port  user@host  1.2.3.4  1.2.3.4:2222  [2001:db8::1]:22  2001:db8::1
#   10.0.0.0/24 (CIDR, network/broadcast skipped below /31)
#   10.0.0.10-50 (last-octet range)   10.0.0.10-10.0.1.20 (full range)
# Lines starting with # are ignored. Errors are printed as "ERR|message".
expand_targets() {
    awk -v defport="$PORT" -v maxh="$MAX_HOSTS" '
    function ip2n(s,   a, j) {
        if (split(s, a, ".") != 4) return -1
        for (j = 1; j <= 4; j++) if (a[j] !~ /^[0-9]+$/ || a[j] + 0 > 255) return -1
        return ((a[1] * 256 + a[2]) * 256 + a[3]) * 256 + a[4]
    }
    function n2ip(n) {
        return int(n / 16777216) % 256 "." int(n / 65536) % 256 "." int(n / 256) % 256 "." n % 256
    }
    function emit(u, h, p) {
        if (++count > maxh) {
            print "ERR|target list expands to more than " maxh " hosts; narrow it or raise --max-hosts"
            stop = 1; exit
        }
        print u "|" h "|" p
    }
    {
        sub(/#.*/, ""); gsub(/[ \t\r]+/, ",")
        nf = split($0, items, ",")
        for (k = 1; k <= nf && !stop; k++) {
            it = items[k]; if (it == "") continue
            u = ""; p = defport
            if (index(it, "@")) { u = substr(it, 1, index(it, "@") - 1); it = substr(it, index(it, "@") + 1) }
            if (it ~ /^\[[0-9A-Fa-f:.]+\](:[0-9]+)?$/) {          # [v6] or [v6]:port
                h = it; sub(/^\[/, "", h); sub(/\].*$/, "", h)
                if (it ~ /\]:[0-9]+$/) { p = it; sub(/^.*\]:/, "", p) }
                emit(u, h, p); continue
            }
            tmp = it; colons = gsub(/:/, ":", tmp)
            if (colons > 1) { emit(u, it, p); continue }            # bare IPv6
            if (colons == 1) {
                p = substr(it, index(it, ":") + 1); it = substr(it, 1, index(it, ":") - 1)
                if (p !~ /^[0-9]+$/) { print "ERR|bad port in " items[k]; continue }
            }
            if (it ~ /^[0-9.]+\/[0-9]+$/) {                          # CIDR
                base = substr(it, 1, index(it, "/") - 1); bits = substr(it, index(it, "/") + 1) + 0
                b = ip2n(base)
                if (b < 0 || bits > 32) { print "ERR|bad CIDR " it; continue }
                size = 2 ^ (32 - bits); net = b - (b % size); first = net; last = net + size - 1
                if (bits < 31) { first++; last-- }
                for (x = first; x <= last && !stop; x++) emit(u, n2ip(x), p)
                continue
            }
            if (it ~ /^[0-9.]+-[0-9.]+$/) {                          # range
                lo = substr(it, 1, index(it, "-") - 1); hi = substr(it, index(it, "-") + 1)
                if (hi ~ /^[0-9]+$/) { split(lo, o, "."); hi = o[1] "." o[2] "." o[3] "." hi }
                a = ip2n(lo); z = ip2n(hi)
                if (a < 0 || z < 0 || z < a) { print "ERR|bad range " it; continue }
                for (x = a; x <= z && !stop; x++) emit(u, n2ip(x), p)
                continue
            }
            if (it ~ /\//) { print "ERR|bad destination " it; continue }
            emit(u, it, p)
        }
    }'
}

# ------------------------------------------------------------ source ------
# Sets SSH_SRC to "-b ADDR" or "-B IFACE" after checking it exists locally.
setup_source() {
    SSH_SRC=""
    [ -z "$SRC" ] && return 0
    if echo "$SRC" | grep -Eq '^[0-9.]+$|:'; then
        if command -v ip >/dev/null 2>&1; then
            ip -o addr show 2>/dev/null | grep -Fq " $SRC/" || \
                die "source address $SRC is not configured on this machine"
        elif command -v ifconfig >/dev/null 2>&1; then
            ifconfig 2>/dev/null | grep -Eq "inet6? (addr:)?$SRC[ /%]" || \
                die "source address $SRC is not configured on this machine"
        fi
        SSH_SRC="-b $SRC"
    else
        [ -e "/sys/class/net/$SRC" ] || die "source interface '$SRC' does not exist on this machine"
        ssh -G -B "$SRC" masshole.invalid >/dev/null 2>&1 || \
            die "this ssh client does not support -B (needs OpenSSH 8.9+); give a source address instead"
        SSH_SRC="-B $SRC"
    fi
}

# --------------------------------------------------------- network probe ----
# network_check HOST PORT ; sets NET_STATUS and NET_NOTE.
network_check() {
    host=$1; port=${2:-22}
    NET_STATUS=""; NET_NOTE=""
    printf '%sMaSSHole network probe%s  %s:%s%s  (no passwords sent)\n' "$C_B" "$C_0" \
        "$host" "$port" "${SRC:+  from $SRC}"
    BANNER=""; BANNER_FULL=""; PW_USERS=""; METHODS_SEEN=""
    for u in $(echo "$PROBE_USERS" | tr ',' ' '); do
        # shellcheck disable=SC2086
        out=$($TO_SHORT ssh -F /dev/null -v $SSH_SRC -p "$port" -l "$u" \
              -o BatchMode=yes -o PreferredAuthentications=none \
              -o PubkeyAuthentication=no -o PasswordAuthentication=no \
              -o KbdInteractiveAuthentication=no \
              -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
              -o GlobalKnownHostsFile=/dev/null -o ConnectTimeout="$TIMEOUT" \
              -- "$host" true </dev/null 2>&1)
        # ssh writes its debug/log lines with CRLF endings; strip the CRs
        out=$(printf '%s\n' "$out" | tr -d '\r')
        b=$(echo "$out" | sed -n 's/.*remote software version \([^ ,]*\).*/\1/p' | head -n1)
        full=$(echo "$out" | sed -n 's/.*Remote protocol version [0-9.]*, remote software version \(.*\)$/\1/p' | head -n1)
        [ -n "$b" ] && { BANNER=$b; BANNER_FULL=$full; }
        m=$(echo "$out" | sed -n 's/.*Authentications that can continue: \(.*\)$/\1/p' | head -n1)
        [ -z "$m" ] && m=$(echo "$out" | sed -n 's/.*Permission denied (\(.*\)).*/\1/p' | head -n1)
        if [ -z "$b" ] && [ -z "$m" ]; then
            reason=$(echo "$out" | grep -v '^debug' | tail -n 1)
            if echo "$out" | grep -qi 'bind'; then
                NET_STATUS=ERROR; NET_NOTE="cannot bind source: $reason"
            else
                NET_STATUS=NO_SSH; NET_NOTE=${reason:-no response}
            fi
            bad "No SSH response from $host:$port ($NET_NOTE)"
            return 3
        fi
        info "user '$u': methods offered = ${m:-unknown}"
        METHODS_SEEN="$METHODS_SEEN $u=${m:-?}"
        case ",$m," in *,password,*) PW_USERS="$PW_USERS $u" ;; esac
    done

    hdr "Assessment"
    sb=${BANNER_FULL:-$BANNER}
    info "Server banner: $sb"
    case "$sb" in
        *Debian*|*Ubuntu*|*Raspbian*)
            NET_STATUS=NOT_AFFECTED; NET_NOTE="$sb (glibc distro)"
            ok "Distribution suffix indicates a glibc system. Not affected."; return 0 ;;
        *FreeBSD*|*NetBSD*|*OpenBSD*)
            NET_STATUS=NOT_AFFECTED; NET_NOTE="$sb (non-Linux)"
            ok "Non-Linux system. Not affected."; return 0 ;;
        *dropbear*|*Dropbear*)
            NET_STATUS=NOT_AFFECTED; NET_NOTE="$sb"
            ok "Dropbear server. Not affected."; return 0 ;;
        OpenSSH_*) ;;
        *)  NET_STATUS=NOT_AFFECTED; NET_NOTE="${sb:-unknown} (not OpenSSH)"
            info "Not OpenSSH. Not affected by this issue."; return 0 ;;
    esac
    v=$(echo "$BANNER" | sed -n 's/.*OpenSSH_\([0-9][0-9]*\.[0-9][0-9]*\(p[0-9][0-9]*\)\{0,1\}\).*/\1/p')
    vs=""; [ -n "$v" ] && vs=$(ver_status "$v")
    if [ "$vs" = patched ]; then
        NET_STATUS=PATCHED; NET_NOTE="$sb"
        ok "OpenSSH $v >= $FIXED_UPSTREAM. Patched upstream."; return 0
    fi
    [ "$vs" = ambiguous ] && info "Banner $v omits the portable suffix: 10.6p1 (vulnerable) and 10.6p2 (fixed) look the same."
    if [ -z "$PW_USERS" ]; then
        NET_STATUS=NO_PASSWORD_AUTH; NET_NOTE="$sb;$METHODS_SEEN"
        ok "Password authentication not offered to probed users. Not exploitable as configured."
        return 0
    fi
    NET_STATUS=CANDIDATE; NET_NOTE="$sb; password offered to:$PW_USERS"
    warn "CANDIDATE: OpenSSH ${v:-?} with no distro suffix (consistent with Alpine/musl)"
    warn "and password auth offered for:$PW_USERS"
    info "Alpine backports keep the old upstream version string, so the banner cannot show"
    info "whether the fix is installed. Confirm with: $0 --remote -d $host"
    return 2
}

# ----------------------------------------------------------- remote run -----
# remote_check USER HOST PORT ; runs the local audit over SSH, sets NET_STATUS/NET_NOTE.
remote_check() {
    user=$1; host=$2; port=$3
    login=${user:-$LOGIN}
    dest=$host; [ -n "$login" ] && dest="$login@$host"
    remote_cmd="$ELEVATE sh -s -- --local $NOLOGS_ARG"
    set -- ssh -o BatchMode=yes -o ConnectTimeout="$TIMEOUT"
    # shellcheck disable=SC2086
    [ -n "$SSH_SRC" ] && set -- "$@" $SSH_SRC
    [ -n "$HOSTKEY_OPT" ] && set -- "$@" -o "$HOSTKEY_OPT"
    [ -n "$IDENTITY" ] && set -- "$@" -i "$IDENTITY" -o IdentitiesOnly=yes
    [ -n "$port" ] && set -- "$@" -p "$port"
    # shellcheck disable=SC2086
    report=$($TO_LONG "$@" -- "$dest" "$remote_cmd" < "$SELF" 2>&1)
    rc=$?
    report=$(printf '%s\n' "$report" | tr -d '\r')
    printf '%s\n' "$report"
    if ! echo "$report" | grep -q '== Verdict =='; then
        reason=$(echo "$report" | tail -n 1)
        case $rc in
            124|143) NET_STATUS=TIMEOUT ;;
            255)     NET_STATUS=UNREACHABLE ;;
            *)       NET_STATUS=ERROR ;;
        esac
        NET_NOTE="ssh/elevation failed: ${reason:-exit $rc}"
        return 3
    fi
    NET_NOTE=$(echo "$report" | sed -n '/== Verdict ==/,$p' | sed -n '2p' \
               | sed 's/\x1b\[[0-9;]*m//g; s/^ *\[.\] *//')
    case $rc in
        0) NET_STATUS=OK ;;
        1) NET_STATUS=VULNERABLE ;;
        2) NET_STATUS=AT_RISK ;;
        4) NET_STATUS=COMPROMISED ;;
        *) NET_STATUS=ERROR ;;
    esac
    return $rc
}

# -------------------------------------------------------------- runner ------
severity() {
    case "$1" in
        COMPROMISED) echo 5 ;; VULNERABLE) echo 4 ;;
        AT_RISK|CANDIDATE) echo 3 ;;
        OK|PATCHED|NOT_AFFECTED|NO_PASSWORD_AUTH) echo 1 ;;
        *) echo 0 ;;
    esac
}

# probe_target INDEX "user|host|port"  (runs in background; writes $WORK/INDEX.res)
probe_target() {
    idx=$1; spec=$2
    u=${spec%%|*}; rest=${spec#*|}; h=${rest%%|*}; p=${rest#*|}
    if [ "$MODE" = network ]; then
        network_check "$h" "${p:-22}"
    else
        remote_check "$u" "$h" "$p"
        if [ -n "$OUTDIR" ]; then
            safe=$(echo "${h}_${p:-22}" | tr -c 'A-Za-z0-9._\n-' '_')
            sed 's/\x1b\[[0-9;]*m//g' "$WORK/$idx.out" > "$OUTDIR/$safe.txt" 2>/dev/null
        fi
    fi
    note=$(printf '%s' "$NET_NOTE" | tr -d '\r' | tr '|\n\t' '/  ' | tr -d '\000-\037')
    printf '%s|%s|%s|%s\n' "$h" "${p:-22}" "${NET_STATUS:-ERROR}" "$note" > "$WORK/$idx.res"
}

run_targets() {
    WORK=$(mktemp -d 2>/dev/null || mktemp -d -t masshole) || die "cannot create temp dir"
    trap 'rm -rf "$WORK"' EXIT INT TERM
    printf '%s\n' "$DEST_SPECS" | expand_targets > "$WORK/targets"
    if grep -q '^ERR|' "$WORK/targets"; then
        grep '^ERR|' "$WORK/targets" | sed 's/^ERR|/error: /' >&2
        exit 3
    fi
    N=$(wc -l < "$WORK/targets" | tr -d ' ')
    [ "$N" -gt 0 ] || die "no destinations to check"

    if [ "$MODE" = remote ] && [ "$N" -gt 1 ] && [ -z "$OUTDIR" ]; then
        OUTDIR="masshole-reports-$(date '+%Y%m%d-%H%M%S')"
    fi
    [ -n "$OUTDIR" ] && { mkdir -p "$OUTDIR" || die "cannot create $OUTDIR"; }

    [ "$N" -gt 1 ] && printf '%sMaSSHole %s scan%s: %s target(s), %s parallel, timeout %ss%s\n' \
        "$C_B" "$MODE" "$C_0" "$N" "$JOBS" "$TIMEOUT" "${SRC:+, source $SRC}" >&2

    # launch in batches of $JOBS (portable: no wait -n in POSIX sh)
    i=0; running=0
    while IFS= read -r spec; do
        i=$((i + 1))
        probe_target "$i" "$spec" > "$WORK/$i.out" 2>&1 &
        running=$((running + 1))
        if [ "$running" -ge "$JOBS" ]; then
            wait; running=0
            [ -t 2 ] && [ "$N" -gt 1 ] && printf '\r  progress: %s/%s' "$i" "$N" >&2
        fi
    done < "$WORK/targets"
    wait
    [ -t 2 ] && [ "$N" -gt 1 ] && printf '\r  progress: %s/%s\n' "$N" "$N" >&2

    # collect
    [ -n "$CSV" ] && echo "host,port,mode,status,detail" > "$CSV"
    worst=0; counted=""
    if [ "$N" -eq 1 ] || [ "$VERBOSE" = yes ]; then
        j=0
        while [ "$j" -lt "$N" ]; do
            j=$((j + 1))
            [ "$N" -gt 1 ] && printf '\n%s---- %s ----%s\n' "$C_B" \
                "$(sed -n "${j}p" "$WORK/targets" | cut -d'|' -f2)" "$C_0"
            cat "$WORK/$j.out"
        done
    fi
    if [ "$N" -gt 1 ]; then
        printf '\n%s%-39s %-6s %-16s %s%s\n' "$C_B" "HOST" "PORT" "STATUS" "DETAIL" "$C_0"
    fi
    j=0
    while [ "$j" -lt "$N" ]; do
        j=$((j + 1))
        res=$(cat "$WORK/$j.res" 2>/dev/null)
        [ -z "$res" ] && res="$(sed -n "${j}p" "$WORK/targets" | cut -d'|' -f2)|?|ERROR|probe did not complete"
        h=${res%%|*}; r=${res#*|}; p=${r%%|*}; r=${r#*|}; st=${r%%|*}; note=${r#*|}
        if [ "$N" -gt 1 ]; then
            case "$st" in
                COMPROMISED|VULNERABLE) col=$C_R ;;
                AT_RISK|CANDIDATE|ERROR|TIMEOUT) col=$C_Y ;;
                NO_SSH|UNREACHABLE) col="" ;;
                *) col=$C_G ;;
            esac
            printf '%-39s %-6s %s%-16s%s %s\n' "$h" "$p" "$col" "$st" "$C_0" "$note"
        fi
        [ -n "$CSV" ] && printf '"%s",%s,%s,%s,"%s"\n' "$h" "$p" "$MODE" "$st" \
            "$(printf '%s' "$note" | sed 's/"/""/g')" >> "$CSV"
        counted="$counted $st"
        s=$(severity "$st")
        [ "$s" -gt "$worst" ] && worst=$s
    done

    if [ "$N" -gt 1 ]; then
        printf '\n%sSummary:%s' "$C_B" "$C_0"
        for st in COMPROMISED VULNERABLE AT_RISK CANDIDATE OK PATCHED NOT_AFFECTED \
                  NO_PASSWORD_AUTH NO_SSH UNREACHABLE TIMEOUT ERROR; do
            c=$(printf '%s\n' $counted | grep -cx "$st")
            [ "$c" -gt 0 ] && printf ' %s=%s' "$st" "$c"
        done
        printf '\n'
    fi
    [ -n "$OUTDIR" ] && info "Full per-host reports: $OUTDIR/"
    [ -n "$CSV" ] && info "CSV written: $CSV"

    case "$worst" in
        5) return 4 ;; 4) return 1 ;; 3) return 2 ;; 1) return 0 ;;
        *) return 3 ;;   # nothing answered
    esac
}

# -------------------------------------------------------------- main --------
SELF=$0
MODE=""; DEST_SPECS=""; SRC=""; PORT=""; LOGIN=""
PROBE_USERS="root,alpine"; ELEVATE=""; LOGS=yes; NOLOGS_ARG=""
IDENTITY=""; JOBS=10; TIMEOUT=5; MAX_HOSTS=4096; CSV=""; OUTDIR=""; VERBOSE=no; HOSTKEY_OPT=""

need_arg() { [ $# -ge 2 ] && [ -n "$2" ] || die "$1 needs a value"; }
add_dest() { DEST_SPECS="${DEST_SPECS:+$DEST_SPECS
}$1"; }
is_num()   { case "$2" in ''|*[!0-9]*) die "$1 must be a number" ;; esac; }

while [ $# -gt 0 ]; do
    case "$1" in
        --local)   MODE=local ;;
        --network|--remote)
                   MODE=${1#--}
                   # backwards compatible: "--network HOST" / "--remote HOST"
                   case "${2:-}" in ''|-*) ;; *) add_dest "$2"; shift ;; esac ;;
        -d|--dest|--destination)
                   need_arg "$@"; add_dest "$2"; shift ;;
        -f|--dest-file)
                   need_arg "$@"; [ -r "$2" ] || die "cannot read $2"
                   add_dest "$(cat "$2")"; shift ;;
        -s|--source) need_arg "$@"; SRC=$2; shift ;;
        -p|--port)   need_arg "$@"; is_num "$1" "$2"; PORT=$2; shift ;;
        -l|--login)  need_arg "$@"; LOGIN=$2; shift ;;
        -i|--identity) need_arg "$@"; [ -r "$2" ] || die "cannot read key $2"; IDENTITY=$2; shift ;;
        --user)      need_arg "$@"; PROBE_USERS=$2; shift ;;
        -j|--jobs)   need_arg "$@"; is_num "$1" "$2"; JOBS=$2; shift ;;
        -t|--timeout) need_arg "$@"; is_num "$1" "$2"; TIMEOUT=$2; shift ;;
        --max-hosts) need_arg "$@"; is_num "$1" "$2"; MAX_HOSTS=$2; shift ;;
        --csv)       need_arg "$@"; CSV=$2; shift ;;
        --outdir)    need_arg "$@"; OUTDIR=$2; shift ;;
        --accept-new-hostkeys) HOSTKEY_OPT="StrictHostKeyChecking=accept-new" ;;
        --elevate)   need_arg "$@"
                     case "$2" in sudo) ELEVATE="sudo -n" ;; doas) ELEVATE="doas -n" ;;
                         *) die "--elevate must be sudo or doas" ;; esac; shift ;;
        -v|--verbose) VERBOSE=yes ;;
        --no-logs)   LOGS=no; NOLOGS_ARG="--no-logs" ;;
        -h|--help)   usage; exit 0 ;;
        *) printf 'unknown option: %s\n\n' "$1" >&2; usage >&2; exit 3 ;;
    esac
    shift
done

[ "$JOBS" -ge 1 ] || JOBS=1

case "$MODE" in
    local)
        [ -n "$DEST_SPECS" ] && die "--local audits this machine; use --remote -d ... for other hosts"
        [ -n "$SRC" ] && warn "--source is ignored in --local mode"
        local_check "$LOGS"; exit $? ;;
    network|remote)
        [ -n "$DEST_SPECS" ] || die "--$MODE needs a destination: -d TARGETS or -f FILE"
        command -v ssh >/dev/null 2>&1 || die "an ssh client is required for --$MODE"
        TO_SHORT=""; TO_LONG=""
        if command -v timeout >/dev/null 2>&1 && timeout 5 true 2>/dev/null; then
            TO_SHORT="timeout $((TIMEOUT * 3 + 5))"
            TO_LONG="timeout 900"
        fi
        setup_source
        run_targets; exit $? ;;
    *)  usage; exit 3 ;;
esac
