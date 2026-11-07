#!/bin/sh
# Runtime entrypoint for the lab targets.
#   PASSWORD_AUTH=yes|no   rewrite PasswordAuthentication
#   SEED_IOC=yes           write a fake "Accepted password for alpine" line to
#                          /var/log/messages so the log check has something to find
set -eu
cfg=/etc/ssh/sshd_config

if [ -n "${PASSWORD_AUTH:-}" ]; then
    sed -i "s/^PasswordAuthentication .*/PasswordAuthentication ${PASSWORD_AUTH}/" "$cfg"
fi

ssh-keygen -A >/dev/null

mkdir -p /var/log /run/sshd
if command -v syslogd >/dev/null 2>&1; then
    syslogd -O /var/log/messages          # busybox: sshd auth logs go here
fi

if [ "${SEED_IOC:-no}" = yes ]; then
    # Simulated indicator of compromise (lab data, from a documentation address).
    printf '%s lab sshd[4242]: Accepted password for alpine from 198.51.100.66 port 51515 ssh2\n' \
        "$(date '+%b %e %H:%M:%S')" >> /var/log/messages
fi

SSHD=/usr/sbin/sshd
[ -x /usr/sbin/sshd.pam ] && [ ! -x /usr/sbin/sshd ] && SSHD=/usr/sbin/sshd.pam
[ -x /usr/sbin/sshd.pam ] && grep -q '^UsePAM yes' "$cfg" && SSHD=/usr/sbin/sshd.pam

if command -v syslogd >/dev/null 2>&1; then
    exec "$SSHD" -D
else
    exec "$SSHD" -D -e
fi
