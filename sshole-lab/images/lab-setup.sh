#!/bin/sh
# Build-time setup shared by the Alpine lab images.
# Creates the accounts the *sshole conditions depend on and installs the lab key.
#
#   root    shadow "*"  (as in the Alpine base image)       key login allowed
#   alpine  shadow "*"  (as in Alpine cloud images)         key login + doas nopass
#   bob     SHA-512 password hash (the "real hash" precondition)
#
# LAB ONLY: never run this on a real system.
set -eu

PUBKEY=/tmp/lab_ed25519.pub
[ -r "$PUBKEY" ] || { echo "missing $PUBKEY (run: ssh-keygen -t ed25519 -N '' -f keys/lab_ed25519)" >&2; exit 1; }

apk add --no-cache doas >/dev/null

adduser -D -s /bin/sh alpine
adduser -D -s /bin/sh bob
echo 'bob:LabOnly-NotARealPassw0rd' | chpasswd -c sha512

# "*" = no password (key-only). Busybox adduser -D writes "!" (locked), which
# sshd would refuse even for key logins, so set "*" explicitly.
sed -i -e 's/^root:[^:]*:/root:*:/' -e 's/^alpine:[^:]*:/alpine:*:/' /etc/shadow

for d in /root /home/alpine; do
    mkdir -p "$d/.ssh"
    cp "$PUBKEY" "$d/.ssh/authorized_keys"
    chmod 700 "$d/.ssh"; chmod 600 "$d/.ssh/authorized_keys"
done
chown -R alpine:alpine /home/alpine/.ssh

# Passwordless doas for the alpine user, like the official cloud images
mkdir -p /etc/doas.d
echo 'permit nopass alpine as root' > /etc/doas.d/lab.conf
echo 'permit nopass alpine as root' >> /etc/doas.conf     # covers either config location
chmod 0400 /etc/doas.d/lab.conf /etc/doas.conf

# Put lab settings at the top of sshd_config (first value wins in sshd).
mkdir -p /etc/ssh
cfg=/etc/ssh/sshd_config
[ -f "$cfg" ] || : > "$cfg"
{
    echo "# --- sshole lab (entrypoint may rewrite these) ---"
    echo "PasswordAuthentication yes"
    [ "${LAB_USE_PAM:-no}" = yes ] && echo "UsePAM yes"
    echo "# ------------------------------------------------"
    cat "$cfg"
} > "$cfg.new" && mv "$cfg.new" "$cfg"

rm -f "$PUBKEY"
