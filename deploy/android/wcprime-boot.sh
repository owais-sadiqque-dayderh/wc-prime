#!/data/data/com.termux/files/usr/bin/sh
# Termux:Boot invokes this script. Install the static binary at the path below.
# Root keeps binary and config independent of the Termux app's uid and storage.
su -c 'mkdir -p /data/local/tmp/wc-prime; chmod 700 /data/local/tmp/wc-prime; if [ -f /data/local/tmp/wc-prime/wcprime.pid ] && kill -0 "$(cat /data/local/tmp/wc-prime/wcprime.pid)" 2>/dev/null; then exit 0; fi; nohup /data/local/tmp/wcprime run -dir /data/local/tmp/wc-prime </dev/null >>/data/local/tmp/wc-prime/wcprime.log 2>&1 & echo $! >/data/local/tmp/wc-prime/wcprime.pid'
