# Android (Android 11+)

`cmd wifi` requires the **shell or root uid**. Ordinary Android app processes,
including non-root Termux sessions, cannot control Wi-Fi. Enterprise networks
must be added once in Android Settings; this backend cannot provision their
802.1X credentials. OEM restrictions and Android background power policies may
also limit behavior. A boot script starts the process; it is not a supervisor.

## Rooted device with Termux:Boot

Install Termux and Termux:Boot from the same distribution source, open both at
least once, and grant Termux root access. Copy the Android arm64 binary to
`/data/local/tmp/wcprime`, then `su -c 'chmod 755 /data/local/tmp/wcprime'`.
Place `wcprime-boot.sh` in `~/.termux/boot/` and make it executable. Run it once
to start immediately. Termux:Boot will invoke it at subsequent boots, and
`su -c` starts the service as root. Config and logs live in
`/data/local/tmp/wc-prime/` with permissions restricted to the owner.

```sh
su -c '/data/local/tmp/wcprime url -dir /data/local/tmp/wc-prime'
```

Open the printed URL on the device. The UI binds only to `127.0.0.1:7878`.
To stop, use the PID in `/data/local/tmp/wc-prime/wcprime.pid`; remove the boot
script to disable boot startup. A Termux wake lock and battery optimization
exemption can help on devices that otherwise suspend background work.

## ADB alternative (no root required)

```sh
adb push dist/wcprime-android-arm64 /data/local/tmp/wcprime
adb shell chmod 755 /data/local/tmp/wcprime
adb shell 'mkdir -p /data/local/tmp/wc-prime; chmod 700 /data/local/tmp/wc-prime; nohup /data/local/tmp/wcprime run -dir /data/local/tmp/wc-prime </dev/null >/data/local/tmp/wc-prime/wcprime.log 2>&1 &'
adb shell /data/local/tmp/wcprime url -dir /data/local/tmp/wc-prime
adb forward tcp:7878 tcp:7878
```

Open the printed URL on the host after forwarding. This process runs as the
ADB shell uid, which is allowed to invoke `cmd wifi`; it does not survive a
reboot and may be killed by device policy. Keep one instance running at a time.
