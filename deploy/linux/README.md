# Linux user service

Install `wcprime` at `~/.local/bin/wcprime` and copy `wcprime.service` to
`~/.config/systemd/user/` (create that directory first). Run as the logged-in
user so NetworkManager can authorize `nmcli` through polkit:

```sh
systemctl --user daemon-reload
systemctl --user enable --now wcprime
~/.local/bin/wcprime url
journalctl --user -u wcprime -f
```

NetworkManager and `nmcli` must be installed. The service uses the default
user config directory and listens on `127.0.0.1:7878`. Memory is throttled at
32 MiB with a 64 MiB hard limit; CPU is capped at 10% of one core. Local polkit
policy must allow the user to manage Wi-Fi. A user service normally stops at
logout. To remove it, run `systemctl --user disable --now wcprime`, delete the
unit, and run `systemctl --user daemon-reload`. Saved configuration is retained.
