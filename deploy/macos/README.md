# macOS LaunchAgent

Install the matching binary as `/usr/local/bin/wcprime` and make it executable.
Replace **both** `/Users/YOUR_USERNAME` placeholders in
`com.wcprime.agent.plist` with your absolute home path. Launchd does not expand
`~` or environment variables in plist paths. Create `~/Library/Logs` and
`~/Library/LaunchAgents`, then copy the edited plist to
`~/Library/LaunchAgents/com.wcprime.agent.plist`.

```sh
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.wcprime.agent.plist"
/usr/local/bin/wcprime url
```

The agent runs at login as your user and logs to `~/Library/Logs/wcprime.log`.
Grant any macOS permissions requested for Wi-Fi access. macOS may redact the
network name; enterprise networks need a configuration profile installed once.
To uninstall, run:

```sh
launchctl bootout "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.wcprime.agent.plist"
rm "$HOME/Library/LaunchAgents/com.wcprime.agent.plist"
```

Saved configuration is retained in the default user config directory.
