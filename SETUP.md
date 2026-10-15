# Set up wc-prime

wc-prime is a small background Wi-Fi service with a local management page. The service does not run a browser engine. Open the page in your usual browser to manage saved networks, priorities, and portal logins.

## Quick start on your Mac

You need Go 1.22 or newer to build; the compiled binary runs without Go installed. From your existing project checkout:

```sh
cd /Users/owaissadiqque/.t3/projects/wc-prime
git pull --ff-only
mkdir -p dist
go build -trimpath -ldflags '-s -w' -o dist/wcprime ./cmd/wcprime
./dist/wcprime version
./dist/wcprime check
```

`check` reads the current Wi-Fi state and tests internet connectivity. It does not switch networks.

Start the service in the foreground first:

```sh
./dist/wcprime run
```

Keep that terminal running. In a second terminal, in the same project:

```sh
./dist/wcprime url
```

Open the exact URL it prints, including `#t=...`. The bare `http://127.0.0.1:7878` page cannot authenticate you by itself. Treat the URL like a password. Press **Ctrl+C** in the first terminal to stop the service.

`run` manages real Wi-Fi: it may enable the radio, reconnect to a saved network, or submit a saved portal login. Test it when you can tolerate a brief connection interruption. No service is installed by the build command.

For a separate trial vault, use the same directory on both commands:

```sh
./dist/wcprime run -dir "$HOME/.wc-prime-trial"
# In another terminal:
./dist/wcprime url -dir "$HOME/.wc-prime-trial"
```

If port 7878 is already occupied, use `-listen 127.0.0.1:7879` on both commands. Stop any earlier instance before starting another against the same vault.

## Use the interface

1. **Add network:** enter the exact SSID, security type, and credentials. Scan can fill in the SSID and suggest the security type.
2. **Set priority:** use the up/down buttons. The top enabled saved network is preferred when recovering a broken connection.
3. **Watch Connection:** the page shows online, captive portal, no internet, poor, disconnected, or recovering, plus recent actions.
4. **Disable an entry:** it is excluded from automatic connections and portal credential submission.

### Router or home Wi-Fi

Choose WPA2-Personal or WPA3-Personal and enter the passphrase. Choose Open only for a network that has no Wi-Fi passphrase. Hidden networks need their exact SSID and the Hidden checkbox.

### Institute, hotel, or campus portal

Keep the correct Wi-Fi security type and check **This network has a captive login page**. Enter the portal username/password and establish the trusted login destination using either:

- **Login URL** under Captive portal advanced, for example `https://login.example.edu/`. Its exact origin is trusted automatically.
- **Trusted login hosts**, for discovery-based portals. Prefer an exact HTTPS origin such as `https://login.example.edu`. Add another destination only when your institution confirms that it handles the login.

For a JavaScript-generated form, set the fixed login endpoint, username/password field names, and required extra fields. The service parses normal HTML forms, cookies, hidden tokens, and limited redirects; it does not execute arbitrary JavaScript or solve CAPTCHA/MFA.

A bare hostname permits HTTP or HTTPS and any port; a wildcard trusts every subdomain. Exact HTTPS origins are narrower. Keep certificate verification enabled unless you have deliberately chosen otherwise for a controlled portal. A configured HTTPS origin prevents credential submission to HTTP or an unapproved origin.

### WPA-Enterprise / 802.1X

Choose Enterprise, enter the username/password, and provide the **RADIUS server domain** from your IT team. This is the server certificate name, not necessarily the SSID or your email domain. Advanced options expose EAP, phase-2, anonymous identity, and a CA certificate path.

Linux supports PEAP/TTLS through NetworkManager; Windows supports PEAP-MSCHAPv2 here. Windows custom CAs must already be trusted by Windows; the file identifies which root to accept rather than installing it. macOS requires the institution's configuration profile. Android enterprise reconnection is not implemented by this backend.

On edit, a blank password or passphrase retains the existing saved secret. The API omits those secret values. Extra portal fields are editable/readable metadata; do not assume arbitrary tokens in that field are write-only.

## What the automation does

While online it checks every 15 seconds, using ordinary HTTP connectivity endpoints. During recovery it checks every 5 seconds. It confirms repeated poor/no-internet results before switching, connects only to enabled saved networks, and verifies that the replacement has internet. Poor-link switching considers only sufficiently stronger alternatives and attempts to restore the previous saved working network if all replacements fail.

On macOS, the status commands may return an empty SSID and unknown signal because the OS hides them. This happened during review on the development Mac. Internet detection still worked, but portal lookup by current SSID and signal-based recovery cannot be assumed to work in that state. Verify them on the actual target device; building successfully is not hardware validation.

## Run automatically at login

Do this after the foreground trial works for your network. Stop the foreground instance first.

### macOS

Follow [the macOS guide](deploy/macos/README.md). Install the native binary as `/usr/local/bin/wcprime`. Create `~/Library/LaunchAgents` and `~/Library/Logs`. Replace both `/Users/YOUR_USERNAME` placeholders in `deploy/macos/com.wcprime.agent.plist` with your absolute home path and copy it to `~/Library/LaunchAgents/com.wcprime.agent.plist`.

```sh
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.wcprime.agent.plist"
/usr/local/bin/wcprime url
```

Logs: `~/Library/Logs/wcprime.log`. It starts when your user logs in, not before login. To stop it:

```sh
launchctl bootout "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.wcprime.agent.plist"
```

### Linux

Requires NetworkManager (`nmcli`) and polkit permission to manage Wi-Fi as your logged-in user. Build a native binary and use [the Linux guide](deploy/linux/README.md):

```sh
mkdir -p "$HOME/.local/bin" "$HOME/.config/systemd/user"
cp dist/wcprime "$HOME/.local/bin/wcprime"
cp deploy/linux/wcprime.service "$HOME/.config/systemd/user/"
systemctl --user daemon-reload
systemctl --user enable --now wcprime
"$HOME/.local/bin/wcprime" url
journalctl --user -u wcprime -f
```

Stop with `systemctl --user disable --now wcprime`. A user service normally stops at logout.

### Windows

Build with `go build -trimpath -ldflags "-s -w" -o dist/wcprime.exe ./cmd/wcprime`, or use the matching cross-built executable from `dist/`. In PowerShell:

```powershell
.\deploy\windows\install.ps1 -Source C:\path\to\wcprime.exe
```

The installer creates a user logon Scheduled Task, starts it, and prints the UI link. The cross-built GUI-subsystem executable may need stdout redirection for CLI output; the installer handles that. See [the Windows guide](deploy/windows/README.md). Use `deploy/windows/uninstall.ps1` to remove the task and installed binary.

### Android

This is not a conventional Android app. It needs root or ADB-shell privileges, and Android/OEM power policies can stop it. Follow [the Android guide](deploy/android/README.md) for ADB or Termux:Boot. The Android backend cannot provision or reconnect Enterprise entries; adding one in Settings does not implement that missing Connect path.

## Storage and resource use

Defaults: Linux `~/.config/wc-prime`, macOS `~/Library/Application Support/wc-prime`, Windows `%APPDATA%\wc-prime`. `-dir` overrides the path. Preserve both `vault.bin` and `vault.key` if backing up; protect the key and `ui.token`. On Windows, the key is DPAPI-wrapped for the user account. On other systems it is protected by local file permissions. This does not protect against malware running as the same user, or someone obtaining both the vault and its usable key.

There are no third-party Go module dependencies. The eight target binaries built during review were approximately 7.3–8.3 MB. The 24 MiB Go runtime setting is a soft memory target, not a process RSS guarantee. Child tools such as `system_profiler` also consume resources. Measure idle and recovery CPU/RAM on your target device.

## Verify your real network

Try one network first, then add a controlled backup. Check a portal expiry, a disconnection, a weak link, and a strong backup with no internet; verify recovery/restoration and watch Recent events. Do not judge captive login from a successful connectivity probe alone. Unit tests and cross-compilation passed during review; real Windows, Android, and captive-portal hardware remain unverified.
