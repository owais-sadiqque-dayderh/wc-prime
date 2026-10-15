# Windows logon task

In PowerShell, run `./install.ps1 -Source C:\path\to\wcprime.exe` as the
user who will run the service. The task uses that user's interactive session
at logon, stores the binary in `%LOCALAPPDATA%\wc-prime\`, and starts it now.
The installer prints the authenticated local UI URL. The Windows build uses
the GUI subsystem to avoid a console window; the task is also hidden in Task
Scheduler's default view. `./uninstall.ps1` removes the current user's task
and binary, retaining saved configuration. Task names contain the user's SID
so installations for different users do not overwrite each other.
