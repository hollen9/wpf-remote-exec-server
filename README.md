# wpf-remote-exec-server
Lightweight WPF HTTP command server for Windows XP / .NET Framework 4.0.3.
Remotely execute predefined batch or executable files with password protection,
custom timeouts, per-command visibility settings, and daily logging.

## ⚠ SECURITY NOTICE

Stores passwords in plain text and uses unencrypted HTTP.
Only recommended for trusted, closed networks and non-sensitive automation
(e.g., restarting remote desktop service).

## Features

- Windows XP & .NET 4.0 compatible
- Password-protected HTTP API
- Local subnet restriction (/24)
- Global & per-command timeouts
- "No Response" mode for interactive scripts
- Optional hidden execution
- Auto-start with command-line args (--autostart, --minimized)
- Daily log files in .log/YYYY-MM-DD.log



## Example Usage

- Curl
  `curl -X POST -d "pwd=MySecret&cmd=akemihomura" http://192.168.1.23:4567/run`
- Powershell
  `Invoke-WebRequest -Uri "http://192.168.1.23:456/run" -Method POST -Body "pwd=MySecret&cmd=avemujica" -ContentType "application/x-www-form-urlencoded"`

