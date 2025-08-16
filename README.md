# Hollen's Remote Exec Server
Lightweight WPF HTTP command server for Windows XP / .NET Framework 4.0.3.
Remotely execute predefined batch or executable files with password protection,
custom timeouts, per-command visibility settings, and daily logging.
![exe Screenshot](https://hollen9.github.io/wpf-remote-exec-server/img/wpf-remoteexec_250817015230.png)

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
- Web Browser GET: `http://192.168.1.23:4567/list`
- Curl
  `curl -X POST -d "pwd=MySecret&cmd=akemihomura" http://192.168.1.23:4567/run`
- Powershell
  `Invoke-WebRequest -Uri "http://192.168.1.23:4567/run" -Method POST -Body "pwd=MySecret&cmd=avemujica" -ContentType "application/x-www-form-urlencoded"`

