# Mobile Hotspot Manager

This repository contains a PowerShell script (`mobile-hotspot-manager.ps1`) and a convenience batch file (`run-hotspot-manager.bat`) for managing the Windows mobile hotspot feature.

## Features

- Enable, disable or toggle the Windows mobile hotspot
- Display current hotspot status
- Retrieve saved Wi‑Fi profiles and passwords
- Obtain the current mobile hotspot SSID and password

The PowerShell script uses Windows Runtime APIs when possible and falls back to parsing `netsh` output if those APIs are unavailable. All operations are logged to a file named `MobileHotspot_<date>.log` in the script directory. Wi‑Fi credentials retrieved via the `GetWiFi` action are also exported to a timestamped CSV file.

## Usage

Run the PowerShell script with the desired action:

```powershell
# Enable the hotspot
./mobile-hotspot-manager.ps1 -Action Enable

# Retrieve all Wi‑Fi credentials (including hotspot)
./mobile-hotspot-manager.ps1 -Action GetWiFi
```

You can also run `run-hotspot-manager.bat` for an interactive menu.
