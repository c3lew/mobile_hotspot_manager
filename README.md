# Mobile Hotspot Manager

This repository contains a PowerShell script (`mobile-hotspot-manager.ps1`) and a convenience batch file (`run-hotspot-manager.bat`) for managing the Windows mobile hotspot feature.

## Features

- Enable, disable or toggle the Windows mobile hotspot
- Display current hotspot status
- Retrieve saved Wi‑Fi profiles and passwords
- Obtain the current mobile hotspot SSID and password
- Show the hotspot credentials directly without listing other Wi‑Fi profiles

The PowerShell script uses Windows Runtime APIs when possible and falls back to parsing `netsh` output if those APIs are unavailable. All operations are logged to a file named `MobileHotspot_<date>.log` in the script directory. Wi‑Fi credentials retrieved via the `GetWiFi` action are also exported to a timestamped CSV file.

## Usage

Run the PowerShell script with the desired action:

```powershell
# Enable the hotspot
./mobile-hotspot-manager.ps1 -Action Enable

# Retrieve all Wi‑Fi credentials (including hotspot)
./mobile-hotspot-manager.ps1 -Action GetWiFi

# Show just the current hotspot name and password
./mobile-hotspot-manager.ps1 -Action GetHotspot
```

**Note:** Enabling or disabling the hotspot requires administrative privileges.
Run PowerShell or the provided batch file as *Administrator* for these
operations to succeed.

You can also run `run-hotspot-manager.bat` for an interactive menu.

## Troubleshooting

If you run the script with administrative privileges and receive an error such as:

```
Failed to get tethering manager: Element not found. (Exception from HRESULT: 0x80070490)
```

The current network adapter may not support mobile hotspot, or there might not be an active
internet connection profile. Ensure you are connected to the internet and, if possible,
try connecting via Wi‑Fi before running the script. Some devices do not expose the
Windows Runtime tethering APIs and therefore cannot be managed by this tool.
