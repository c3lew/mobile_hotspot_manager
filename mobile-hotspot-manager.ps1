# ==============================================================================
# Mobile Hotspot Management Script for Windows 10/11
# ==============================================================================
# Description: User-friendly PowerShell script to enable/disable mobile hotspot
#              and retrieve WiFi credentials automatically with logging
# Author: PowerShell Script Assistant
# Version: 1.0
# Requirements: Windows 10/11, PowerShell 5.0 or higher, Administrator privileges
# ==============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Enable", "Disable", "Status", "Toggle", "GetWiFi", "Help")]
    [string]$Action = "Help",
    
    [Parameter(Mandatory=$false)]
    [switch]$Quiet = $false
)

# Global variables
$Script:LogFile = "$PSScriptRoot\MobileHotspot_$(Get-Date -Format 'yyyy-MM-dd').log"
$Script:ErrorCount = 0

# ==============================================================================
# LOGGING FUNCTIONS
# ==============================================================================

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$Timestamp [$Level] $Message"
    
    # Write to console if not in quiet mode
    if (-not $Quiet) {
        switch ($Level) {
            "INFO"    { Write-Host $LogEntry -ForegroundColor Cyan }
            "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
            "WARNING" { Write-Host $LogEntry -ForegroundColor Yellow }
            "ERROR"   { Write-Host $LogEntry -ForegroundColor Red }
        }
    }
    
    # Write to log file
    try {
        $LogEntry | Out-File -FilePath $Script:LogFile -Append -Encoding UTF8
    }
    catch {
        Write-Warning "Failed to write to log file: $_"
    }
}

function Start-LogSession {
    $separator = "=" * 80
    Write-Log -Message $separator -Level "INFO"
    Write-Log -Message "Mobile Hotspot Manager Script Started" -Level "INFO"
    Write-Log -Message "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level "INFO"
    Write-Log -Message "User: $env:USERNAME" -Level "INFO"
    Write-Log -Message "Computer: $env:COMPUTERNAME" -Level "INFO"
    Write-Log -Message "Action: $Action" -Level "INFO"
    Write-Log -Message $separator -Level "INFO"
}

function Stop-LogSession {
    $separator = "=" * 80
    Write-Log -Message $separator -Level "INFO"
    Write-Log -Message "Script completed with $Script:ErrorCount error(s)" -Level "INFO"
    Write-Log -Message "Log file location: $Script:LogFile" -Level "INFO"
    Write-Log -Message $separator -Level "INFO"
}

# ==============================================================================
# HOTSPOT MANAGEMENT FUNCTIONS
# ==============================================================================

function Initialize-HotspotManager {
    try {
        Write-Log -Message "Initializing Windows Runtime components..." -Level "INFO"
        
        # Load Windows Runtime
        Add-Type -AssemblyName System.Runtime.WindowsRuntime
        
        # Get async task support
        $Script:asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | 
            Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and 
                          $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
        
        Write-Log -Message "Windows Runtime components loaded successfully" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log -Message "Failed to initialize Windows Runtime: $($_.Exception.Message)" -Level "ERROR"
        $Script:ErrorCount++
        return $false
    }
}

function Wait-AsyncOperation {
    param(
        [Parameter(Mandatory=$true)]
        $WinRtTask,
        
        [Parameter(Mandatory=$true)]
        [Type]$ResultType
    )
    
    try {
        $asTask = $Script:asTaskGeneric.MakeGenericMethod($ResultType)
        $netTask = $asTask.Invoke($null, @($WinRtTask))
        $netTask.Wait(-1) | Out-Null
        return $netTask.Result
    }
    catch {
        Write-Log -Message "Async operation failed: $($_.Exception.Message)" -Level "ERROR"
        $Script:ErrorCount++
        throw
    }
}

function Get-TetheringManager {
    try {
        Write-Log -Message "Getting tethering manager..." -Level "INFO"
        
        $connectionProfile = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile()
        
        if ($null -eq $connectionProfile) {
            Write-Log -Message "No internet connection profile found. Make sure you have an active internet connection." -Level "ERROR"
            $Script:ErrorCount++
            return $null
        }
        
        $tetheringManager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]::CreateFromConnectionProfile($connectionProfile)
        
        Write-Log -Message "Tethering manager obtained successfully" -Level "SUCCESS"
        return $tetheringManager
    }
    catch {
        Write-Log -Message "Failed to get tethering manager: $($_.Exception.Message)" -Level "ERROR"
        $Script:ErrorCount++
        return $null
    }
}

function Get-HotspotStatus {
    try {
        $tetheringManager = Get-TetheringManager
        if ($null -eq $tetheringManager) {
            return "Unknown"
        }
        
        $state = $tetheringManager.TetheringOperationalState
        Write-Log -Message "Current hotspot status: $state" -Level "INFO"
        
        return $state
    }
    catch {
        Write-Log -Message "Failed to get hotspot status: $($_.Exception.Message)" -Level "ERROR"
        $Script:ErrorCount++
        return "Error"
    }
}

function Enable-MobileHotspot {
    try {
        Write-Log -Message "Attempting to enable mobile hotspot..." -Level "INFO"
        
        $tetheringManager = Get-TetheringManager
        if ($null -eq $tetheringManager) {
            return $false
        }
        
        $currentState = $tetheringManager.TetheringOperationalState
        
        if ($currentState -eq "On") {
            Write-Log -Message "Mobile hotspot is already enabled" -Level "INFO"
            return $true
        }
        
        Write-Log -Message "Starting mobile hotspot..." -Level "INFO"
        $result = Wait-AsyncOperation -WinRtTask $tetheringManager.StartTetheringAsync() -ResultType ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])
        
        if ($result.Status -eq "Success") {
            Write-Log -Message "Mobile hotspot enabled successfully" -Level "SUCCESS"
            return $true
        }
        else {
            Write-Log -Message "Failed to enable mobile hotspot. Status: $($result.Status)" -Level "ERROR"
            $Script:ErrorCount++
            return $false
        }
    }
    catch {
        Write-Log -Message "Error enabling mobile hotspot: $($_.Exception.Message)" -Level "ERROR"
        $Script:ErrorCount++
        return $false
    }
}

function Disable-MobileHotspot {
    try {
        Write-Log -Message "Attempting to disable mobile hotspot..." -Level "INFO"
        
        $tetheringManager = Get-TetheringManager
        if ($null -eq $tetheringManager) {
            return $false
        }
        
        $currentState = $tetheringManager.TetheringOperationalState
        
        if ($currentState -eq "Off") {
            Write-Log -Message "Mobile hotspot is already disabled" -Level "INFO"
            return $true
        }
        
        Write-Log -Message "Stopping mobile hotspot..." -Level "INFO"
        $result = Wait-AsyncOperation -WinRtTask $tetheringManager.StopTetheringAsync() -ResultType ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])
        
        if ($result.Status -eq "Success") {
            Write-Log -Message "Mobile hotspot disabled successfully" -Level "SUCCESS"
            return $true
        }
        else {
            Write-Log -Message "Failed to disable mobile hotspot. Status: $($result.Status)" -Level "ERROR"
            $Script:ErrorCount++
            return $false
        }
    }
    catch {
        Write-Log -Message "Error disabling mobile hotspot: $($_.Exception.Message)" -Level "ERROR"
        $Script:ErrorCount++
        return $false
    }
}

function Toggle-MobileHotspot {
    try {
        $currentStatus = Get-HotspotStatus
        
        if ($currentStatus -eq "On") {
            Write-Log -Message "Hotspot is ON, toggling to OFF..." -Level "INFO"
            return Disable-MobileHotspot
        }
        elseif ($currentStatus -eq "Off") {
            Write-Log -Message "Hotspot is OFF, toggling to ON..." -Level "INFO"
            return Enable-MobileHotspot
        }
        else {
            Write-Log -Message "Cannot toggle hotspot. Current state: $currentStatus" -Level "ERROR"
            $Script:ErrorCount++
            return $false
        }
    }
    catch {
        Write-Log -Message "Error toggling mobile hotspot: $($_.Exception.Message)" -Level "ERROR"
        $Script:ErrorCount++
        return $false
    }
}

# ==============================================================================
# WIFI CREDENTIAL FUNCTIONS
# ==============================================================================

function Get-WiFiProfiles {
    try {
        Write-Log -Message "Retrieving WiFi profiles..." -Level "INFO"
        
        $profilesOutput = netsh wlan show profiles
        $profiles = @()
        
        foreach ($line in $profilesOutput) {
            if ($line -match "All User Profile\s*:\s*(.+)") {
                $profileName = $matches[1].Trim()
                $profiles += $profileName
            }
        }
        
        Write-Log -Message "Found $($profiles.Count) WiFi profiles" -Level "INFO"
        return $profiles
    }
    catch {
        Write-Log -Message "Failed to get WiFi profiles: $($_.Exception.Message)" -Level "ERROR"
        $Script:ErrorCount++
        return @()
    }
}

function Get-WiFiPassword {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ProfileName
    )
    
    try {
        $profileOutput = netsh wlan show profile name="$ProfileName" key=clear
        
        foreach ($line in $profileOutput) {
            if ($line -match "Key Content\s*:\s*(.+)") {
                return $matches[1].Trim()
            }
        }
        
        return "N/A"
    }
    catch {
        Write-Log -Message "Failed to get password for profile '$ProfileName': $($_.Exception.Message)" -Level "ERROR"
        return "Error"
    }
}

function Show-WiFiCredentials {
    try {
        Write-Log -Message "Retrieving all WiFi credentials..." -Level "INFO"
        
        $profiles = Get-WiFiProfiles
        
        if ($profiles.Count -eq 0) {
            Write-Log -Message "No WiFi profiles found" -Level "WARNING"
            return
        }
        
        $credentials = @()
        
        foreach ($profile in $profiles) {
            $password = Get-WiFiPassword -ProfileName $profile
            $credentials += [PSCustomObject]@{
                'WiFi Name' = $profile
                'Password' = $password
            }
        }
        
        Write-Log -Message "WiFi Credentials Retrieved:" -Level "SUCCESS"
        Write-Log -Message "$('=' * 60)" -Level "INFO"
        
        $credentials | Format-Table -AutoSize | Out-String | ForEach-Object {
            $_.Trim() -split "`n" | ForEach-Object {
                if ($_.Trim()) {
                    Write-Log -Message $_ -Level "INFO"
                }
            }
        }
        
        Write-Log -Message "$('=' * 60)" -Level "INFO"
        
        # Save to CSV file
        $csvPath = "$PSScriptRoot\WiFi_Credentials_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').csv"
        $credentials | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Log -Message "WiFi credentials saved to: $csvPath" -Level "SUCCESS"
        
        return $credentials
    }
    catch {
        Write-Log -Message "Failed to retrieve WiFi credentials: $($_.Exception.Message)" -Level "ERROR"
        $Script:ErrorCount++
    }
}

# ==============================================================================
# USER INTERFACE FUNCTIONS
# ==============================================================================

function Show-Help {
    $helpText = @"

==============================================================================
                    Mobile Hotspot Manager for Windows 10/11
==============================================================================

DESCRIPTION:
    This script allows you to control Windows Mobile Hotspot programmatically
    and retrieve WiFi credentials without using the built-in Windows UI.

USAGE:
    .\mobile-hotspot-manager.ps1 -Action <Action> [-Quiet]

ACTIONS:
    Enable      Enable the mobile hotspot
    Disable     Disable the mobile hotspot  
    Toggle      Toggle hotspot state (on->off or off->on)
    Status      Show current hotspot status
    GetWiFi     Retrieve all saved WiFi credentials
    Help        Show this help message

PARAMETERS:
    -Action     Required. Specifies the action to perform
    -Quiet      Optional. Suppress console output (logging still occurs)

EXAMPLES:
    .\mobile-hotspot-manager.ps1 -Action Enable
    .\mobile-hotspot-manager.ps1 -Action Status
    .\mobile-hotspot-manager.ps1 -Action GetWiFi
    .\mobile-hotspot-manager.ps1 -Action Toggle -Quiet

REQUIREMENTS:
    - Windows 10/11
    - PowerShell 5.0 or higher
    - Administrator privileges
    - Active internet connection (for hotspot operations)

NOTES:
    - All operations are logged to: MobileHotspot_YYYY-MM-DD.log
    - WiFi credentials are exported to CSV when using GetWiFi action
    - Run as Administrator for best results

==============================================================================
"@

    Write-Host $helpText -ForegroundColor Green
}

function Test-Prerequisites {
    Write-Log -Message "Checking prerequisites..." -Level "INFO"
    
    # Check Windows version
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -lt 10) {
        Write-Log -Message "This script requires Windows 10 or later" -Level "ERROR"
        $Script:ErrorCount++
        return $false
    }
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Log -Message "This script requires PowerShell 5.0 or later" -Level "ERROR"
        $Script:ErrorCount++
        return $false
    }
    
    # Check if running as administrator
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Log -Message "Warning: Not running as Administrator. Some operations may fail." -Level "WARNING"
    }
    
    Write-Log -Message "Prerequisites check completed" -Level "SUCCESS"
    return $true
}

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

function Main {
    try {
        # Start logging
        Start-LogSession
        
        # Show help if requested
        if ($Action -eq "Help") {
            Show-Help
            return
        }
        
        # Check prerequisites
        if (-not (Test-Prerequisites)) {
            Write-Log -Message "Prerequisites check failed. Exiting." -Level "ERROR"
            return
        }
        
        # Initialize hotspot manager (not needed for WiFi operations)
        if ($Action -ne "GetWiFi") {
            if (-not (Initialize-HotspotManager)) {
                Write-Log -Message "Failed to initialize hotspot manager. Exiting." -Level "ERROR"
                return
            }
        }
        
        # Execute requested action
        switch ($Action) {
            "Enable" {
                $success = Enable-MobileHotspot
                if ($success) {
                    Write-Log -Message "Mobile hotspot has been enabled successfully" -Level "SUCCESS"
                } else {
                    Write-Log -Message "Failed to enable mobile hotspot" -Level "ERROR"
                }
            }
            
            "Disable" {
                $success = Disable-MobileHotspot
                if ($success) {
                    Write-Log -Message "Mobile hotspot has been disabled successfully" -Level "SUCCESS"
                } else {
                    Write-Log -Message "Failed to disable mobile hotspot" -Level "ERROR"
                }
            }
            
            "Toggle" {
                $success = Toggle-MobileHotspot
                if ($success) {
                    Write-Log -Message "Mobile hotspot has been toggled successfully" -Level "SUCCESS"
                } else {
                    Write-Log -Message "Failed to toggle mobile hotspot" -Level "ERROR"
                }
            }
            
            "Status" {
                $status = Get-HotspotStatus
                Write-Log -Message "Current mobile hotspot status: $status" -Level "INFO"
                
                if (-not $Quiet) {
                    Write-Host "`nMobile Hotspot Status: " -NoNewline -ForegroundColor Cyan
                    switch ($status) {
                        "On" { Write-Host "ENABLED" -ForegroundColor Green }
                        "Off" { Write-Host "DISABLED" -ForegroundColor Red }
                        "InTransition" { Write-Host "CHANGING STATE" -ForegroundColor Yellow }
                        default { Write-Host $status -ForegroundColor Yellow }
                    }
                }
            }
            
            "GetWiFi" {
                Show-WiFiCredentials
            }
            
            default {
                Write-Log -Message "Unknown action: $Action" -Level "ERROR"
                Show-Help
            }
        }
    }
    catch {
        Write-Log -Message "Unexpected error in main execution: $($_.Exception.Message)" -Level "ERROR"
        $Script:ErrorCount++
    }
    finally {
        # End logging
        Stop-LogSession
        
        # Exit with appropriate code
        if ($Script:ErrorCount -gt 0) {
            exit 1
        } else {
            exit 0
        }
    }
}

# Run the main function
Main