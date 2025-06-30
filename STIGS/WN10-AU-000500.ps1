<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Jorge Juarez
    LinkedIn        : linkedin.com/in/jorgejuarez1
    GitHub          : github.com/jorjuarez
    Date Created    : 2025-06-30
    Last Modified   : 2024-06-30
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000500

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\(STIG-ID-WN10-AU-000500).ps1 
#>

# --- Configuration Parameters ---
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$MaxSizeName = "MaxSize"
$MaxSizeValue = 33000 # In KB, 0x000080e8 in hex (33000 decimal)
$RetentionName = "Retention" 
$RetentionValue = 0   # 0 = Overwrite events as needed (oldest events first)
                      # 1 = Archive the log when full, do not overwrite (STIG requires overwrite)
                      # This value 0 ensures the log continually overwrites old events, which is the required STIG behavior to prevent the log from filling up and stopping new event recording.

Write-Host "--- Applying STIG WN10-AU-000500 Remediation ---"
Write-Host "Target Registry Path: $RegPath"
Write-Host "Desired Max Log Size: $($MaxSizeValue) KB"
Write-Host "Desired Retention: Overwrite events as needed"

# --- Step 1: Ensure the registry path exists ---
Write-Host "`nChecking if registry path exists..."
try {
    # Check if the path exists, if not, create it
    if (-not (Test-Path $RegPath)) {
        Write-Host "Registry path '$RegPath' not found. Creating it..."
        New-Item -Path $RegPath -Force | Out-Null
        Write-Host "Registry path created successfully."
    } else {
        Write-Host "Registry path '$RegPath' already exists."
    }
}
catch {
    Write-Error "Failed to check/create registry path: $($_.Exception.Message)"
    exit 1 # Exit with an error code
}

# --- Step 2: Set the MaxSize DWORD value ---
Write-Host "`nSetting '$MaxSizeName' value..."
try {
    Set-ItemProperty -LiteralPath $RegPath -Name $MaxSizeName -Value $MaxSizeValue -Type DWord -Force
    Write-Host "Successfully set '$MaxSizeName' to $($MaxSizeValue) KB."
}
catch {
    Write-Error "Failed to set '$MaxSizeName' value: $($_.Exception.Message)"
    exit 1
}

# --- Step 3: Set the Retention DWORD value ---
# This ensures that the log overwrites old events, which is typically required by STIGs
Write-Host "`nSetting '$RetentionName' value (retention policy)..."
try {
    Set-ItemProperty -LiteralPath $RegPath -Name $RetentionName -Value $RetentionValue -Type DWord -Force
    Write-Host "Successfully set '$RetentionName' to $($RetentionValue) (Overwrite events as needed)."
}
catch {
    Write-Error "Failed to set '$RetentionName' value: $($_.Exception.Message)"
    exit 1
}

# --- Verification ---
Write-Host "`n--- Verifying Changes ---"
try {
    $CurrentMaxSize = (Get-ItemProperty -LiteralPath $RegPath -Name $MaxSizeName -ErrorAction Stop).MaxSize
    $CurrentRetention = (Get-ItemProperty -LiteralPath $RegPath -Name $RetentionName -ErrorAction Stop).Retention

    Write-Host "Current MaxSize: $($CurrentMaxSize) KB"
    Write-Host "Current Retention: $($CurrentRetention) (0 = Overwrite, 1 = Archive)"

    if ($CurrentMaxSize -ge $MaxSizeValue -and $CurrentRetention -eq $RetentionValue) {
        Write-Host "`nSUCCESS: WN10-AU-000500 remediation applied and verified successfully."
    } else {
        Write-Warning "`nWARNING: Registry values do not match desired configuration. Please review."
    }
}
catch {
    Write-Error "Failed to verify registry values: $($_.Exception.Message)"
    Write-Warning "Please manually check the registry path: $RegPath"
}

Write-Host "`n--- Script Complete ---"
