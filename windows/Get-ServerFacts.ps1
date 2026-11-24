<#
.SYNOPSIS
Facts for this Windows server as JSON in the estate-audit inventory format.
.DESCRIPTION
Read-only. Patch date comes from Get-HotFix, or the OS install date when no hotfix has a date.
Volumes are fixed local disks with one usage sample; a SAN or NAS LUN shows up as a local volume
here, so set kind in the inventory by hand if you want it labelled.
#>
[CmdletBinding()]
param(
    [string]$Role = 'unspecified'
)

$ErrorActionPreference = 'Stop'

function Format-Day($d) { ([datetime]$d).ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) }

$os = Get-CimInstance -ClassName Win32_OperatingSystem

$patched = $os.InstallDate
$hot = Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($hot) { $patched = $hot.InstalledOn }

$volumes = @(Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter -and $_.Size -gt 0 } | ForEach-Object {
    [ordered]@{
        name    = "$($_.DriveLetter):"
        kind    = 'local'
        size_gb = [math]::Round($_.Size / 1GB, 2)
        history = @([ordered]@{ date = Format-Day (Get-Date); used_gb = [math]::Round(($_.Size - $_.SizeRemaining) / 1GB, 2) })
    }
})

$certs = @(Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue | ForEach-Object {
    $subject = if ($_.Subject) { $_.Subject } else { $_.Thumbprint }
    [ordered]@{ subject = $subject; not_after = Format-Day $_.NotAfter }
})

[ordered]@{
    name         = $env:COMPUTERNAME
    os           = 'windows'
    os_name      = $os.Caption
    role         = $Role
    last_patched = Format-Day $patched
    certs        = $certs
    volumes      = $volumes
} | ConvertTo-Json -Depth 6
