<#
.SYNOPSIS
    Mareu uninstaller for Windows.
.DESCRIPTION
    Removes the binary and completion script, and removes the install directory
    from your user PATH. Leaves config and sessions intact.
.PARAMETER Dest
    Install directory used at install time. Default: %LOCALAPPDATA%\Programs\mareu
.PARAMETER DryRun
    Print planned actions without changing anything.
#>
[CmdletBinding()]
param(
    [string]$Dest = (Join-Path $env:LOCALAPPDATA 'Programs\mareu'),
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'

function Do-Action($desc, $action) {
    if ($DryRun) { Write-Host "  [dry-run] $desc" } else { Write-Host "  $desc"; & $action }
}

Write-Host "> mareu uninstall"

# Remove install dir contents + dir.
if (Test-Path $Dest) {
    Do-Action "removing $Dest" { Remove-Item -Recurse -Force $Dest }
} else {
    Write-Host "  $Dest not present"
}

# Strip the dir from user PATH.
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath -and ($userPath.Split(';') -contains $Dest)) {
    Do-Action "removing $Dest from user PATH" {
        $new = ($userPath.Split(';') | Where-Object { $_ -ne $Dest }) -join ';'
        [Environment]::SetEnvironmentVariable('Path', $new, 'User')
    }
} else {
    Write-Host "  $Dest not on user PATH"
}

# Remove the completion line from the profile (best-effort).
$profilePath = $PROFILE.CurrentUserAllHosts
if ((Test-Path $profilePath)) {
    $complFile = Join-Path $Dest '_mareu.completion.ps1'
    $kept = Get-Content $profilePath | Where-Object { $_ -notlike "*$complFile*" -and $_ -notlike '*# mareu completion*' }
    Do-Action "cleaning completion line from $profilePath" {
        Set-Content -Path $profilePath -Value $kept -Encoding utf8
    }
}

Write-Host "  note: config (%APPDATA%\mareu) and sessions (%LOCALAPPDATA%\mareu) are left intact."
Write-Host "> done. Open a new terminal for PATH changes to apply."
