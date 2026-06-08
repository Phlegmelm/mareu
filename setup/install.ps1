<#
.SYNOPSIS
    Mareu installer for Windows.

.DESCRIPTION
    Builds the release binary, places it in a per-user programs directory, adds
    that directory to your user PATH (no admin required), and wires PowerShell
    tab-completion into your profile. Idempotent — safe to re-run.

    Use -Symlink to create a symlink to target\release\mareu.exe instead of
    copying (so rebuilds propagate). Symlinks on Windows require an elevated
    (admin) shell OR Developer Mode; the script falls back to copying if it
    can't create one.

.PARAMETER Dest
    Install directory. Default: %LOCALAPPDATA%\Programs\mareu

.PARAMETER Symlink
    Symlink the binary instead of copying it (needs admin / Developer Mode).

.PARAMETER NoBuild
    Skip `cargo build --release` and use an existing binary.

.PARAMETER NoCompletions
    Skip wiring PowerShell completion into $PROFILE.

.PARAMETER DryRun
    Print planned actions without changing anything.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File setup\install.ps1

.EXAMPLE
    # from an elevated shell, link instead of copy:
    powershell -ExecutionPolicy Bypass -File setup\install.ps1 -Symlink
#>
[CmdletBinding()]
param(
    [string]$Dest = (Join-Path $env:LOCALAPPDATA 'Programs\mareu'),
    [switch]$Symlink,
    [switch]$NoBuild,
    [switch]$NoCompletions,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$RepoDir = Split-Path -Parent $PSScriptRoot
$BinSrc  = Join-Path $RepoDir 'target\release\mareu.exe'

function Say($m) { Write-Host "  $m" }
function Do-Action($desc, $action) {
    if ($DryRun) { Write-Host "  [dry-run] $desc" }
    else { Say $desc; & $action }
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-DeveloperMode {
    try {
        $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock'
        (Get-ItemProperty -Path $k -Name AllowDevelopmentWithoutDevLicense -ErrorAction Stop).AllowDevelopmentWithoutDevLicense -eq 1
    } catch { $false }
}

Write-Host "> mareu install  (repo: $RepoDir)"

# -- toolchain + build -------------------------------------------------------
if (-not $NoBuild) {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw "cargo not found - install Rust from https://rustup.rs"
    }
    Do-Action "building release binary..." { Push-Location $RepoDir; try { cargo build --release } finally { Pop-Location } }
}
if (-not $DryRun -and -not (Test-Path $BinSrc)) {
    throw "binary not found at $BinSrc (run without -NoBuild)"
}

# -- install binary ----------------------------------------------------------
Do-Action "creating $Dest" { New-Item -ItemType Directory -Force -Path $Dest | Out-Null }
$DestExe = Join-Path $Dest 'mareu.exe'

if ($Symlink) {
    $canLink = (Test-Admin) -or (Test-DeveloperMode)
    if ($canLink) {
        Do-Action "linking $DestExe -> $BinSrc" {
            if (Test-Path $DestExe) { Remove-Item $DestExe -Force }
            New-Item -ItemType SymbolicLink -Path $DestExe -Target $BinSrc | Out-Null
        }
    } else {
        Say "symlink needs an admin shell or Developer Mode; copying instead"
        Do-Action "copying $BinSrc -> $DestExe" { Copy-Item -Force $BinSrc $DestExe }
    }
} else {
    Do-Action "copying $BinSrc -> $DestExe" { Copy-Item -Force $BinSrc $DestExe }
}

# -- user PATH (no admin needed) --------------------------------------------
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath -and ($userPath.Split(';') -contains $Dest)) {
    Say "PATH: $Dest already on user PATH (OK)"
} else {
    Do-Action "adding $Dest to user PATH" {
        $new = if ([string]::IsNullOrEmpty($userPath)) { $Dest } else { "$userPath;$Dest" }
        [Environment]::SetEnvironmentVariable('Path', $new, 'User')
        $env:Path = "$env:Path;$Dest"   # current session
    }
    Say "  open a new terminal for PATH to take effect in other shells"
}

# -- PowerShell completion ---------------------------------------------------
if (-not $NoCompletions) {
    $complFile = Join-Path $Dest '_mareu.completion.ps1'
    Do-Action "generating PowerShell completion -> $complFile" {
        & $BinSrc completions powershell | Out-File -FilePath $complFile -Encoding utf8
    }
    $profilePath = $PROFILE.CurrentUserAllHosts
    $line = ". `"$complFile`""
    if (-not $DryRun) {
        $profileDir = Split-Path -Parent $profilePath
        if (-not (Test-Path $profileDir)) { New-Item -ItemType Directory -Force -Path $profileDir | Out-Null }
        if (-not (Test-Path $profilePath)) { New-Item -ItemType File -Path $profilePath | Out-Null }
        $existing = Get-Content -Raw -Path $profilePath -ErrorAction SilentlyContinue
        if ($existing -notlike "*$complFile*") {
            Add-Content -Path $profilePath -Value "`n# mareu completion`n$line"
            Say "wired completion into $profilePath"
        } else {
            Say "completion already wired in $profilePath"
        }
    } else {
        Write-Host "  [dry-run] add '$line' to $profilePath"
    }
}

Write-Host "> done. Open a new terminal, then:  mareu --version"
