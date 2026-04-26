<#
.SYNOPSIS
The PowerShell installer for agentsso (permitlayer) on Windows.

.DESCRIPTION
Detects platform (x86_64 only at MVP), resolves the latest GitHub Release
tag (or honours $env:AGENTSSO_VERSION), downloads the matching .zip
artifact, verifies its sha256 sidecar, extracts agentsso.exe, and copies
it to %LOCALAPPDATA%\Programs\agentsso\agentsso.exe (overridable via
$env:AGENTSSO_INSTALL_DIR or the -InstallDir parameter).

Recommended invocation:
    iwr https://raw.githubusercontent.com/permitlayer/permitlayer/main/install/install.ps1 -UseBasicParsing | iex

With autostart (Startup-folder shortcut):
    & ([scriptblock]::Create((iwr https://raw.githubusercontent.com/permitlayer/permitlayer/main/install/install.ps1 -UseBasicParsing).Content)) -Autostart

Notes:
- No Authenticode signing yet (Story 7.7 / post-MVP). Trust chain is
  HTTPS to GitHub Releases + sha256 sidecar verification.
- `irm | iex` bypasses ExecutionPolicy on .ps1 files (the policy fires only
  on disk-resident scripts; piped strings via Invoke-Expression don't trip it).
  See: about_Signing.
- Story 7.3 owns full autostart. The -Autostart flag here drops a
  Startup-folder .lnk only — no Task Scheduler, no `agentsso autostart enable`.
- Story 7.4 owns uninstall. No receipt JSON, no ARP entry; uninstall is
  manual until 7.4 lands.
#>

[CmdletBinding()]
param(
    [switch]$Autostart,
    [switch]$NoModifyPath,
    [string]$Version = $env:AGENTSSO_VERSION,
    [string]$InstallDir = $env:AGENTSSO_INSTALL_DIR
)

# --- Configuration -----------------------------------------------------------

$script:RepoOwner = 'permitlayer'
$script:RepoName  = 'permitlayer'
$script:PkgName   = 'permitlayer-daemon'
$script:BinName   = 'agentsso.exe'
$script:DefaultPort = 3820

# --- Output helpers ----------------------------------------------------------

# ANSI escape — works on Windows Terminal, PowerShell 7+ default, and
# legacy conhost.exe with VT enabled (Windows 10 v1607+).
$script:ESC = [char]27
$script:TEAL  = "$ESC[36m"
$script:DIM   = "$ESC[90m"
$script:WHITE = "$ESC[97m"
$script:RESET = "$ESC[0m"

# Honour NO_COLOR (https://no-color.org/) and drop ANSI when output is
# redirected (CI logs, pipes). Modern Windows Terminal + conhost on
# Windows 10 v1607+ support VT; older hosts will render escape sequences
# as garbage, but the irm | iex flow on Windows 10 v2004+ (PRD §608)
# is in the supported set.
if ($env:NO_COLOR -or [Console]::IsOutputRedirected) {
    $script:TEAL = ''
    $script:DIM  = ''
    $script:WHITE = ''
    $script:RESET = ''
}

# Print a completed step in ProgressSteps format (UX-DR9). Mirrors
# install.sh's step_done. The arrow + checkmark glyphs are UTF-8;
# PowerShell 7 + Windows Terminal render them natively. Legacy conhost
# requires the OutputEncoding setting below in main.
function Write-StepDone {
    param(
        [Parameter(Mandatory)] [string]$Label,
        [string]$Value = ''
    )
    $arrow = '->'
    $check = 'OK'
    # Use UTF-8 glyphs only when we have a real TTY with VT support;
    # otherwise stick to ASCII so logs in CI / file redirection stay clean.
    if ($script:RESET -ne '') {
        $arrow = "$([char]0x2192)"  # →
        $check = "$([char]0x2713)"  # ✓
    }
    $padded = $Label.PadRight(36)
    if ($Value) {
        Write-Host ("  {0}{1} {2}{3}{4}{5}{6} {7}{8}{9}" -f `
            $script:DIM, $arrow, $padded, $script:RESET, `
            $script:WHITE, $Value, $script:RESET, `
            $script:TEAL, $check, $script:RESET)
    } else {
        Write-Host ("  {0}{1} {2}{3}{4}{5}{6}" -f `
            $script:DIM, $arrow, $padded, $script:RESET, `
            $script:TEAL, $check, $script:RESET)
    }
}

function Write-Err {
    param([string]$Message)
    Write-Host ("  error: {0}" -f $Message) -ForegroundColor Red
    throw $Message
}

function Write-Warn {
    param([string]$Message)
    Write-Host ("  warning: {0}" -f $Message) -ForegroundColor Yellow
}

# --- Preconditions -----------------------------------------------------------

function Test-PowerShellVersion {
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Err "PowerShell 5.1 or later is required (you have $($PSVersionTable.PSVersion))."
    }
}

function Test-ExecutionPolicy {
    # Soft check — do NOT mutate the policy. `irm | iex` (the recommended
    # invocation) bypasses this entirely; the check fires only when a user
    # has saved the file and is running it from disk under a restrictive
    # default like `Restricted` or `AllSigned`.
    $allowed = @('Unrestricted', 'RemoteSigned', 'Bypass', 'Undefined')
    $policy = (Get-ExecutionPolicy).ToString()
    if ($policy -notin $allowed) {
        $msg = "ExecutionPolicy must be one of [$($allowed -join ', ')] but is '$policy'. Run: Set-ExecutionPolicy RemoteSigned -Scope CurrentUser"
        Write-Err $msg
    }
}

# --- Architecture detection --------------------------------------------------

# Returns the dist target triple (e.g. "x86_64-pc-windows-msvc"). Throws
# on unsupported architectures.
function Get-Arch {
    # Try .NET RuntimeInformation first (most reliable on ARM64 emulation).
    try {
        $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    } catch {
        # PS 5.1 on Windows 7 / older: RuntimeInformation may not be loaded.
        # Fall back to Is64BitOperatingSystem.
        if ([Environment]::Is64BitOperatingSystem) {
            $arch = 'X64'
        } else {
            $arch = 'X86'
        }
    }
    switch ($arch) {
        'X64'   { return 'x86_64-pc-windows-msvc' }
        'Arm64' { Write-Err "ARM64 Windows is not yet supported. Track Story 7.7 for cross-platform CI matrix expansion." }
        default { Write-Err "Unsupported architecture: $arch (only x86_64 is supported at MVP)." }
    }
}

# --- Version resolution ------------------------------------------------------

# Resolves the install version — uses $Version param if non-empty, else
# fetches the latest release from GitHub. Strips the leading 'v' (matches
# install.sh behaviour at line ~170).
function Resolve-Version {
    param([string]$RequestedVersion)
    if ($RequestedVersion) {
        return $RequestedVersion -replace '^v', ''
    }
    $url = "https://api.github.com/repos/$($script:RepoOwner)/$($script:RepoName)/releases/latest"
    try {
        $release = Invoke-RestMethod -Uri $url -UseBasicParsing -TimeoutSec 30
    } catch {
        Write-Err "failed to fetch latest release from GitHub: $($_.Exception.Message)"
    }
    if (-not $release.tag_name) {
        Write-Err "could not determine latest release tag"
    }
    return $release.tag_name -replace '^v', ''
}

# --- Download + verification -------------------------------------------------

# Downloads the artifact + sha256 sidecar to the given temp dir. Returns
# the full path to the downloaded zip.
function Get-Release {
    param(
        [Parameter(Mandatory)] [string]$Version,
        [Parameter(Mandatory)] [string]$Target,
        [Parameter(Mandatory)] [string]$TempDir
    )
    $artifact = "$($script:PkgName)-$Target.zip"
    $base = "https://github.com/$($script:RepoOwner)/$($script:RepoName)/releases/download/v$Version"
    $zipUrl = "$base/$artifact"
    $shaUrl = "$zipUrl.sha256"

    $zipPath = Join-Path $TempDir $artifact
    $shaPath = "$zipPath.sha256"

    # Fetch sha256 sidecar first — fail fast if missing (the spec requires
    # sha256 verification; a missing sidecar means the release is partial
    # or someone hand-published an unsigned binary).
    try {
        Invoke-WebRequest -Uri $shaUrl -OutFile $shaPath -UseBasicParsing -TimeoutSec 30
    } catch {
        Write-Err ("sha256 sidecar not available at $shaUrl. Refusing to install " +
            "an unverified binary. Possible causes: partial release, network " +
            "MITM, or a release published without sha256 (file an issue).")
    }

    # Fetch the zip itself.
    try {
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing -TimeoutSec 120
    } catch {
        Write-Err "failed to download ${zipUrl}: $($_.Exception.Message)"
    }

    return $zipPath
}

# Verifies the zip's sha256 against the sidecar file's first
# whitespace-delimited token. Throws on mismatch with both hashes printed.
function Test-Sha256 {
    param(
        [Parameter(Mandatory)] [string]$ZipPath
    )
    $shaPath = "$ZipPath.sha256"
    if (-not (Test-Path $shaPath)) {
        Write-Err "sha256 sidecar missing at $shaPath"
    }
    # sha256sum format: "<64hex>  <basename>". Take the first whitespace
    # token and lowercase it.
    $expected = (Get-Content -Raw -LiteralPath $shaPath).Trim().Split()[0].ToLowerInvariant()
    $actual   = (Get-FileHash -Algorithm SHA256 -LiteralPath $ZipPath).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        Write-Err ("sha256 mismatch for $ZipPath`nExpected: $expected`nActual:   $actual`n" +
            "The downloaded binary may be corrupted or tampered with.")
    }
}

# --- Install -----------------------------------------------------------------

# Extracts the zip and copies agentsso.exe to $InstallDir. Returns the
# full path to the installed exe.
function Install-AgentSso {
    param(
        [Parameter(Mandatory)] [string]$ZipPath,
        [Parameter(Mandatory)] [string]$InstallDir
    )
    # Extract to a sibling temp dir under the same parent (so we can move
    # the binary atomically — same volume guaranteed).
    $extractDir = Join-Path (Split-Path -Parent $ZipPath) 'extract'
    New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
    Expand-Archive -LiteralPath $ZipPath -DestinationPath $extractDir -Force

    # dist's executable-zip layout: agentsso.exe lives at the archive root
    # alongside CHANGELOG.md / LICENSE / README.md / install.sh.
    $exeSrc = Get-ChildItem -Path $extractDir -Filter $script:BinName -Recurse | Select-Object -First 1
    if (-not $exeSrc) {
        Write-Err "$($script:BinName) not found inside $ZipPath"
    }

    # Ensure target dir exists.
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

    $exeDest = Join-Path $InstallDir $script:BinName
    Copy-Item -LiteralPath $exeSrc.FullName -Destination $exeDest -Force
    return $exeDest
}

# --- PATH mutation -----------------------------------------------------------

# Prepends $InstallDir to the user's HKCU\Environment\Path as REG_EXPAND_SZ
# and broadcasts WM_SETTINGCHANGE so File Explorer + new processes pick up
# the change without logout. Idempotent: skips if $InstallDir already in PATH.
#
# Uses the cargo-dist installer.ps1 pattern verbatim (verified primary
# source: https://github.com/axodotdev/cargo-dist/blob/main/cargo-dist/templates/installer/installer.ps1.j2).
# Three subtle bits matter: (1) 'DoNotExpandEnvironmentNames' preserves
# %var% lazy evaluation in existing PATH entries; (2) `-split ';' -ne ''`
# drops empty entries from trailing `;`; (3) `,$InstallDir + $current`
# uses the comma-operator to force single-element-array concatenation.
function Update-UserPath {
    param(
        [Parameter(Mandatory)] [string]$InstallDir,
        [string]$RegistryPath = 'registry::HKEY_CURRENT_USER\Environment'
    )
    $current = (Get-Item -LiteralPath $RegistryPath).GetValue('Path', '', 'DoNotExpandEnvironmentNames') `
        -split ';' -ne ''
    # PowerShell's -contains is case-insensitive by default, which matches
    # Windows path semantics (paths are case-preserving but not -sensitive).
    if ($current -contains $InstallDir) {
        return $false  # no change
    }
    $new = (,$InstallDir + $current) -join ';'
    Set-ItemProperty -Type ExpandString -LiteralPath $RegistryPath -Name Path -Value $new

    # WM_SETTINGCHANGE broadcast via the dummy SetEnvironmentVariable
    # round-trip. Without this, File Explorer + new processes won't see
    # the new PATH until logout. The dummy variable name is GUID-prefixed
    # so we don't collide with anything real, and immediately deleted.
    $dummy = 'agentsso-' + [guid]::NewGuid()
    [Environment]::SetEnvironmentVariable($dummy, 'x', 'User')
    [Environment]::SetEnvironmentVariable($dummy, [NullString]::Value, 'User')

    return $true  # changed
}

# --- Autostart (Story 7.2 minimum; Story 7.3 owns full autostart) ------------

# STORY 7.3 BOUNDARY: full Task Scheduler / `agentsso autostart enable`
# integration belongs to Story 7.3. This Startup-folder shortcut is the
# install-time minimum that mirrors install.sh's `nohup agentsso start`
# (the Mac/Linux installer also doesn't do real LaunchAgent registration —
# it just starts the daemon once). Story 7.3 will detect this shortcut
# (filename `agentsso.lnk`) and either manage it or warn the user.
function Register-StartupShortcut {
    param(
        [Parameter(Mandatory)] [string]$ExePath,
        [Parameter(Mandatory)] [string]$WorkingDir
    )
    $startup = [Environment]::GetFolderPath('Startup')
    if (-not $startup) {
        Write-Warn "Could not resolve Startup folder; skipping autostart shortcut."
        return $null
    }
    $lnkPath = Join-Path $startup 'agentsso.lnk'
    $wsh = New-Object -ComObject WScript.Shell
    $sc = $wsh.CreateShortcut($lnkPath)
    # Critical (per MS docs at learn.microsoft.com/.../scripting-articles/xsy6k3ys):
    # arguments MUST go in .Arguments, NOT shell-quoted into .TargetPath.
    $sc.TargetPath       = $ExePath
    $sc.Arguments        = 'start'
    $sc.WorkingDirectory = $WorkingDir
    $sc.IconLocation     = "$ExePath,0"
    $sc.Description      = 'AgentSSO daemon (autostart)'
    $sc.Save()
    return $lnkPath
}

# --- Main --------------------------------------------------------------------

function Invoke-Main {
    $start = Get-Date

    # Mascot glyph (UX-DR24).
    Write-Host ''
    Write-Host ("  {0}{1}{2} permitlayer" -f $script:WHITE, "$([char]0x2591)$([char]0x2592)$([char]0x2593)$([char]0x2588)", $script:RESET)
    Write-Host '       the guard between your agent and your data'
    Write-Host ''

    # Step 1: Detect platform.
    $target = Get-Arch
    Write-StepDone -Label 'detecting platform' -Value "Windows $($target -replace '-pc-windows-msvc$','')"

    # Resolve version.
    $resolvedVersion = Resolve-Version -RequestedVersion $Version

    # Resolve install dir default.
    if (-not $InstallDir) {
        $script:InstallDir = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Programs\agentsso'
    } else {
        $script:InstallDir = $InstallDir
    }

    # Set up temp dir + cleanup. Use try/finally so the temp dir is
    # removed even on error.
    $tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ([guid]::NewGuid()))
    try {
        # Step 2: Download.
        $zipPath = Get-Release -Version $resolvedVersion -Target $target -TempDir $tmp.FullName
        $sizeMB = [math]::Round((Get-Item $zipPath).Length / 1MB, 1)
        Write-StepDone -Label "downloading agentsso v$resolvedVersion" -Value "$sizeMB MB"

        # Step 3: Verify sha256.
        Test-Sha256 -ZipPath $zipPath
        Write-StepDone -Label 'verifying checksum' -Value 'sha256'

        # Step 4: Install.
        $exePath = Install-AgentSso -ZipPath $zipPath -InstallDir $script:InstallDir
        Write-StepDone -Label "installing to $($script:InstallDir)" -Value ''

        # Step 5: Update PATH (unless -NoModifyPath).
        if (-not $NoModifyPath) {
            $changed = Update-UserPath -InstallDir $script:InstallDir
            if ($changed) {
                Write-StepDone -Label 'updating user PATH' -Value 'open a new terminal'
            } else {
                Write-StepDone -Label 'updating user PATH' -Value 'already present'
            }
        }

        # Step 6: Optional autostart.
        if ($Autostart) {
            $lnk = Register-StartupShortcut -ExePath $exePath -WorkingDir $script:InstallDir
            if ($lnk) {
                Write-StepDone -Label 'registering autostart' -Value 'Startup folder'
            }
        }
    } finally {
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $tmp.FullName
    }

    # Elapsed.
    $elapsed = [int]((Get-Date) - $start).TotalSeconds
    Write-Host ''
    Write-Host "  installed in ${elapsed}s"
    Write-Host ''
    Write-Host "  next:  agentsso setup gmail"
    Write-Host ''
}

# Allow sourcing for testing without executing main. Mirrors install.sh's
# AGENTSSO_TEST_MODE pattern at line ~471.
if ($env:AGENTSSO_TEST_MODE -ne '1') {
    Test-PowerShellVersion
    Test-ExecutionPolicy
    Invoke-Main
}
