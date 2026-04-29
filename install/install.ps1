<#
.SYNOPSIS
The PowerShell installer for agentsso (permitlayer) on Windows.

.DESCRIPTION
Detects platform (x86_64 only at MVP), resolves the latest GitHub Release
tag (or honours $env:AGENTSSO_VERSION), downloads the matching .zip
artifact, verifies its sha256 sidecar (and minisig if minisign.exe is on
PATH), extracts agentsso.exe, and copies it to
%LOCALAPPDATA%\Programs\agentsso\agentsso.exe (overridable via
$env:AGENTSSO_INSTALL_DIR or the -InstallDir parameter).

Recommended invocation:
    iwr https://raw.githubusercontent.com/permitlayer/permitlayer/main/install/install.ps1 -UseBasicParsing | iex

With autostart (Startup-folder shortcut):
    & ([scriptblock]::Create((iwr https://raw.githubusercontent.com/permitlayer/permitlayer/main/install/install.ps1 -UseBasicParsing).Content)) -Autostart

Notes:
- No Authenticode signing yet (Story 7.7 / post-MVP). Trust chain is
  HTTPS to GitHub Releases + sha256 sidecar verification, with optional
  minisig verification if minisign.exe is available on PATH.
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

# P7: Dev Notes idiom — set ErrorActionPreference + ProgressPreference at
# script top. Stop on any error; SilentlyContinue speeds up Invoke-WebRequest
# 10x on PS 5.1 (the noisy progress bar is the bottleneck, not network).
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

# P9: Force TLS 1.2 on PS 5.1 / .NET Framework hosts. Stock Windows 10's
# WinPS 5.1 default ServicePointManager protocol is sometimes still
# TLS 1.0/1.1, which GitHub rejected years ago. Harmless on PS 7+ where
# TLS 1.2/1.3 is already the default.
if ($PSVersionTable.PSEdition -ne 'Core') {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    } catch {
        # Some restricted hosts disallow this; not fatal — Invoke-WebRequest
        # may still succeed on TLS 1.0 against permissive endpoints.
    }
}

# --- Configuration -----------------------------------------------------------

$script:RepoOwner = 'permitlayer'
$script:RepoName  = 'permitlayer'
$script:PkgName   = 'permitlayer-daemon'
$script:BinName   = 'agentsso.exe'
$script:DefaultPort = 3820
# Embedded minisign ed25519 public key (mirror of install/permitlayer.pub).
# Used by P23 — Verify-Minisig — when minisign.exe is on PATH for
# defense-in-depth on top of sha256 sidecar verification.
$script:MinisignPubKey = 'RWR0hYjG6FR31smbyN0CT1/Pfg+yl8nTATUaIAq4jUXlvvFOckj99ipC'

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
# $script:OutputEncoding is set in Invoke-Main so legacy conhost renders
# them correctly (P2).
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

# P26: Detect Run-as-Administrator. Most agentsso users want a per-user
# install — but if the user right-clicked PowerShell → "Run as Administrator"
# before running iwr|iex, [Environment]::GetFolderPath('LocalApplicationData')
# returns the ADMIN profile, not the originating user's. Warn loudly so
# they know what they're doing.
function Test-AdministratorContext {
    try {
        $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Warn "Running as Administrator — install will use the admin profile's %LOCALAPPDATA% and HKCU. If you intended a per-user install for a different account, re-run as that user instead."
        }
    } catch {
        # Identity APIs unavailable (rare; e.g. constrained language mode).
        # Not fatal — proceed.
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
# fetches the latest release from GitHub. Strips the leading 'v', trims
# whitespace (P10), and validates the result looks like semver (P15).
function Resolve-Version {
    param([string]$RequestedVersion)
    if ($RequestedVersion) {
        # P10: .Trim() defensively — `'v0.3.0 '` would otherwise produce
        # a broken URL with a trailing space inside the path segment.
        # Trim BEFORE the v-strip so leading whitespace doesn't prevent
        # `^v` from matching (the `^` anchor is position-0 only, so
        # `'  v0.3.0  '` -replace '^v',''` is a no-op without the trim).
        $candidate = $RequestedVersion.Trim() -replace '^v',''
        Test-SemverShape $candidate
        return $candidate
    }
    $url = "https://api.github.com/repos/$($script:RepoOwner)/$($script:RepoName)/releases/latest"
    try {
        # P8: explicit User-Agent + Accept header. GitHub recommends a
        # User-Agent on all API calls and may reject anonymous calls without
        # one in the future. Accept pins the v3 JSON contract.
        $headers = @{
            'User-Agent' = 'agentsso-installer'
            'Accept'     = 'application/vnd.github+json'
        }
        $release = Invoke-RestMethod -Uri $url -UseBasicParsing -TimeoutSec 30 -Headers $headers
    } catch {
        # P8: actionable rate-limit message. Anonymous GitHub API is
        # 60 req/hour/IP; corporate NATs blow past that. Detect 403 with
        # X-RateLimit-Remaining: 0 and tell the user to set the env var.
        $resp = $_.Exception.Response
        if ($resp -and $resp.StatusCode.value__ -eq 403) {
            $remaining = $null
            try { $remaining = $resp.Headers['X-RateLimit-Remaining'] } catch {}
            if ($remaining -eq '0') {
                $reset = $null
                try { $reset = $resp.Headers['X-RateLimit-Reset'] } catch {}
                $resetMsg = if ($reset) {
                    " (resets at $([DateTimeOffset]::FromUnixTimeSeconds([int64]$reset).ToLocalTime()))"
                } else { '' }
                Write-Err "GitHub API rate limit exceeded$resetMsg. Set `$env:AGENTSSO_VERSION` to a specific version (e.g. '0.3.0') to skip the API lookup."
            }
        }
        Write-Err "failed to fetch latest release from GitHub: $($_.Exception.Message)"
    }
    if (-not $release.tag_name) {
        Write-Err "could not determine latest release tag"
    }
    $resolved = ($release.tag_name -replace '^v','').Trim()
    Test-SemverShape $resolved
    return $resolved
}

# P15: Reject obviously-malformed version strings before they flow into
# URL construction. Catches `latest`, empty strings, or any tag that
# doesn't parse as semver.
function Test-SemverShape {
    param([Parameter(Mandatory)] [string]$Version)
    if ($Version -notmatch '^\d+\.\d+\.\d+(-[\w\.]+)?(\+[\w\.]+)?$') {
        Write-Err "Version '$Version' does not look like semver (expected MAJOR.MINOR.PATCH[-prerelease][+build])."
    }
}

# --- Download + verification -------------------------------------------------

# Downloads the artifact + sha256 sidecar (and .minisig sibling for P23) to
# the given temp dir. Returns the full path to the downloaded zip.
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
    $sigUrl = "$zipUrl.minisig"

    $zipPath = Join-Path $TempDir $artifact
    $shaPath = "$zipPath.sha256"
    $sigPath = "$zipPath.minisig"

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

    # P23: also try to fetch .minisig — best effort. If it's missing, we
    # silently skip minisig verification (sha256 is still mandatory). If
    # it's present, Verify-Minisig will use it when minisign.exe is on PATH.
    try {
        Invoke-WebRequest -Uri $sigUrl -OutFile $sigPath -UseBasicParsing -TimeoutSec 30
    } catch {
        # No .minisig — fine, sha256-only path. Don't even warn (most
        # users won't have minisign.exe and the sha256 is the documented
        # primary trust mechanism).
    }

    # Fetch the zip itself.
    try {
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing -TimeoutSec 120
    } catch {
        Write-Err "failed to download ${zipUrl}: $($_.Exception.Message)"
    }

    return $zipPath
}

# Verifies the zip's sha256 against the sidecar file. P5: parses the sidecar
# in sha256sum format (`<hex>  <basename>` per line, optionally with `*`
# binary marker), locates the line whose filename matches the artifact's
# basename, and compares hashes. Throws if the sidecar references a
# different file or the hash mismatches. P14: handles BOM (UTF-16LE BOM
# from Out-File-NoNewline on PS 5.1 would otherwise contaminate the hex).
function Test-Sha256 {
    param(
        [Parameter(Mandatory)] [string]$ZipPath
    )
    $shaPath = "$ZipPath.sha256"
    if (-not (Test-Path $shaPath)) {
        Write-Err "sha256 sidecar missing at $shaPath"
    }
    $artifactName = Split-Path -Leaf $ZipPath

    # Read raw + strip BOM. PS 5.1's Out-File -NoNewline default emits
    # UTF-16LE BOM; PS 7+'s Get-Content -Raw auto-strips when it detects
    # the encoding, but be defensive across PS versions.
    $raw = Get-Content -Raw -LiteralPath $shaPath
    if ($raw.Length -ge 1 -and [int][char]$raw[0] -eq 0xFEFF) {
        $raw = $raw.Substring(1)
    }

    # Parse sha256sum-format lines: `<hex>  <basename>` or `<hex> *<basename>`.
    # Find the line whose basename matches the downloaded artifact. Single-line
    # sidecars (the dist 0.31 default) work because the only line IS the match.
    $expected = $null
    foreach ($line in $raw -split "`r?`n") {
        $line = $line.Trim()
        if (-not $line) { continue }
        $parts = $line -split '\s+', 2
        if ($parts.Count -lt 2) {
            # Single-token line — sha256sum without filename. Accept ONLY
            # if the sidecar has exactly one such line (legacy single-line
            # format). Defer to the count-check below.
            $expected = $parts[0].ToLowerInvariant()
            continue
        }
        $hash = $parts[0]
        $name = $parts[1].TrimStart('*').Trim()  # strip optional binary marker
        if ($name -eq $artifactName) {
            $expected = $hash.ToLowerInvariant()
            break
        }
    }

    if (-not $expected) {
        Write-Err "sha256 sidecar at $shaPath does not reference $artifactName (sidecar may describe a different artifact)."
    }

    # Validate the hex shape — protects against reading a binary garbage
    # sidecar that happens to start with valid-looking text.
    if ($expected -notmatch '^[0-9a-f]{64}$') {
        Write-Err "sha256 sidecar at $shaPath does not contain a valid 64-char hex digest (got '$expected')."
    }

    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $ZipPath).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        Write-Err ("sha256 mismatch for $ZipPath`nExpected: $expected`nActual:   $actual`n" +
            "The downloaded binary may be corrupted or tampered with.")
    }
}

# P23: Defense-in-depth minisig verification. Only fires if minisign.exe is
# on PATH AND a .minisig file was downloaded. install.sh does this on
# macOS/Linux via the bundled minisign package; on Windows minisign isn't
# common, so we don't require it — but if a security-conscious user has
# installed it (winget install jedisct1.minisign), use it.
#
# This closes part of the trust gap that sha256-from-same-origin leaves
# open: a registry-token-compromised release would need to forge a
# minisig too, which requires the signing key (much higher bar than
# editing release assets).
function Verify-Minisig {
    param(
        [Parameter(Mandatory)] [string]$ZipPath
    )
    $sigPath = "$ZipPath.minisig"
    if (-not (Test-Path $sigPath)) {
        return $false  # no .minisig downloaded; sha256 is the only trust gate
    }
    $minisign = Get-Command minisign.exe -ErrorAction SilentlyContinue
    if (-not $minisign) {
        return $false  # not installed; sha256-only path
    }
    # minisign returns 0 on valid signature, non-zero on failure.
    & $minisign.Source -V -m $ZipPath -P $script:MinisignPubKey 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Err ("minisig verification FAILED for $ZipPath. The downloaded binary " +
            "may be tampered with, or you have an outdated minisign.exe / wrong public key.")
    }
    return $true  # verified
}

# --- Install -----------------------------------------------------------------

# Extracts the zip and copies agentsso.exe to $InstallDir. Returns the
# full path to the installed exe.
function Install-AgentSso {
    param(
        [Parameter(Mandatory)] [string]$ZipPath,
        [Parameter(Mandatory)] [string]$InstallDir
    )
    # P6: detect daemon-running file lock BEFORE extraction; print actionable
    # message rather than a cryptic Copy-Item PSException downstream.
    $exeDest = Join-Path $InstallDir $script:BinName
    if (Test-Path $exeDest) {
        try {
            $fs = [System.IO.File]::Open($exeDest, 'Open', 'Write', 'None')
            $fs.Close()
        } catch {
            Write-Err ("$exeDest is in use (the agentsso daemon is likely running). " +
                "Stop it first with: agentsso stop  — then re-run this installer.")
        }
    }

    # Extract to a sibling temp dir under the same parent (so we can move
    # the binary atomically — same volume guaranteed). Wipe any prior
    # extract dir to avoid leftovers from a previous failed run.
    $extractDir = Join-Path (Split-Path -Parent $ZipPath) 'extract'
    if (Test-Path $extractDir) {
        Remove-Item -Recurse -Force $extractDir
    }
    New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
    Expand-Archive -LiteralPath $ZipPath -DestinationPath $extractDir -Force

    # P25: Zip Slip defense-in-depth. Modern Expand-Archive is patched
    # against CVE-2018-1208-class path-traversal, but assert it ourselves
    # so a future regression OR a hand-crafted malicious zip would fail
    # loud.
    #
    # P25 follow-up (Story 7.7 hosted-runner fix): naive `StartsWith`
    # path comparison is fragile on Windows because hosted runners
    # (`runneradmin` user) can yield 8.3-short-name forms
    # (`C:\Users\RUNNER~1\AppData\Local\Temp\...`) from one cmdlet
    # and long-form (`C:\Users\runneradmin\AppData\Local\Temp\...`)
    # from another for the same path. Compare via `GetRelativePath`
    # instead: if the relative form starts with `..`, the file
    # escaped the root. This works regardless of 8.3 vs long-form
    # because .NET's GetRelativePath normalizes both inputs to a
    # canonical form before computing the relationship.
    $extractRoot = (Get-Item -LiteralPath $extractDir).FullName
    Get-ChildItem -LiteralPath $extractDir -Recurse -File | ForEach-Object {
        $resolved = $_.FullName
        $rel = [System.IO.Path]::GetRelativePath($extractRoot, $resolved)
        if ($rel.StartsWith('..') -or [System.IO.Path]::IsPathRooted($rel)) {
            Write-Err "Zip Slip detected: extracted file '$resolved' escapes '$extractRoot'. The downloaded zip is malformed or malicious."
        }
    }

    # P11: prefer agentsso.exe at the archive root (dist's documented
    # layout). Only fall back to recursive search if not found at root —
    # and even then, warn so a future dist layout change is visible.
    $rootExe = Join-Path $extractDir $script:BinName
    if (Test-Path $rootExe) {
        $exeSrc = Get-Item -LiteralPath $rootExe
    } else {
        Write-Warn "$($script:BinName) not at archive root; falling back to recursive search (dist layout may have changed)."
        $exeSrc = Get-ChildItem -Path $extractDir -Filter $script:BinName -Recurse | Select-Object -First 1
    }
    if (-not $exeSrc) {
        Write-Err "$($script:BinName) not found inside $ZipPath"
    }

    # Ensure target dir exists.
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

    Copy-Item -LiteralPath $exeSrc.FullName -Destination $exeDest -Force
    return $exeDest
}

# --- PATH mutation -----------------------------------------------------------

# Prepends $InstallDir to the user's HKCU\Environment\Path as REG_EXPAND_SZ
# and broadcasts WM_SETTINGCHANGE so File Explorer + new processes pick up
# the change without logout. Idempotent across env-var-form, expanded-form,
# and trailing-backslash variants (P3, P4). P19: preserves empty PATH
# entries (user's deliberate `;;` placeholders aren't dropped). P24:
# read-modify-write retry on race.
#
# Uses the cargo-dist installer.ps1 pattern for the registry write
# (verified primary source:
# https://github.com/axodotdev/cargo-dist/blob/main/cargo-dist/templates/installer/installer.ps1.j2).
# Three subtle bits matter: (1) 'DoNotExpandEnvironmentNames' preserves
# %var% lazy evaluation in existing PATH entries; (2) the trailing-backslash
# normalization runs only on the *comparison* side, never on the stored
# value; (3) `,$InstallDir + $current` uses the comma-operator to force
# single-element-array concatenation.
function Update-UserPath {
    param(
        [Parameter(Mandatory)] [string]$InstallDir,
        [string]$RegistryPath = 'registry::HKEY_CURRENT_USER\Environment'
    )
    # Normalize the install dir for comparison (strip trailing backslash).
    # NOT used for the stored value — we want to preserve whatever the
    # caller passed.
    $needleNormalized = $InstallDir.TrimEnd('\')
    $needleExpanded = [Environment]::ExpandEnvironmentVariables($needleNormalized).TrimEnd('\')

    # P24: retry on read-modify-write race. Bounded to 3 attempts so a
    # real outage fails the step rather than spinning forever.
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $rawCurrent = (Get-Item -LiteralPath $RegistryPath).GetValue('Path', '', 'DoNotExpandEnvironmentNames')

        # P19: preserve empty entries. Split without filtering, then
        # only de-dup the new entry against non-empty existing entries.
        $current = $rawCurrent -split ';'

        # P3 + P4: idempotency check across env-var-form, expanded-form,
        # and trailing-backslash variants. Compare each existing entry
        # (literal AND expanded, both with trailing backslash stripped)
        # against the needle in both forms.
        $alreadyPresent = $false
        foreach ($entry in $current) {
            if ([string]::IsNullOrWhiteSpace($entry)) { continue }
            $literalNorm  = $entry.TrimEnd('\')
            $expandedNorm = [Environment]::ExpandEnvironmentVariables($entry).TrimEnd('\')
            if (($literalNorm  -ieq $needleNormalized) -or
                ($expandedNorm -ieq $needleExpanded) -or
                ($literalNorm  -ieq $needleExpanded)  -or
                ($expandedNorm -ieq $needleNormalized)) {
                $alreadyPresent = $true
                break
            }
        }
        if ($alreadyPresent) {
            return $false  # no change
        }

        $new = (,$InstallDir + $current) -join ';'
        Set-ItemProperty -Type ExpandString -LiteralPath $RegistryPath -Name Path -Value $new

        # P24: re-read and verify. If another process raced us, retry.
        $verify = (Get-Item -LiteralPath $RegistryPath).GetValue('Path', '', 'DoNotExpandEnvironmentNames')
        if ($verify -eq $new) {
            # WM_SETTINGCHANGE broadcast via the dummy SetEnvironmentVariable
            # round-trip. Without this, File Explorer + new processes won't
            # see the new PATH until logout. The dummy variable name is
            # GUID-prefixed so we don't collide with anything real, and is
            # immediately deleted.
            $dummy = 'agentsso-' + [guid]::NewGuid()
            [Environment]::SetEnvironmentVariable($dummy, 'x', 'User')
            [Environment]::SetEnvironmentVariable($dummy, [NullString]::Value, 'User')
            return $true  # changed
        }
        # Race lost — another writer beat us. Loop and retry.
    }
    Write-Err "Update-UserPath: registry write raced 3 times in a row; another installer may be holding the registry. Re-run after the other install completes."
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
    # P28: validate the exe responds to `start --help` before registering.
    # If the binary doesn't have a `start` subcommand (because we shipped
    # a broken build, or the user's CLI surface drifted), every login
    # would otherwise spam a console error from the .lnk.
    try {
        # Cap the dry-run at 5 seconds to avoid hanging the installer.
        $proc = Start-Process -FilePath $ExePath -ArgumentList @('start','--help') `
            -NoNewWindow -PassThru -RedirectStandardOutput ([System.IO.Path]::GetTempFileName()) `
            -RedirectStandardError ([System.IO.Path]::GetTempFileName())
        if (-not $proc.WaitForExit(5000)) {
            $proc.Kill()
            Write-Warn "agentsso start --help did not exit within 5s; skipping autostart shortcut to avoid login-loop spam."
            return $null
        }
        if ($proc.ExitCode -ne 0) {
            Write-Warn "agentsso start --help exited $($proc.ExitCode); skipping autostart shortcut to avoid login-loop spam."
            return $null
        }
    } catch {
        Write-Warn "Could not validate agentsso start subcommand ($($_.Exception.Message)); skipping autostart shortcut."
        return $null
    }

    $startup = [Environment]::GetFolderPath('Startup')
    if (-not $startup) {
        Write-Warn "Could not resolve Startup folder; skipping autostart shortcut."
        return $null
    }
    $lnkPath = Join-Path $startup 'agentsso.lnk'

    # P12: WScript.Shell COM is unavailable on Server Core. Wrap the COM
    # creation + shortcut writing in try/catch so a failed autostart
    # registration warns rather than killing the whole install.
    try {
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
    } catch {
        Write-Warn "Could not create autostart shortcut ($($_.Exception.Message)); WScript.Shell COM may be unavailable on this host."
        return $null
    }
    return $lnkPath
}

# --- Main --------------------------------------------------------------------

function Invoke-Main {
    $start = Get-Date

    # P2: set OutputEncoding to UTF-8 so the mascot block-drawing chars
    # and ProgressSteps arrow + checkmark glyphs render correctly on
    # legacy conhost (which defaults to codepage 437/1252 on many fresh
    # Windows installs). Wrap in try/catch — some redirected hosts throw
    # when setting the encoding.
    try {
        [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
    } catch {
        # Output encoding couldn't be changed — glyphs may render as `?`
        # but installation still works.
    }

    # P26: warn if running as Administrator — install will go to admin's
    # profile, not the originating user's.
    Test-AdministratorContext

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

    # P16: assert the resolved install dir is rooted. In some service /
    # stripped-profile contexts, GetFolderPath('LocalApplicationData')
    # returns an empty string — Join-Path then yields `Programs\agentsso`
    # (relative) and we'd silently install under cwd. Fail loud instead.
    if (-not [System.IO.Path]::IsPathRooted($script:InstallDir)) {
        Write-Err ("Could not resolve a valid absolute install directory (got '$($script:InstallDir)'). " +
            "Set `$env:AGENTSSO_INSTALL_DIR explicitly to an absolute path before re-running.")
    }

    # Set up temp dir + cleanup. Use try/finally so the temp dir is
    # removed even on error. [System.IO.Path]::GetTempPath() is more
    # robust than $env:TEMP (which can be unset in service contexts).
    $tempBase = [System.IO.Path]::GetTempPath()
    $tmp = New-Item -ItemType Directory -Path (Join-Path $tempBase ([guid]::NewGuid()))
    try {
        # Step 2: Download.
        $zipPath = Get-Release -Version $resolvedVersion -Target $target -TempDir $tmp.FullName
        $sizeMB = [math]::Round((Get-Item $zipPath).Length / 1MB, 1)
        Write-StepDone -Label "downloading agentsso v$resolvedVersion" -Value "$sizeMB MB"

        # Step 3: Verify sha256.
        Test-Sha256 -ZipPath $zipPath
        Write-StepDone -Label 'verifying checksum' -Value 'sha256'

        # Step 3b: optional minisig verification (P23). Defense-in-depth
        # if minisign.exe is on PATH; silently skipped otherwise.
        if (Verify-Minisig -ZipPath $zipPath) {
            Write-StepDone -Label 'verifying signature' -Value 'ed25519 (minisign)'
        }

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
            } else {
                Write-StepDone -Label 'registering autostart' -Value 'skipped'
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
