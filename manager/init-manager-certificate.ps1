<#
.SYNOPSIS
Initializes a production Manager APK keystore and its KernelSU identity inputs.

.DESCRIPTION
Creates a new keystore outside the source tree, exports its public DER
certificate, computes KSU_EXPECTED_SIZE and KSU_EXPECTED_HASH, and writes
PowerShell and Bash environment files. Passwords are requested interactively
by keytool and are never accepted as script arguments or written to disk.

.EXAMPLE
.\init-manager-certificate.ps1 `
    -OutputDirectory C:\Secure\AegisSU\manager-identity `
    -KeyAlias aegissu-release `
    -PackageName org.nhsystems.privmanager
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$KeyAlias,

    [string]$PackageName = "",

    [ValidateSet("RSA", "EC")]
    [string]$KeyAlgorithm = "RSA",

    [ValidateRange(2048, 8192)]
    [int]$KeySize = 3072,

    [ValidateRange(1, 36500)]
    [int]$ValidityDays = 10000,

    [string]$DistinguishedName = "CN=AegisSU Manager, OU=Release, O=AegisSU"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = [IO.Path]::GetFullPath((Join-Path $ScriptDirectory ".."))

if ([string]::IsNullOrWhiteSpace($PackageName)) {
    $GradleProperties = Join-Path $ScriptDirectory "gradle.properties"
    if (Test-Path -LiteralPath $GradleProperties -PathType Leaf) {
        foreach ($line in Get-Content -LiteralPath $GradleProperties) {
            if ($line -match '^\s*KSU_PACKAGE_NAME\s*=\s*(.*?)\s*$') {
                $PackageName = $Matches[1]
            }
        }
    }
    if ([string]::IsNullOrWhiteSpace($PackageName)) {
        $PackageName = "me.weishu.kernelsu"
    }
}
$PackageName = $PackageName.Trim()
if ($PackageName -notmatch '^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$') {
    throw "Invalid Android package name: $PackageName"
}

function Assert-LastExitCode {
    param([Parameter(Mandatory = $true)][string]$Operation)

    if ($LASTEXITCODE -ne 0) {
        throw "$Operation failed with exit code $LASTEXITCODE"
    }
}

function Require-Command {
    param([Parameter(Mandatory = $true)][string[]]$Names)

    foreach ($name in $Names) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($command) {
            return $command
        }
    }
    throw "Required command not found: $($Names -join ' or ')"
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    $encoding = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path, $Content, $encoding)
}

function Quote-PowerShellLiteral {
    param([Parameter(Mandatory = $true)][string]$Value)
    return "'" + $Value.Replace("'", "''") + "'"
}

function Quote-ShellLiteral {
    param([Parameter(Mandatory = $true)][string]$Value)
    if ($Value.Contains("'")) {
        throw "Shell environment value contains an unsupported quote"
    }
    return "'" + $Value + "'"
}

function Read-DecimalCDefine {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $text = Get-Content -LiteralPath $Path -Raw
    $pattern = '(?m)^\s*#define\s+{0}\s+([0-9]+)\s*$' -f [regex]::Escape($Name)
    $match = [regex]::Match($text, $pattern)
    if (-not $match.Success) {
        throw "Unable to read $Name from $Path"
    }
    return [int]::Parse($match.Groups[1].Value)
}

$ManagerCertificateMaxLength = Read-DecimalCDefine `
    -Path (Join-Path $RepoRoot "kernel\manager\apk_sign.h") `
    -Name "KSU_MANAGER_CERT_MAX_LENGTH"

if ([string]::IsNullOrWhiteSpace($DistinguishedName) -or
    $DistinguishedName.Contains("`n") -or
    $DistinguishedName.Contains("`r")) {
    throw "DistinguishedName must be a nonempty single line"
}
if ([string]::IsNullOrWhiteSpace($KeyAlias) -or
    $KeyAlias.Contains("`n") -or
    $KeyAlias.Contains("`r")) {
    throw "KeyAlias must be a nonempty single line"
}
if ($KeyAlgorithm -eq "EC" -and $PSBoundParameters.ContainsKey("KeySize")) {
    throw "KeySize applies only to RSA keys"
}

$KeytoolCommand = Require-Command @("keytool.exe", "keytool")
if (-not [IO.Path]::IsPathRooted($OutputDirectory)) {
    throw "OutputDirectory must be an absolute path"
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$RepoPrefix = $RepoRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
$OutputPrefix = $OutputDirectory.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if ($OutputPrefix.StartsWith($RepoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Manager private material must be outside the source tree"
}
if (Test-Path -LiteralPath $OutputDirectory) {
    throw "Refusing to overwrite existing path: $OutputDirectory"
}

$OutputParent = Split-Path -Parent $OutputDirectory
if ([string]::IsNullOrWhiteSpace($OutputParent)) {
    throw "OutputDirectory must have a parent directory"
}
New-Item -ItemType Directory -Path $OutputParent -Force | Out-Null
$StageDirectory = Join-Path $OutputParent (".aegissu-manager-{0}" -f [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $StageDirectory | Out-Null
$Completed = $false

try {
    $KeystoreName = if ($KeyAlgorithm -eq "RSA") { "manager-release.p12" } else { "manager-release-ec.p12" }
    $StageKeystore = Join-Path $StageDirectory $KeystoreName
    $StageCertificate = Join-Path $StageDirectory "manager-certificate.der"

    Write-Host "=== Generate Manager signing identity ==="
    Write-Host "keytool will request the new keystore password interactively."
    $GenerateArguments = @(
        "-genkeypair",
        "-alias", $KeyAlias,
        "-keyalg", $KeyAlgorithm,
        "-validity", $ValidityDays.ToString(),
        "-dname", $DistinguishedName,
        "-storetype", "PKCS12",
        "-keystore", $StageKeystore
    )
    if ($KeyAlgorithm -eq "RSA") {
        $GenerateArguments += @("-keysize", $KeySize.ToString(), "-sigalg", "SHA256withRSA")
    } else {
        $GenerateArguments += @("-groupname", "secp256r1", "-sigalg", "SHA256withECDSA")
    }
    & $KeytoolCommand.Source @GenerateArguments
    Assert-LastExitCode "Manager key generation"

    Write-Host "=== Export Manager public certificate ==="
    & $KeytoolCommand.Source `
        -exportcert `
        -alias $KeyAlias `
        -keystore $StageKeystore `
        -file $StageCertificate
    Assert-LastExitCode "Manager certificate export"

    & $KeytoolCommand.Source -list -alias $KeyAlias -keystore $StageKeystore
    Assert-LastExitCode "Manager keystore verification"

    $CertificateFile = Get-Item -LiteralPath $StageCertificate
    $CertificateLength = $CertificateFile.Length
    if ($CertificateLength -gt $ManagerCertificateMaxLength) {
        throw "Manager certificate is $CertificateLength bytes; kernel maximum is $ManagerCertificateMaxLength bytes"
    }
    $CertificateSizeHex = "0x{0:x4}" -f $CertificateLength
    $CertificateHash = (Get-FileHash -LiteralPath $StageCertificate -Algorithm SHA256).Hash.ToLowerInvariant()
    $FinalKeystore = Join-Path $OutputDirectory $KeystoreName

    $PowerShellEnvironment = @(
        "`$env:KSU_EXPECTED_SIZE = $(Quote-PowerShellLiteral $CertificateSizeHex)",
        "`$env:KSU_EXPECTED_HASH = $(Quote-PowerShellLiteral $CertificateHash)",
        "`$env:KSU_MANAGER_PACKAGE = $(Quote-PowerShellLiteral $PackageName)",
        "`$KsuManagerKeystore = $(Quote-PowerShellLiteral $FinalKeystore)",
        "`$KsuManagerKeyAlias = $(Quote-PowerShellLiteral $KeyAlias)"
    ) -join [Environment]::NewLine
    Write-Utf8NoBom `
        -Path (Join-Path $StageDirectory "manager-build-env.ps1") `
        -Content ($PowerShellEnvironment + [Environment]::NewLine)

    $ShellEnvironment = @(
        "export KSU_EXPECTED_SIZE=$(Quote-ShellLiteral $CertificateSizeHex)",
        "export KSU_EXPECTED_HASH=$(Quote-ShellLiteral $CertificateHash)",
        "export KSU_MANAGER_PACKAGE=$(Quote-ShellLiteral $PackageName)"
    ) -join "`n"
    Write-Utf8NoBom `
        -Path (Join-Path $StageDirectory "manager-kernel.env") `
        -Content ($ShellEnvironment + "`n")

    $Metadata = [ordered]@{
        format_version = 1
        package_name = $PackageName
        key_alias = $KeyAlias
        key_algorithm = $KeyAlgorithm
        key_size = if ($KeyAlgorithm -eq "RSA") { $KeySize } else { $null }
        certificate_size = $CertificateLength
        certificate_size_hex = $CertificateSizeHex
        kernel_certificate_max_size = $ManagerCertificateMaxLength
        certificate_sha256 = $CertificateHash
        keystore_file = $KeystoreName
        certificate_file = "manager-certificate.der"
        created_at_utc = [DateTime]::UtcNow.ToString("o")
    }
    Write-Utf8NoBom `
        -Path (Join-Path $StageDirectory "metadata.json") `
        -Content (($Metadata | ConvertTo-Json -Depth 3) + [Environment]::NewLine)

    [IO.Directory]::Move($StageDirectory, $OutputDirectory)
    $Completed = $true

    Write-Host ""
    Write-Host "Manager certificate initialized."
    Write-Host "Output directory : $OutputDirectory"
    Write-Host "Keystore         : $FinalKeystore"
    Write-Host "Key alias        : $KeyAlias"
    Write-Host "Package          : $PackageName"
    Write-Host "Certificate size : $CertificateSizeHex ($CertificateLength bytes)"
    Write-Host "Certificate hash : $CertificateHash"
    Write-Host ""
    Write-Host "For PowerShell release builds:"
    Write-Host ". '$OutputDirectory\manager-build-env.ps1'"
    $BuildReleaseScript = Join-Path $RepoRoot "build-release.ps1"
    Write-Host "& '$BuildReleaseScript' -Keystore `$KsuManagerKeystore -KeyAlias `$KsuManagerKeyAlias -PackageName `$env:KSU_MANAGER_PACKAGE"
    Write-Host ""
    Write-Host "For WSL kernel builds, source manager-kernel.env first."
} finally {
    if (-not $Completed -and (Test-Path -LiteralPath $StageDirectory)) {
        Remove-Item -LiteralPath $StageDirectory -Recurse -Force
    }
}
