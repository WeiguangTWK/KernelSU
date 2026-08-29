<#
.SYNOPSIS
Builds ksuinit, ksud, and a v2-signed KernelSU Manager APK on Windows.

.EXAMPLE
.\build-release.ps1 `
    -Keystore C:\keys\kernelsu-release.jks `
    -KeyAlias kernelsu-release

.EXAMPLE
.\build-release.ps1 `
    -Keystore C:\keys\kernelsu-release.jks `
    -KeyAlias kernelsu-release `
    -AndroidSdk E:\AndroidSDK `
    -OutputApk dist\KernelSU-custom.apk

.EXAMPLE
.\build-release.ps1 `
    -Keystore C:\keys\kernelsu-release.jks `
    -KeyAlias kernelsu-release `
    -ProvenanceCertificate \\wsl.localhost\Ubuntu\secure\provenance\provenance-certificate.pem `
    -ProvenancePrivateKey \\wsl.localhost\Ubuntu\secure\provenance\provenance-private-key.pem `
    -ProvenanceSecurityEpoch 1

.NOTES
The script never accepts keystore passwords as arguments. keytool and
apksigner request them interactively so they are not stored in command history.
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Keystore,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$KeyAlias,

    [string]$PackageName = "",
    [string]$AndroidSdk = "",
    [string]$NdkRoot = "",
    [string]$ProvenanceCertificate = "",
    [string]$ProvenancePrivateKey = "",
    [uint64]$ProvenanceSecurityEpoch = 0,
    [string]$ProvenanceBuildIdentity = "",
    [string]$OutputApk = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RepoRoot

function Assert-LastExitCode {
    param([Parameter(Mandatory = $true)][string]$Operation)

    if ($LASTEXITCODE -ne 0) {
        throw "$Operation failed with exit code $LASTEXITCODE"
    }
}

function Require-Command {
    param([Parameter(Mandatory = $true)][string]$Name)

    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $command) {
        throw "Required command not found: $Name"
    }
    return $command
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

function Read-LkmMetadataValue {
    param(
        [Parameter(Mandatory = $true)][string]$ModuleText,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ModulePath
    )

    $pattern = '(?:^|\x00){0}=([^\x00]*)\x00' -f [regex]::Escape($Name)
    $match = [regex]::Match($ModuleText, $pattern)
    if (-not $match.Success) {
        throw "LKM is missing metadata '$Name': $ModulePath"
    }
    return $match.Groups[1].Value
}

function Find-LkmMetadataValue {
    param(
        [Parameter(Mandatory = $true)][string]$ModuleText,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $pattern = '(?:^|\x00){0}=([^\x00]*)\x00' -f [regex]::Escape($Name)
    $match = [regex]::Match($ModuleText, $pattern)
    if ($match.Success) {
        return $match.Groups[1].Value
    }
    return $null
}

function ConvertTo-LowerHex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return -join ($Bytes | ForEach-Object { $_.ToString("x2") })
}

function Get-ProvenanceBuildIdentity {
    $temporaryIndex = Join-Path `
        ([IO.Path]::GetTempPath()) `
        ("kernelsu-build-identity-{0}.index" -f [guid]::NewGuid())
    $savedIndex = $env:GIT_INDEX_FILE
    try {
        $env:GIT_INDEX_FILE = $temporaryIndex
        & git read-tree HEAD
        Assert-LastExitCode "temporary Git index initialization"
        & git add -A -- .
        Assert-LastExitCode "source snapshot staging"
        $treeId = (& git write-tree).Trim()
        Assert-LastExitCode "source snapshot tree generation"
        if ($treeId -notmatch '^[0-9a-fA-F]{40,64}$') {
            throw "Invalid source snapshot tree ID: $treeId"
        }
    } finally {
        if ($null -eq $savedIndex) {
            Remove-Item Env:GIT_INDEX_FILE -ErrorAction SilentlyContinue
        } else {
            $env:GIT_INDEX_FILE = $savedIndex
        }
        Remove-Item $temporaryIndex -Force -ErrorAction SilentlyContinue
        Remove-Item "$temporaryIndex.lock" -Force -ErrorAction SilentlyContinue
    }

    $domain = "KSU-PROVENANCE-BUILD-IDENTITY-V1`n$($treeId.ToLowerInvariant())`n"
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha256.ComputeHash([Text.Encoding]::ASCII.GetBytes($domain))
        return ConvertTo-LowerHex -Bytes $digest
    } finally {
        $sha256.Dispose()
    }
}

function Convert-CUnsignedLiteral {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Description
    )

    if ($Value -match '^0[xX]([0-9a-fA-F]+)$') {
        return [Convert]::ToUInt32($Matches[1], 16)
    }

    $parsed = [uint32]0
    if ([uint32]::TryParse($Value, [ref]$parsed)) {
        return $parsed
    }
    throw "Invalid C unsigned literal for ${Description}: $Value"
}

function Read-RepoVersion {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $text = Get-Content $Path -Raw
    $match = [regex]::Match($text, $Pattern)
    if (-not $match.Success) {
        throw "Unable to determine $Description from $Path"
    }
    return $match.Groups[1].Value
}

function Read-GradleProperty {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $value = $null
    foreach ($line in Get-Content $Path) {
        if ($line -match ('^\s*{0}\s*=\s*(.*?)\s*$' -f [regex]::Escape($Name))) {
            $value = $Matches[1]
        }
    }
    return $value
}

Write-Host "=== Resolve build environment ==="

Require-Command git | Out-Null
Require-Command cargo | Out-Null
Require-Command rustup | Out-Null
Require-Command java | Out-Null
$KeytoolCommand = Require-Command keytool.exe

$provenanceValues = @(
    $ProvenanceCertificate,
    $ProvenancePrivateKey,
    $ProvenanceBuildIdentity
)
$ProvenanceSigningEnabled = (($provenanceValues | Where-Object {
    -not [string]::IsNullOrWhiteSpace($_)
}).Count -gt 0) -or ($ProvenanceSecurityEpoch -ne 0)
$ProvenanceCertificateKeyId = ""
if ($ProvenanceSigningEnabled) {
    if ([string]::IsNullOrWhiteSpace($ProvenanceCertificate) -or
        [string]::IsNullOrWhiteSpace($ProvenancePrivateKey) -or
        $ProvenanceSecurityEpoch -eq 0) {
        throw "Provenance signing requires -ProvenanceCertificate, -ProvenancePrivateKey, and -ProvenanceSecurityEpoch"
    }
    if (-not (Test-Path $ProvenanceCertificate -PathType Leaf)) {
        throw "Provenance certificate not found: $ProvenanceCertificate"
    }
    if (-not (Test-Path $ProvenancePrivateKey -PathType Leaf)) {
        throw "Provenance private key not found: $ProvenancePrivateKey"
    }
    $ProvenanceCertificate = (Resolve-Path $ProvenanceCertificate).Path
    $ProvenancePrivateKey = (Resolve-Path $ProvenancePrivateKey).Path
    $OpenSslCommand = Require-Command openssl

    if ([string]::IsNullOrWhiteSpace($ProvenanceBuildIdentity)) {
        $ProvenanceBuildIdentity = Get-ProvenanceBuildIdentity
    } elseif ($ProvenanceBuildIdentity -notmatch '^[0-9a-fA-F]{64}$') {
        throw "Provenance build identity must contain exactly 64 hexadecimal characters"
    } else {
        $ProvenanceBuildIdentity = $ProvenanceBuildIdentity.ToLowerInvariant()
    }

    $provenanceDer = Join-Path `
        ([IO.Path]::GetTempPath()) `
        ("kernelsu-provenance-{0}.der" -f [guid]::NewGuid())
    try {
        & $OpenSslCommand.Source x509 `
            -in $ProvenanceCertificate `
            -outform DER `
            -out $provenanceDer
        Assert-LastExitCode "provenance certificate conversion"
        $ProvenanceCertificateKeyId = (Get-FileHash $provenanceDer -Algorithm SHA256).Hash.ToLowerInvariant()
    } finally {
        Remove-Item $provenanceDer -Force -ErrorAction SilentlyContinue
    }

    Write-Host "Provenance key ID : $ProvenanceCertificateKeyId"
    Write-Host "Provenance epoch  : $ProvenanceSecurityEpoch"
    Write-Host "Provenance build  : $ProvenanceBuildIdentity"
}

$isShallow = (& git rev-parse --is-shallow-repository).Trim()
Assert-LastExitCode "Git shallow-repository check"
if ($isShallow -eq "true") {
    throw "The Git repository is shallow, which would produce an incorrect KernelSU version. Run: git fetch --unshallow --tags origin"
}

$gitCommitCountText = (& git rev-list --count HEAD).Trim()
Assert-LastExitCode "Git commit count"
$gitCommitCount = 0
if (-not [int]::TryParse($gitCommitCountText, [ref]$gitCommitCount)) {
    throw "Invalid Git commit count: $gitCommitCountText"
}
$KernelSuVersion = 30000 + $gitCommitCount
Write-Host "Git commits: $gitCommitCount"
Write-Host "KernelSU version: $KernelSuVersion"

$PackageNameSource = "-PackageName parameter"
if ([string]::IsNullOrWhiteSpace($PackageName)) {
    $ManagerGradleProperties = Join-Path $RepoRoot "manager\gradle.properties"
    $PackageName = Read-GradleProperty `
        -Path $ManagerGradleProperties `
        -Name "KSU_PACKAGE_NAME"
    if ([string]::IsNullOrWhiteSpace($PackageName)) {
        $PackageName = "me.weishu.kernelsu"
        $PackageNameSource = "built-in fallback"
    } else {
        $PackageName = $PackageName.Trim()
        $PackageNameSource = "manager\gradle.properties"
    }
}
$PackageName = $PackageName.Trim()
if ($PackageName -notmatch '^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$') {
    throw "Invalid Android package name: $PackageName"
}

$NdkVersion = Read-RepoVersion `
    -Path "$RepoRoot\manager\gradle\libs.versions.toml" `
    -Pattern 'ndk\s*=\s*"([^"]+)"' `
    -Description "NDK version"

$BuildToolsVersion = Read-RepoVersion `
    -Path "$RepoRoot\manager\build.gradle.kts" `
    -Pattern 'androidBuildToolsVersion"\]\s*=\s*"([^"]+)"' `
    -Description "Android build-tools version"

if (-not $AndroidSdk) {
    if ($env:ANDROID_SDK_ROOT) {
        $AndroidSdk = $env:ANDROID_SDK_ROOT
    } elseif ($env:ANDROID_HOME) {
        $AndroidSdk = $env:ANDROID_HOME
    }
}

if (-not $AndroidSdk -or -not (Test-Path $AndroidSdk -PathType Container)) {
    throw "Android SDK not found. Pass -AndroidSdk or set ANDROID_HOME."
}
$AndroidSdk = (Resolve-Path $AndroidSdk).Path

if (-not $NdkRoot) {
    $NdkRoot = Join-Path $AndroidSdk "ndk\$NdkVersion"
}
if (-not (Test-Path $NdkRoot -PathType Container)) {
    throw "Android NDK $NdkVersion not found: $NdkRoot"
}
$NdkRoot = (Resolve-Path $NdkRoot).Path

$LlvmRoot = Join-Path $NdkRoot "toolchains\llvm\prebuilt\windows-x86_64"
$LlvmBin = Join-Path $LlvmRoot "bin"
$LlvmStrip = Join-Path $LlvmBin "llvm-strip.exe"
$BuildTools = Join-Path $AndroidSdk "build-tools\$BuildToolsVersion"
$ZipAlign = Join-Path $BuildTools "zipalign.exe"
$ApkSigner = Join-Path $BuildTools "apksigner.bat"

foreach ($requiredPath in @(
    $LlvmBin,
    (Join-Path $LlvmBin "libclang.dll"),
    $LlvmStrip,
    $ZipAlign,
    $ApkSigner
)) {
    if (-not (Test-Path $requiredPath)) {
        throw "Required Android tool not found: $requiredPath"
    }
}

$env:ANDROID_HOME = $AndroidSdk
$env:ANDROID_SDK_ROOT = $AndroidSdk
$env:ANDROID_NDK_HOME = $NdkRoot
$env:ANDROID_NDK_ROOT = $NdkRoot
$env:LIBCLANG_PATH = $LlvmBin
$env:KSU_PACKAGE_NAME = $PackageName

$pathEntries = $env:PATH -split ";"
if (-not ($pathEntries -contains $LlvmBin)) {
    $env:PATH = "$LlvmBin;$env:PATH"
}

Write-Host "Android SDK : $AndroidSdk"
Write-Host "Android NDK : $NdkRoot"
Write-Host "Build tools: $BuildTools"
Write-Host "Package name: $PackageName ($PackageNameSource)"

Write-Host "`n=== Test module static audit ==="

& cargo test --package ksu-module-audit
Assert-LastExitCode "module static audit tests"

$requiredTargets = @(
    "aarch64-unknown-linux-musl",
    "aarch64-linux-android",
    "x86_64-linux-android"
)
$installedTargets = @(& rustup target list --installed)
Assert-LastExitCode "rustup target list"
foreach ($target in $requiredTargets) {
    if ($installedTargets -notcontains $target) {
        throw "Rust target is not installed: $target. Run: rustup target add $target"
    }
}

Write-Host "`n=== Verify release certificate against LKM files ==="

if (-not (Test-Path $Keystore -PathType Leaf)) {
    throw "Keystore not found: $Keystore"
}
$Keystore = (Resolve-Path $Keystore).Path

$CertDer = Join-Path ([IO.Path]::GetTempPath()) ("kernelsu-cert-{0}.der" -f [guid]::NewGuid())
try {
    & $KeytoolCommand.Source -exportcert -alias $KeyAlias -keystore $Keystore -file $CertDer
    Assert-LastExitCode "Certificate export"

    $CertFile = Get-Item $CertDer
    $CertHash = (Get-FileHash $CertDer -Algorithm SHA256).Hash.ToLowerInvariant()
    $CertSizeHex = "0x{0:x4}" -f $CertFile.Length
    $ManagerCertificateMaxLength = Read-DecimalCDefine `
        -Path (Join-Path $RepoRoot "kernel\manager\apk_sign.h") `
        -Name "KSU_MANAGER_CERT_MAX_LENGTH"
    if ($CertFile.Length -gt $ManagerCertificateMaxLength) {
        throw "Manager certificate is $($CertFile.Length) bytes; kernel maximum is $ManagerCertificateMaxLength bytes"
    }
    Write-Host ("Certificate size  : $CertSizeHex ({0} bytes)" -f $CertFile.Length)
    Write-Host "Certificate SHA256: $CertHash"

    $Kmis = @(
        "android12-5.10",
        "android13-5.10",
        "android13-5.15",
        "android14-5.15",
        "android14-6.1",
        "android15-6.6",
        "android16-6.12"
    )
    $LkmProvenanceEnabled = $null
    foreach ($kmi in $Kmis) {
        $modulePath = Join-Path $RepoRoot "kernel\dist\${kmi}_kernelsu.ko"
        if (-not (Test-Path $modulePath -PathType Leaf)) {
            throw "Missing LKM: $modulePath"
        }

        $moduleBytes = [IO.File]::ReadAllBytes($modulePath)
        $moduleText = [Text.Encoding]::ASCII.GetString($moduleBytes)
        $identityVersion = Read-LkmMetadataValue `
            -ModuleText $moduleText `
            -Name "ksu_manager_identity_version" `
            -ModulePath $modulePath
        if ($identityVersion -ne "1") {
            throw "Unsupported LKM Manager identity version '$identityVersion': $modulePath"
        }

        $moduleCertSizeText = Read-LkmMetadataValue `
            -ModuleText $moduleText `
            -Name "ksu_manager_cert_size" `
            -ModulePath $modulePath
        $moduleCertSize = Convert-CUnsignedLiteral `
            -Value $moduleCertSizeText `
            -Description "LKM Manager certificate size"
        if ($moduleCertSize -ne $CertFile.Length) {
            throw "LKM Manager certificate size is $moduleCertSizeText, expected ${CertSizeHex}: $modulePath"
        }

        $moduleCertHash = Read-LkmMetadataValue `
            -ModuleText $moduleText `
            -Name "ksu_manager_cert_sha256" `
            -ModulePath $modulePath
        if (-not [string]::Equals($moduleCertHash, $CertHash, [StringComparison]::OrdinalIgnoreCase)) {
            throw "LKM Manager certificate hash is $moduleCertHash, expected ${CertHash}: $modulePath"
        }

        $modulePackage = Read-LkmMetadataValue `
            -ModuleText $moduleText `
            -Name "ksu_manager_package" `
            -ModulePath $modulePath
        if (-not [string]::Equals($modulePackage, $PackageName, [StringComparison]::Ordinal)) {
            throw "LKM Manager package is $modulePackage, expected ${PackageName}: $modulePath"
        }

        $provenanceHeaderFormat = Find-LkmMetadataValue `
            -ModuleText $moduleText `
            -Name "ksu_provenance_key_header_format"
        $moduleHasProvenance = $null -ne $provenanceHeaderFormat
        if ($null -eq $LkmProvenanceEnabled) {
            $LkmProvenanceEnabled = $moduleHasProvenance
        } elseif ($LkmProvenanceEnabled -ne $moduleHasProvenance) {
            throw "LKM provenance configuration differs across KMI builds: $modulePath"
        }

        if ($moduleHasProvenance) {
            if ($provenanceHeaderFormat -ne "2") {
                throw "Unsupported LKM provenance key header format '$provenanceHeaderFormat': $modulePath"
            }
            $moduleKeyIds = (Read-LkmMetadataValue `
                -ModuleText $moduleText `
                -Name "ksu_provenance_key_ids" `
                -ModulePath $modulePath).Split(',')
            $moduleEpochTexts = (Read-LkmMetadataValue `
                -ModuleText $moduleText `
                -Name "ksu_provenance_minimum_epochs" `
                -ModulePath $modulePath).Split(',')
            if ($moduleKeyIds.Count -ne $moduleEpochTexts.Count -or $moduleKeyIds.Count -eq 0) {
                throw "Malformed LKM provenance key metadata: $modulePath"
            }
            if (-not $ProvenanceSigningEnabled) {
                throw "LKM enables provenance; supply the provenance signing parameters to build-release.ps1"
            }
            $keyIndex = [Array]::IndexOf($moduleKeyIds, $ProvenanceCertificateKeyId)
            if ($keyIndex -lt 0) {
                throw "LKM does not trust the selected provenance certificate: $modulePath"
            }
            $minimumEpoch = [uint64]0
            if (-not [uint64]::TryParse($moduleEpochTexts[$keyIndex], [ref]$minimumEpoch)) {
                throw "Invalid LKM provenance minimum epoch '$($moduleEpochTexts[$keyIndex])': $modulePath"
            }
            if ($ProvenanceSecurityEpoch -lt $minimumEpoch) {
                throw "Signing epoch $ProvenanceSecurityEpoch is below LKM minimum ${minimumEpoch}: $modulePath"
            }
        } elseif ($ProvenanceSigningEnabled) {
            throw "Provenance signing was requested but LKM provenance is disabled: $modulePath"
        }
    }
    Write-Host "All LKM files match the selected Manager and provenance configuration."
} finally {
    Remove-Item $CertDer -Force -ErrorAction SilentlyContinue
}

Write-Host "`n=== Prepare embedded LKM assets ==="

$AssetDir = Join-Path $RepoRoot "userspace\ksud\bin\aarch64"
New-Item -ItemType Directory $AssetDir -Force | Out-Null
foreach ($kmi in $Kmis) {
    Copy-Item `
        (Join-Path $RepoRoot "kernel\dist\${kmi}_kernelsu.ko") `
        (Join-Path $AssetDir "${kmi}_kernelsu.ko") `
        -Force
}

Write-Host "`n=== Build ksuinit ==="

& cargo clean --package ksuinit

$MuslLinker = Join-Path $LlvmBin "aarch64-linux-android26-clang.cmd"
$savedRustFlags = $env:RUSTFLAGS
$savedMuslLinker = $env:CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER
try {
    $env:CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER = $MuslLinker
    $env:RUSTFLAGS = "-C link-arg=-no-pie"

    & cargo build --package ksuinit --target aarch64-unknown-linux-musl --release
    Assert-LastExitCode "ksuinit build"
} finally {
    if ($null -eq $savedRustFlags) {
        Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
    } else {
        $env:RUSTFLAGS = $savedRustFlags
    }

    if ($null -eq $savedMuslLinker) {
        Remove-Item Env:CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER -ErrorAction SilentlyContinue
    } else {
        $env:CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER = $savedMuslLinker
    }
}

$Ksuinit = Join-Path $RepoRoot "target\aarch64-unknown-linux-musl\release\ksuinit"
if (-not (Test-Path $Ksuinit -PathType Leaf)) {
    throw "ksuinit output not found: $Ksuinit"
}
Copy-Item $Ksuinit (Join-Path $AssetDir "ksuinit") -Force

Write-Host "`n=== Build ksud ==="

& cargo clean --package ksud
Assert-LastExitCode "ksud clean"

$CargoNdk = Get-Command cargo-ndk -ErrorAction SilentlyContinue
if ($CargoNdk) {
    Write-Host "Using cargo-ndk: $($CargoNdk.Source)"
    & cargo ndk `
        --target arm64-v8a `
        --target x86_64 `
        --platform 26 `
        build `
        --release `
        --manifest-path "$RepoRoot\userspace\ksud\Cargo.toml"
    Assert-LastExitCode "ksud cargo-ndk build"
} else {
    Write-Warning "cargo-ndk not found; using direct NDK Clang configuration."

    $env:CC_aarch64_linux_android = Join-Path $LlvmBin "aarch64-linux-android26-clang.cmd"
    $env:CXX_aarch64_linux_android = Join-Path $LlvmBin "aarch64-linux-android26-clang++.cmd"
    $env:AR_aarch64_linux_android = Join-Path $LlvmBin "llvm-ar.exe"
    $env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = $env:CC_aarch64_linux_android
    $env:BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android = "--sysroot=$LlvmRoot\sysroot -I$LlvmRoot\sysroot\usr\include\aarch64-linux-android"

    & cargo build `
        --target aarch64-linux-android `
        --release `
        --manifest-path "$RepoRoot\userspace\ksud\Cargo.toml"
    Assert-LastExitCode "arm64 ksud build"

    $env:CC_x86_64_linux_android = Join-Path $LlvmBin "x86_64-linux-android26-clang.cmd"
    $env:CXX_x86_64_linux_android = Join-Path $LlvmBin "x86_64-linux-android26-clang++.cmd"
    $env:AR_x86_64_linux_android = Join-Path $LlvmBin "llvm-ar.exe"
    $env:CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER = $env:CC_x86_64_linux_android
    $env:BINDGEN_EXTRA_CLANG_ARGS_x86_64_linux_android = "--sysroot=$LlvmRoot\sysroot -I$LlvmRoot\sysroot\usr\include\x86_64-linux-android"

    & cargo build `
        --target x86_64-linux-android `
        --release `
        --manifest-path "$RepoRoot\userspace\ksud\Cargo.toml"
    Assert-LastExitCode "x86_64 ksud build"
}

$KsudByAbi = @{
    "arm64-v8a" = Join-Path $RepoRoot "target\aarch64-linux-android\release\ksud"
    "x86_64" = Join-Path $RepoRoot "target\x86_64-linux-android\release\ksud"
}

$JniRoot = Join-Path $RepoRoot "manager\app\src\main\jniLibs"
$ProvenanceAssetRoot = Join-Path $RepoRoot "manager\app\src\main\assets\provenance"
$PackagedKsudByAbi = @{}
$ProvenanceSidecars = @{}
foreach ($abi in $KsudByAbi.Keys) {
    $ksud = $KsudByAbi[$abi]
    if (-not (Test-Path $ksud -PathType Leaf)) {
        throw "ksud output not found: $ksud"
    }

    $abiDir = Join-Path $JniRoot $abi
    New-Item -ItemType Directory $abiDir -Force | Out-Null
    $packagedKsud = Join-Path $abiDir "libksud.so"
    Copy-Item $ksud $packagedKsud -Force
    & $LlvmStrip --strip-unneeded $packagedKsud
    Assert-LastExitCode "$abi ksud strip"
    if ((Get-Item $packagedKsud).Length -le 0) {
        throw "Stripped $abi ksud is empty: $packagedKsud"
    }
    $PackagedKsudByAbi[$abi] = $packagedKsud

    $provenanceAbiDir = Join-Path $ProvenanceAssetRoot $abi
    New-Item -ItemType Directory $provenanceAbiDir -Force | Out-Null
    $packagedSidecar = Join-Path $provenanceAbiDir "ksud.provenance"
    Remove-Item $packagedSidecar -Force -ErrorAction SilentlyContinue
    if ($ProvenanceSigningEnabled) {
        Write-Host "Signing provenance manifest for $abi"
        & cargo run --quiet --release `
            --manifest-path "$RepoRoot\userspace\ksud\Cargo.toml" `
            -- provenance-manifest sign `
            --image $packagedKsud `
            --certificate $ProvenanceCertificate `
            --private-key $ProvenancePrivateKey `
            --output $packagedSidecar `
            --build-id $ProvenanceBuildIdentity `
            --roles 1 `
            --security-epoch $ProvenanceSecurityEpoch `
            --uapi-min 1 `
            --uapi-max 1
        Assert-LastExitCode "$abi provenance signing"

        & cargo run --quiet --release `
            --manifest-path "$RepoRoot\userspace\ksud\Cargo.toml" `
            -- provenance-manifest verify `
            --image $packagedKsud `
            --certificate $ProvenanceCertificate `
            --sidecar $packagedSidecar `
            --required-role 1 `
            --minimum-security-epoch $ProvenanceSecurityEpoch
        Assert-LastExitCode "$abi provenance verification"
        if ((Get-Item $packagedSidecar).Length -ne 576) {
            throw "Unexpected $abi provenance sidecar size: $packagedSidecar"
        }
        $ProvenanceSidecars[$abi] = $packagedSidecar
    }
}

Write-Host "`n=== Build Manager release APK ==="

Push-Location (Join-Path $RepoRoot "manager")
try {
    & .\gradlew.bat clean assembleRelease "-PKSU_PACKAGE_NAME=$PackageName"
    Assert-LastExitCode "Manager release build"
} finally {
    Pop-Location
}

$UnsignedApk = Get-ChildItem `
    (Join-Path $RepoRoot "manager\app\build\outputs\apk\release\*.apk") |
    Sort-Object LastWriteTime |
    Select-Object -Last 1
if (-not $UnsignedApk) {
    throw "Manager release APK not found"
}

Write-Host "`n=== Align and sign Manager APK ==="

$DistDir = Join-Path $RepoRoot "dist"
New-Item -ItemType Directory $DistDir -Force | Out-Null
foreach ($abi in $ProvenanceSidecars.Keys) {
    Copy-Item `
        $ProvenanceSidecars[$abi] `
        (Join-Path $DistDir "ksud-${abi}.provenance") `
        -Force
}
if (-not $OutputApk) {
    $OutputApk = Join-Path $DistDir "KernelSU-release-signed.apk"
} elseif (-not [IO.Path]::IsPathRooted($OutputApk)) {
    $OutputApk = Join-Path $RepoRoot $OutputApk
}
$OutputApk = [IO.Path]::GetFullPath($OutputApk)
$OutputParent = Split-Path -Parent $OutputApk
New-Item -ItemType Directory $OutputParent -Force | Out-Null

$AlignedApk = Join-Path $DistDir "KernelSU-release-aligned.apk"
Remove-Item $AlignedApk, $OutputApk -Force -ErrorAction SilentlyContinue

& $ZipAlign -P 16 -f 4 $UnsignedApk.FullName $AlignedApk
Assert-LastExitCode "zipalign"

& $ZipAlign -c -P 16 4 $AlignedApk
Assert-LastExitCode "zipalign verification"

Write-Host "apksigner will prompt for the keystore and key passwords."
& $ApkSigner sign `
    --v1-signing-enabled false `
    --v2-signing-enabled true `
    --v3-signing-enabled false `
    --v4-signing-enabled false `
    --ks $Keystore `
    --ks-key-alias $KeyAlias `
    --out $OutputApk `
    $AlignedApk
Assert-LastExitCode "APK signing"

& $ApkSigner verify --verbose --print-certs $OutputApk
Assert-LastExitCode "APK signature verification"

if ($ProvenanceSigningEnabled) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($OutputApk)
    try {
        foreach ($abi in $ProvenanceSidecars.Keys) {
            $libEntryName = "lib/$abi/libksud.so"
            $libEntry = $archive.GetEntry($libEntryName)
            if ($null -eq $libEntry) {
                throw "Signed APK is missing ksud executable: $libEntryName"
            }
            $packagedKsud = $PackagedKsudByAbi[$abi]
            $packagedKsudSize = (Get-Item $packagedKsud).Length
            if ($libEntry.Length -ne $packagedKsudSize) {
                throw "Signed APK changed $abi ksud size ($($libEntry.Length), expected $packagedKsudSize)"
            }
            $libStream = $libEntry.Open()
            $libSha256 = [Security.Cryptography.SHA256]::Create()
            try {
                $libEntryHash = ConvertTo-LowerHex ($libSha256.ComputeHash($libStream))
            } finally {
                $libSha256.Dispose()
                $libStream.Dispose()
            }
            $packagedKsudHash = (Get-FileHash $packagedKsud -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($libEntryHash -ne $packagedKsudHash) {
                throw "Signed APK changed $abi ksud bytes: $libEntryName"
            }

            $entryName = "assets/provenance/$abi/ksud.provenance"
            $entry = $archive.GetEntry($entryName)
            if ($null -eq $entry) {
                throw "Signed APK is missing provenance sidecar: $entryName"
            }
            if ($entry.Length -ne 576) {
                throw "Signed APK provenance sidecar has wrong size ($($entry.Length)): $entryName"
            }
            $stream = $entry.Open()
            $sha256 = [Security.Cryptography.SHA256]::Create()
            try {
                $entryHash = ConvertTo-LowerHex ($sha256.ComputeHash($stream))
            } finally {
                $sha256.Dispose()
                $stream.Dispose()
            }
            $sourceHash = (Get-FileHash $ProvenanceSidecars[$abi] -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($entryHash -ne $sourceHash) {
                throw "Signed APK changed provenance sidecar bytes: $entryName"
            }
        }
    } finally {
        $archive.Dispose()
    }
}

Remove-Item $AlignedApk -Force -ErrorAction SilentlyContinue

$FinalApk = Get-Item $OutputApk
$FinalHash = (Get-FileHash $OutputApk -Algorithm SHA256).Hash
Write-Host "`n=== Release completed ==="
Write-Host "APK   : $($FinalApk.FullName)"
Write-Host "Size  : $($FinalApk.Length) bytes"
Write-Host "SHA256: $FinalHash"
if ($ProvenanceSigningEnabled) {
    Write-Host "Provenance build identity: $ProvenanceBuildIdentity"
    foreach ($abi in ($ProvenanceSidecars.Keys | Sort-Object)) {
        $sidecarOutput = Join-Path $DistDir "ksud-${abi}.provenance"
        Write-Host "Provenance $abi : $sidecarOutput"
    }
}
