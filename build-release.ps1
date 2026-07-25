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

    [string]$PackageName = "me.weishu.kernelsu",
    [string]$AndroidSdk = "",
    [string]$NdkRoot = "",
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

function Test-ByteSequence {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Data,
        [Parameter(Mandatory = $true)][byte[]]$Needle
    )

    if ($Needle.Length -eq 0 -or $Data.Length -lt $Needle.Length) {
        return $false
    }

    $lastStart = $Data.Length - $Needle.Length
    for ($i = 0; $i -le $lastStart; $i++) {
        if ($Data[$i] -ne $Needle[0]) {
            continue
        }

        $matched = $true
        for ($j = 1; $j -lt $Needle.Length; $j++) {
            if ($Data[$i + $j] -ne $Needle[$j]) {
                $matched = $false
                break
            }
        }

        if ($matched) {
            return $true
        }
    }

    return $false
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

Write-Host "=== Resolve build environment ==="

Require-Command git | Out-Null
Require-Command cargo | Out-Null
Require-Command rustup | Out-Null
Require-Command java | Out-Null
$KeytoolCommand = Require-Command keytool.exe

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
$BuildTools = Join-Path $AndroidSdk "build-tools\$BuildToolsVersion"
$ZipAlign = Join-Path $BuildTools "zipalign.exe"
$ApkSigner = Join-Path $BuildTools "apksigner.bat"

foreach ($requiredPath in @(
    $LlvmBin,
    (Join-Path $LlvmBin "libclang.dll"),
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
Write-Host "Package name: $PackageName"

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
    Write-Host ("Certificate size  : 0x{0:x4} ({0} bytes)" -f $CertFile.Length)
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
    $CertHashBytes = [Text.Encoding]::ASCII.GetBytes($CertHash)
    foreach ($kmi in $Kmis) {
        $modulePath = Join-Path $RepoRoot "kernel\dist\${kmi}_kernelsu.ko"
        if (-not (Test-Path $modulePath -PathType Leaf)) {
            throw "Missing LKM: $modulePath"
        }

        $moduleBytes = [IO.File]::ReadAllBytes($modulePath)
        if (-not (Test-ByteSequence -Data $moduleBytes -Needle $CertHashBytes)) {
            throw "LKM does not contain the selected certificate hash: $modulePath"
        }
    }
    Write-Host "All LKM files recognize the selected certificate."
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
foreach ($abi in $KsudByAbi.Keys) {
    $ksud = $KsudByAbi[$abi]
    if (-not (Test-Path $ksud -PathType Leaf)) {
        throw "ksud output not found: $ksud"
    }

    $abiDir = Join-Path $JniRoot $abi
    New-Item -ItemType Directory $abiDir -Force | Out-Null
    Copy-Item $ksud (Join-Path $abiDir "libksud.so") -Force
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

Remove-Item $AlignedApk -Force -ErrorAction SilentlyContinue

$FinalApk = Get-Item $OutputApk
$FinalHash = (Get-FileHash $OutputApk -Algorithm SHA256).Hash
Write-Host "`n=== Release completed ==="
Write-Host "APK   : $($FinalApk.FullName)"
Write-Host "Size  : $($FinalApk.Length) bytes"
Write-Host "SHA256: $FinalHash"
