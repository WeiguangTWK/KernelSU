package me.weishu.kernelsu.ui.util

import android.content.ContentResolver
import android.content.Context
import android.database.Cursor
import android.net.Uri
import android.os.Environment
import android.os.Parcelable
import android.os.SystemClock
import android.provider.OpenableColumns
import android.system.Os
import android.util.Log
import com.topjohnwu.superuser.CallbackList
import com.topjohnwu.superuser.Shell
import com.topjohnwu.superuser.ShellUtils
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.parcelize.Parcelize
import me.weishu.kernelsu.BuildConfig
import me.weishu.kernelsu.Natives
import me.weishu.kernelsu.ksuApp
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.Executor
import java.util.UUID

/**
 * @author weishu
 * @date 2023/1/1.
 */
private const val TAG = "KsuCli"

private fun getKsuDaemonPath(): String {
    return ksuApp.applicationInfo.nativeLibraryDir + File.separator + "libksud.so"
}

data class FlashResult(val code: Int, val err: String, val showReboot: Boolean) {
    constructor(result: Shell.Result, showReboot: Boolean) : this(result.code, result.err.joinToString("\n"), showReboot)
    constructor(result: Shell.Result) : this(result, result.isSuccess)
}

object KsuCli {
    val SHELL: Shell = createRootShell()
    val GLOBAL_MNT_SHELL: Shell = createRootShell(true)
}

fun getRootShell(globalMnt: Boolean = false): Shell {
    return if (globalMnt) KsuCli.GLOBAL_MNT_SHELL else {
        KsuCli.SHELL
    }
}

inline fun <T> withNewRootShell(
    globalMnt: Boolean = false,
    block: Shell.() -> T
): T {
    return createRootShell(globalMnt).use(block)
}

fun Uri.getFileName(context: Context): String? {
    var fileName: String? = null
    val contentResolver: ContentResolver = context.contentResolver
    val cursor: Cursor? = contentResolver.query(this, null, null, null, null)
    cursor?.use {
        if (it.moveToFirst()) {
            fileName = it.getString(it.getColumnIndexOrThrow(OpenableColumns.DISPLAY_NAME))
        }
    }
    return fileName
}

fun createRootShell(globalMnt: Boolean = false): Shell {
    Shell.enableVerboseLogging = BuildConfig.DEBUG
    val builder = Shell.Builder.create()
    return try {
        if (globalMnt) {
            builder.build(getKsuDaemonPath(), "debug", "su", "-g")
        } else {
            builder.build(getKsuDaemonPath(), "debug", "su")
        }
    } catch (e: Throwable) {
        Log.w(TAG, "ksu failed: ", e)
        try {
            if (globalMnt) {
                builder.build("su", "-mm")
            } else {
                builder.build("su")
            }
        } catch (e: Throwable) {
            Log.e(TAG, "su failed: ", e)
            builder.build("sh")
        }
    }
}

fun execKsud(args: String, newShell: Boolean = false, globalMnt: Boolean = false): Boolean {
    return if (newShell) {
        withNewRootShell(globalMnt = globalMnt) {
            ShellUtils.fastCmdResult(this, "${getKsuDaemonPath()} $args")
        }
    } else {
        ShellUtils.fastCmdResult(getRootShell(globalMnt), "${getKsuDaemonPath()} $args")
    }
}

suspend fun beginAuditInstallSession(timeoutSeconds: Int = 180): String = withContext(Dispatchers.IO) {
    require(timeoutSeconds in 1..600) { "Invalid audit installation session timeout" }
    val id = UUID.randomUUID().toString().replace("-", "")
    check(execKsud("audit-install-session begin $id --timeout-seconds $timeoutSeconds", newShell = true)) {
        "Unable to start the audit installation session"
    }
    repeat(100) {
        val stdout = ArrayList<String>()
        val stderr = ArrayList<String>()
        val result = getRootShell().newJob()
            .add("${getKsuDaemonPath()} audit-install-session status $id")
            .to(stdout, stderr)
            .exec()
        if (result.isSuccess) {
            val status = stdout.firstOrNull()?.let { JSONObject(it) }
            val error = status
                ?.takeUnless { it.isNull("error") }
                ?.optString("error")
                ?.takeIf(String::isNotBlank)
            if (error != null) {
                runCatching { releaseAuditInstallSession(id) }
                throw IllegalStateException(error)
            }
            if (status?.optBoolean("ready") == true) return@withContext id
        }
        delay(100)
    }
    error("Timed out waiting for the audit installation session")
}

suspend fun releaseAuditInstallSession(id: String) = withContext(Dispatchers.IO) {
    check(id.length == 32 && id.all { it in '0'..'9' || it in 'a'..'f' }) {
        "Invalid audit installation session id"
    }
    check(execKsud("audit-install-session release $id", newShell = true)) {
        "Unable to release the audit installation session"
    }
}

suspend fun getFeatureStatus(feature: String): String = withContext(Dispatchers.IO) {
    val shell = getRootShell()
    val out = shell.newJob()
        .add("${getKsuDaemonPath()} feature check $feature").to(ArrayList<String>(), null).exec().out
    out.firstOrNull()?.trim().orEmpty()
}

suspend fun getFeaturePersistValue(feature: String): Long? = withContext(Dispatchers.IO) {
    val shell = getRootShell()
    val out = shell.newJob()
        .add("${getKsuDaemonPath()} feature get --config $feature").to(ArrayList<String>(), null).exec().out
    val valueLine = out.firstOrNull { it.trim().startsWith("Value:") } ?: return@withContext null
    valueLine.substringAfter("Value:").trim().toLongOrNull()
}

fun install() {
    val start = SystemClock.elapsedRealtime()
    val libadbroot = File(ksuApp.applicationInfo.nativeLibraryDir, "libadbroot.so").absolutePath
    val result = execKsud("install --libadbroot $libadbroot --data-path ${ksuApp.applicationInfo.deviceProtectedDataDir}", true)
    Log.w(TAG, "install result: $result, cost: ${SystemClock.elapsedRealtime() - start}ms")
}

fun listModules(): String {
    val shell = getRootShell()

    val out = shell.newJob()
        .add("${getKsuDaemonPath()} module list").to(ArrayList(), null).exec().out
    return out.joinToString("\n").ifBlank { "[]" }
}

suspend fun getModuleAuditHistories(): String = withContext(Dispatchers.IO) {
    val stdout = ArrayList<String>()
    val stderr = ArrayList<String>()
    val result = getRootShell().newJob()
        .add("${getKsuDaemonPath()} module audit-history --json")
        .to(stdout, stderr)
        .exec()
    check(result.isSuccess) {
        stderr.joinToString("\n").ifBlank { "Unable to read module audit history" }
    }
    stdout.joinToString("\n").ifBlank { "[]" }
}

suspend fun getGlobalAuditHistory(): String = withContext(Dispatchers.IO) {
    val stdout = ArrayList<String>()
    val stderr = ArrayList<String>()
    val result = getRootShell().newJob()
        .add("${getKsuDaemonPath()} global-audit history")
        .to(stdout, stderr)
        .exec()
    check(result.isSuccess) {
        stderr.joinToString("\n").ifBlank { "Unable to read global audit history" }
    }
    stdout.joinToString("\n").ifBlank { "{}" }
}

suspend fun getGlobalAuditStatus(): String = withContext(Dispatchers.IO) {
    val stdout = ArrayList<String>()
    val stderr = ArrayList<String>()
    val result = getRootShell().newJob()
        .add("${getKsuDaemonPath()} global-audit status")
        .to(stdout, stderr)
        .exec()
    check(result.isSuccess) {
        stderr.joinToString("\n").ifBlank { "Unable to read global audit status" }
    }
    stdout.joinToString("\n").also { check(it.isNotBlank()) }
}

suspend fun getGlobalAuditRevision(): String = withContext(Dispatchers.IO) {
    val stdout = ArrayList<String>()
    val stderr = ArrayList<String>()
    val result = getRootShell().newJob()
        .add("${getKsuDaemonPath()} global-audit store-revision")
        .to(stdout, stderr)
        .exec()
    check(result.isSuccess) {
        stderr.joinToString("\n").ifBlank { "Unable to read global audit revision" }
    }
    stdout.firstOrNull()?.trim().also { check(!it.isNullOrBlank()) } ?: ""
}

suspend fun waitForGlobalAuditChange(baseline: String): Boolean = withContext(Dispatchers.IO) {
    check(baseline.length == 64 && baseline.all { it.isLowerHexDigit() }) {
        "Invalid global audit dashboard revision"
    }
    val stdout = ArrayList<String>()
    val stderr = ArrayList<String>()
    val result = withNewRootShell {
        newJob()
            .add(
                "${getKsuDaemonPath()} global-audit watch " +
                    "--baseline $baseline --timeout-seconds 30"
            )
            .to(stdout, stderr)
            .exec()
    }
    check(result.isSuccess) {
        stderr.joinToString("\n").ifBlank { "Unable to watch global audit state" }
    }
    stdout.any { line ->
        runCatching { JSONObject(line).optString("type") == "changed" }.getOrDefault(false)
    }
}

suspend fun streamModuleAuditDashboard(
    installSession: String? = null,
    onLine: (String) -> Unit,
): Unit =
    withContext(Dispatchers.IO) {
        check(
            installSession == null ||
                (installSession.length == 32 && installSession.all { it.isLowerHexDigit() })
        ) { "Invalid audit installation session id" }
        val stderr = ArrayList<String>()
        val stdout = object : CallbackList<String?>(Executor { command -> command.run() }) {
            override fun onAddElement(value: String?) {
                value?.takeIf(String::isNotBlank)?.let(onLine)
            }
        }
        val result = withNewRootShell {
            newJob()
                .add(
                    "${getKsuDaemonPath()} module audit-dashboard" +
                        (installSession?.let { " --install-session $it" } ?: "")
                )
                .to(stdout, stderr)
                .exec()
        }
        check(result.isSuccess) {
            stderr.joinToString("\n").ifBlank { "Unable to refresh module audit dashboard" }
        }
    }

suspend fun getModuleAuditStatuses(): String = withContext(Dispatchers.IO) {
    runModuleAuditCommand(
        "audit-status --json",
        "Unable to read module audit status",
    )
}

suspend fun getModuleAuditCheckpoint(): String = withContext(Dispatchers.IO) {
    val stdout = ArrayList<String>()
    val stderr = ArrayList<String>()
    val result = getRootShell().newJob()
        .add("${getKsuDaemonPath()} module audit-checkpoint")
        .to(stdout, stderr)
        .exec()
    check(result.isSuccess) {
        stderr.joinToString("\n").ifBlank { "Unable to read module audit checkpoint" }
    }
    stdout.joinToString("\n").also { check(it.isNotBlank()) }
}

suspend fun getModuleAuditAuthorizationStatus(): String = withContext(Dispatchers.IO) {
    runModuleAuditCommand(
        "audit-auth status",
        "Unable to read Manager audit authorization status",
    )
}

suspend fun registerModuleAuditAuthorizationKey(
    publicKeyHex: String,
    recover: Boolean,
): String = withContext(Dispatchers.IO) {
    check(publicKeyHex.length == 130 && publicKeyHex.all { it.isLowerHexDigit() }) {
        "Invalid Manager audit authorization public key"
    }
    val operation = if (recover) "recover" else "register"
    runModuleAuditCommand(
        "audit-auth $operation --public-key $publicKeyHex",
        "Unable to register Manager audit authorization key",
    )
}

suspend fun getModuleAuditAuthorizationChallenge(action: String, moduleId: String? = null): String =
    withContext(Dispatchers.IO) {
        check(
            action == "rescan" || action == "prune" || action == "secure-remove" ||
                action == "recover-sealed"
        ) {
            "Unsupported audit authorization action"
        }
        check(moduleId == null || moduleId.matches(Regex("^[A-Za-z][A-Za-z0-9._-]+$"))) {
            "Invalid module id"
        }
        check((action == "secure-remove" || action == "recover-sealed") == (moduleId != null)) {
            "Module-specific audit authorization must target exactly one module"
        }
        runModuleAuditCommand(
            "audit-auth challenge $action" + (moduleId?.let { " --id $it" } ?: ""),
            "Unable to obtain Manager audit authorization challenge",
        )
    }

suspend fun getModuleAuditRecoveryStatus(): String = withContext(Dispatchers.IO) {
    runModuleAuditCommand(
        "audit-recovery-status --json",
        "Unable to diagnose Manager-sealed audit history",
    )
}

suspend fun recoverManagerSealedAudit(moduleId: String, authorization: String): String =
    withContext(Dispatchers.IO) {
        check(moduleId.matches(Regex("^[A-Za-z][A-Za-z0-9._-]+$"))) { "Invalid module id" }
        check(authorization.isNotEmpty() && authorization.all { it.isLowerHexDigit() }) {
            "Invalid Manager audit authorization token"
        }
        runModuleAuditCommand(
            "audit-recover-sealed $moduleId --json --authorization $authorization",
            "Unable to recover Manager-sealed audit history",
        )
    }

suspend fun getModuleAuditSealStatus(): String = withContext(Dispatchers.IO) {
    runModuleAuditCommand(
        "audit-seal status",
        "Unable to read Manager audit seal status",
    )
}

suspend fun commitModuleAuditSeal(envelopeHex: String): String = withContext(Dispatchers.IO) {
    check(envelopeHex.isNotEmpty() && envelopeHex.all { it.isLowerHexDigit() }) {
        "Invalid Manager audit seal envelope"
    }
    val input = File.createTempFile("module-audit-seal-", ".hex", ksuApp.cacheDir)
    try {
        input.writeText(envelopeHex, Charsets.US_ASCII)
        check(input.absolutePath.all { it.isLetterOrDigit() || it in "/._-" }) {
            "Unsafe Manager audit seal path"
        }
        runModuleAuditCommand(
            "audit-seal commit --file ${input.absolutePath}",
            "Unable to commit Manager audit seal",
        )
    } finally {
        input.delete()
    }
}

suspend fun rescanInstalledModules(authorization: String): String = withContext(Dispatchers.IO) {
    check(authorization.isNotEmpty() && authorization.all { it.isLowerHexDigit() }) {
        "Invalid Manager audit authorization token"
    }
    val stdout = ArrayList<String>()
    val stderr = ArrayList<String>()
    val result = getRootShell().newJob()
        .add(
            "${getKsuDaemonPath()} module audit-rescan --json " +
                "--authorization $authorization"
        )
        .to(stdout, stderr)
        .exec()
    check(result.isSuccess) {
        stderr.joinToString("\n").ifBlank { "Unable to rescan installed modules" }
    }
    stdout.joinToString("\n").ifBlank { "[]" }
}

suspend fun getStaleModuleAuditHistories(): String = withContext(Dispatchers.IO) {
    val stdout = ArrayList<String>()
    val stderr = ArrayList<String>()
    val result = getRootShell().newJob()
        .add("${getKsuDaemonPath()} module audit-prune --dry-run --json")
        .to(stdout, stderr)
        .exec()
    check(result.isSuccess) {
        stderr.joinToString("\n").ifBlank { "Unable to list stale module audit histories" }
    }
    stdout.joinToString("\n").ifBlank { "[]" }
}

suspend fun pruneStaleModuleAuditHistories(authorization: String): String =
    withContext(Dispatchers.IO) {
        check(authorization.isNotEmpty() && authorization.all { it.isLowerHexDigit() }) {
            "Invalid Manager audit authorization token"
        }
        val stdout = ArrayList<String>()
        val stderr = ArrayList<String>()
        val result = getRootShell().newJob()
            .add(
                "${getKsuDaemonPath()} module audit-prune --json " +
                    "--authorization $authorization"
            )
            .to(stdout, stderr)
            .exec()
        check(result.isSuccess) {
            stderr.joinToString("\n").ifBlank { "Unable to clear stale module audit histories" }
        }
        stdout.joinToString("\n").ifBlank { "[]" }
    }

suspend fun containModuleForSecureRemoval(moduleId: String): String = withContext(Dispatchers.IO) {
    check(moduleId.matches(Regex("^[A-Za-z][A-Za-z0-9._-]+$"))) { "Invalid module id" }
    runModuleAuditCommand(
        "audit-contain $moduleId",
        "Unable to contain untrusted module",
    )
}

suspend fun securelyRemoveModule(moduleId: String, authorization: String): String =
    withContext(Dispatchers.IO) {
        check(moduleId.matches(Regex("^[A-Za-z][A-Za-z0-9._-]+$"))) { "Invalid module id" }
        check(authorization.isNotEmpty() && authorization.all { it.isLowerHexDigit() }) {
            "Invalid Manager audit authorization token"
        }
        runModuleAuditCommand(
            "audit-secure-remove $moduleId --json --authorization $authorization",
            "Unable to securely remove untrusted module",
        )
    }

suspend fun getModuleAuditResponseStatus(): String = withContext(Dispatchers.IO) {
    runModuleAuditCommand(
        "audit-response-status",
        "Unable to read module audit response prerequisites",
    )
}

private fun runModuleAuditCommand(command: String, fallbackError: String): String {
    val stdout = ArrayList<String>()
    val stderr = ArrayList<String>()
    val result = getRootShell().newJob()
        .add("${getKsuDaemonPath()} module $command")
        .to(stdout, stderr)
        .exec()
    check(result.isSuccess) { stderr.joinToString("\n").ifBlank { fallbackError } }
    return stdout.joinToString("\n").also { check(it.isNotBlank()) }
}

private fun Char.isLowerHexDigit(): Boolean = this in '0'..'9' || this in 'a'..'f'

fun getModuleCount(): Int {
    val result = listModules()
    runCatching {
        val array = JSONArray(result)
        return array.length()
    }.getOrElse { return 0 }
}

fun getSuperuserCount(): Int {
    return Natives.getSuperuserCount()
}

fun toggleModule(id: String, enable: Boolean): Boolean {
    val cmd = if (enable) {
        "module enable $id"
    } else {
        "module disable $id"
    }
    val result = execKsud(cmd, true)
    Log.i(TAG, "$cmd result: $result")
    return result
}

fun undoUninstallModule(id: String): Boolean {
    val cmd = "module undo-uninstall $id"
    val result = execKsud(cmd, true)
    Log.i(TAG, "undo uninstall module $id result: $result")
    return result
}

fun uninstallModule(id: String): Boolean {
    val cmd = "module uninstall $id"
    val result = execKsud(cmd, true)
    Log.i(TAG, "uninstall module $id result: $result")
    return result
}

private fun flashWithIO(
    cmd: String,
    onStdout: (String) -> Unit,
    onStderr: (String) -> Unit
): Shell.Result {

    val stdoutCallback: CallbackList<String?> = object : CallbackList<String?>() {
        override fun onAddElement(s: String?) {
            onStdout(s ?: "")
        }
    }

    val stderrCallback: CallbackList<String?> = object : CallbackList<String?>() {
        override fun onAddElement(s: String?) {
            onStderr(s ?: "")
        }
    }

    return withNewRootShell {
        newJob().add(cmd).to(stdoutCallback, stderrCallback).exec()
    }
}

fun flashModule(
    uri: Uri,
    onStdout: (String) -> Unit,
    onStderr: (String) -> Unit
): FlashResult {
    val resolver = ksuApp.contentResolver
    with(resolver.openInputStream(uri)) {
        val file = File(ksuApp.cacheDir, "module.zip")
        file.outputStream().use { output ->
            this?.copyTo(output)
        }
        val cmd = "module install ${file.absolutePath}"
        val result = flashWithIO("${getKsuDaemonPath()} $cmd", onStdout, onStderr)
        Log.i("KernelSU", "install module $uri result: $result")

        file.delete()

        return FlashResult(result)
    }
}

fun runModuleAction(
    moduleId: String, onStdout: (String) -> Unit, onStderr: (String) -> Unit
): Boolean {
    val stdoutCallback: CallbackList<String?> = object : CallbackList<String?>() {
        override fun onAddElement(s: String?) {
            onStdout(s ?: "")
        }
    }

    val stderrCallback: CallbackList<String?> = object : CallbackList<String?>() {
        override fun onAddElement(s: String?) {
            onStderr(s ?: "")
        }
    }

    val result = withNewRootShell(true) {
        newJob().add("${getKsuDaemonPath()} module action $moduleId")
            .to(stdoutCallback, stderrCallback).exec()
    }

    Log.i("KernelSU", "Module runAction result: $result")

    return result.isSuccess
}

fun restoreBoot(
    onStdout: (String) -> Unit, onStderr: (String) -> Unit
): FlashResult {
    val result = flashWithIO("${getKsuDaemonPath()} boot-restore -f", onStdout, onStderr)
    return FlashResult(result)
}

fun uninstallPermanently(
    onStdout: (String) -> Unit, onStderr: (String) -> Unit
): FlashResult {
    val result = flashWithIO("${getKsuDaemonPath()} uninstall --package-name ${BuildConfig.APPLICATION_ID}", onStdout, onStderr)
    return FlashResult(result)
}

@Parcelize
sealed class LkmSelection : Parcelable {
    @Parcelize
    data class LkmUri(val uri: Uri) : LkmSelection()

    @Parcelize
    data class KmiString(val value: String) : LkmSelection()

    @Parcelize
    data object KmiNone : LkmSelection()
}

fun installBoot(
    bootUri: Uri?,
    lkm: LkmSelection,
    ota: Boolean,
    partition: String?,
    allowShell: Boolean,
    enableAdb: Boolean,
    forceBackup: Boolean,
    onStdout: (String) -> Unit,
    onStderr: (String) -> Unit,
): FlashResult {
    val resolver = ksuApp.contentResolver

    val bootFile = bootUri?.let { uri ->
        with(resolver.openInputStream(uri)) {
            val bootFile = File(ksuApp.cacheDir, "boot.img")
            bootFile.outputStream().use { output ->
                this?.copyTo(output)
            }

            bootFile
        }
    }

    var cmd = "boot-patch"

    cmd += if (bootFile == null) {
        // no boot.img, use -f to flash
        " -f"
    } else {
        " -b ${bootFile.absolutePath}"
    }

    if (allowShell) {
        cmd += " --allow-shell"
    }

    if (enableAdb) {
        cmd += " --enable-adbd"
    }

    if (ota) {
        cmd += " -u"
    }

    if (forceBackup) {
        cmd += " --backup"
    }

    var lkmFile: File? = null
    when (lkm) {
        is LkmSelection.LkmUri -> {
            lkmFile = with(resolver.openInputStream(lkm.uri)) {
                val file = File(ksuApp.cacheDir, "kernelsu-tmp-lkm.ko")
                file.outputStream().use { output ->
                    this?.copyTo(output)
                }

                file
            }
            cmd += " -m ${lkmFile.absolutePath}"
        }

        is LkmSelection.KmiString -> {
            cmd += " --kmi ${lkm.value}"
        }

        LkmSelection.KmiNone -> {
            // do nothing
        }
    }

    // output dir
    if (bootFile != null) {
        val downloadsDir =
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        cmd += " -o $downloadsDir"
    }

    partition?.let { part ->
        cmd += " --partition $part"
    }

    val result = flashWithIO("${getKsuDaemonPath()} $cmd", onStdout, onStderr)
    Log.i("KernelSU", "install boot result: ${result.isSuccess}")

    bootFile?.delete()
    lkmFile?.delete()

    // if boot uri is empty, it is direct install, when success, we should show reboot button
    val showReboot = bootUri == null && result.isSuccess // we create a temporary val here, to avoid calc showReboot double
    if (showReboot) { // because we decide do not update ksud when startActivity
        install() // install ksud here
    }
    return FlashResult(result, showReboot)
}

fun reboot(reason: String = "") {
    if (reason == "soft_reboot") {
        execKsud("soft-reboot", true, true)
        return
    }
    val shell = getRootShell()
    if (reason == "recovery") {
        // KEYCODE_POWER = 26, hide incorrect "Factory data reset" message
        ShellUtils.fastCmd(shell, "/system/bin/input keyevent 26")
    }
    ShellUtils.fastCmd(shell, "/system/bin/svc power reboot $reason || /system/bin/reboot $reason")
}

fun rootAvailable(): Boolean {
    val shell = getRootShell()
    return shell.isRoot
}

suspend fun getCurrentKmi(): String = withContext(Dispatchers.IO) {
    val shell = getRootShell()
    val cmd = "boot-info current-kmi"
    ShellUtils.fastCmd(shell, "${getKsuDaemonPath()} $cmd")
}

suspend fun getSupportedKmis(): List<String> = withContext(Dispatchers.IO) {
    val shell = getRootShell()
    val cmd = "boot-info supported-kmis"
    val out = shell.newJob().add("${getKsuDaemonPath()} $cmd").to(ArrayList(), null).exec().out
    out.filter { it.isNotBlank() }.map { it.trim() }
}

suspend fun isAbDevice(): Boolean = withContext(Dispatchers.IO) {
    val shell = getRootShell()
    val cmd = "boot-info is-ab-device"
    ShellUtils.fastCmd(shell, "${getKsuDaemonPath()} $cmd").trim().toBoolean()
}

suspend fun getDefaultPartition(): String = withContext(Dispatchers.IO) {
    val shell = getRootShell()
    if (shell.isRoot) {
        val cmd = "boot-info default-partition"
        ShellUtils.fastCmd(shell, "${getKsuDaemonPath()} $cmd").trim()
    } else {
        if (!Os.uname().release.contains("android12-")) "init_boot" else "boot"
    }
}

suspend fun getSlotSuffix(ota: Boolean): String = withContext(Dispatchers.IO) {
    val shell = getRootShell()
    val cmd = if (ota) {
        "boot-info slot-suffix --ota"
    } else {
        "boot-info slot-suffix"
    }
    ShellUtils.fastCmd(shell, "${getKsuDaemonPath()} $cmd").trim()
}

suspend fun getAvailablePartitions(): List<String> = withContext(Dispatchers.IO) {
    val shell = getRootShell()
    val cmd = "boot-info available-partitions"
    val out = shell.newJob().add("${getKsuDaemonPath()} $cmd").to(ArrayList(), null).exec().out
    out.filter { it.isNotBlank() }.map { it.trim() }
}

fun hasMagisk(): Boolean {
    val shell = getRootShell(true)
    val result = shell.newJob().add("which magisk").exec()
    Log.i(TAG, "has magisk: ${result.isSuccess}")
    return result.isSuccess
}

fun isSepolicyValid(rules: String?): Boolean {
    if (rules == null) {
        return true
    }
    val shell = getRootShell()
    val result =
        shell.newJob().add("${getKsuDaemonPath()} sepolicy check '$rules'").to(ArrayList(), null)
            .exec()
    return result.isSuccess
}

fun getSepolicy(pkg: String): String {
    val shell = getRootShell()
    val result =
        shell.newJob().add("${getKsuDaemonPath()} profile get-sepolicy $pkg").to(ArrayList(), null)
            .exec()
    Log.i(TAG, "code: ${result.code}, out: ${result.out}, err: ${result.err}")
    return result.out.joinToString("\n")
}

fun setSepolicy(pkg: String, rules: String): Boolean {
    val shell = getRootShell()
    val result = shell.newJob().add("${getKsuDaemonPath()} profile set-sepolicy $pkg '$rules'")
        .to(ArrayList(), null).exec()
    Log.i(TAG, "set sepolicy result: ${result.code}")
    return result.isSuccess
}

fun listAppProfileTemplates(): List<String> {
    val shell = getRootShell()
    return shell.newJob().add("${getKsuDaemonPath()} profile list-templates").to(ArrayList(), null)
        .exec().out
}

fun getAppProfileTemplate(id: String): String {
    val shell = getRootShell()
    return shell.newJob().add("${getKsuDaemonPath()} profile get-template '${id}'")
        .to(ArrayList(), null).exec().out.joinToString("\n")
}

fun setAppProfileTemplate(id: String, template: String): Boolean {
    val shell = getRootShell()
    val escapedTemplate = template.replace("'", "'\\''")
    val cmd = """${getKsuDaemonPath()} profile set-template "$id" '$escapedTemplate'"""
    return shell.newJob().add(cmd)
        .to(ArrayList(), null).exec().isSuccess
}

fun deleteAppProfileTemplate(id: String): Boolean {
    val shell = getRootShell()
    return shell.newJob().add("${getKsuDaemonPath()} profile delete-template '${id}'")
        .to(ArrayList(), null).exec().isSuccess
}

fun forceStopApp(packageName: String, userId: Int? = null) {
    val shell = getRootShell()
    val userArg = userId?.let { " --user $it" } ?: ""
    val result = shell.newJob().add("am force-stop$userArg $packageName").exec()
    Log.i(TAG, "force stop $packageName result: $result")
}

fun launchApp(packageName: String, userId: Int? = null) {
    val shell = getRootShell()
    val userArg = userId?.let { " --user $it" } ?: ""
    val result =
        shell.newJob()
            .add("cmd package resolve-activity --brief$userArg $packageName | tail -n 1 | xargs cmd activity start-activity$userArg -n")
            .exec()
    Log.i(TAG, "launch $packageName result: $result")
}

fun restartApp(packageName: String, userId: Int? = null) {
    forceStopApp(packageName, userId)
    launchApp(packageName, userId)
}
