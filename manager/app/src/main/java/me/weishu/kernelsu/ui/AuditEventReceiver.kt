package me.weishu.kernelsu.ui

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.UserManager
import androidx.core.app.NotificationCompat
import me.weishu.kernelsu.R
import me.weishu.kernelsu.ksuApp

class AuditEventReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION) return
        if (context.getSystemService(UserManager::class.java)?.isUserUnlocked == true) {
            ksuApp.auditCoordinator.invalidate()
        }
        val kind = intent.getStringExtra(EXTRA_KIND).orEmpty()
        val fallbackMessage = intent.getStringExtra(EXTRA_MESSAGE)?.takeIf(String::isNotBlank)
        val message = when (kind) {
            "auditd_restart" -> context.getString(R.string.security_audit_global_restart)
            "containment_applied" -> context.getString(R.string.security_audit_global_containment)
            "audit_store_missing" -> context.getString(R.string.security_audit_global_store_missing)
            "audit_state_unavailable" -> context.getString(R.string.security_audit_global_state_unavailable)
            "audit_verification_failed" -> context.getString(R.string.security_audit_global_verification_failed)
            "watch_overflow" -> context.getString(R.string.security_audit_global_watch_overflow)
            else -> fallbackMessage ?: return
        }

        val notificationManager =
            context.getSystemService(NotificationManager::class.java)
        notificationManager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                context.getString(R.string.security_audit_center),
                NotificationManager.IMPORTANCE_HIGH,
            )
        )

        val contentIntent = Intent(context, MainActivity::class.java).apply {
            action = Intent.ACTION_VIEW
            data = Uri.parse("ksu://audit")
            addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        val pendingIntent = PendingIntent.getActivity(
            context,
            0,
            contentIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentTitle(context.getString(R.string.security_audit_center))
            .setContentText(message)
            .setSubText(kind)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setStyle(NotificationCompat.BigTextStyle().bigText(message))
            .build()

        notificationManager.notify(NOTIFICATION_ID, notification)
    }

    companion object {
        const val ACTION = "me.weishu.kernelsu.action.AUDIT_SECURITY_EVENT"
        private const val EXTRA_KIND = "kind"
        private const val EXTRA_MESSAGE = "message"
        private const val CHANNEL_ID = "kernelsu_security_events"
        private const val NOTIFICATION_ID = 2020
    }
}
