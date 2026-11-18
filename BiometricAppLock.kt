package com.example.antispyware.applock

import android.app.AppOpsManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.os.Process
import android.provider.Settings
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Shared in-memory lock session state (cleared when screen turns off or app closes).
 */
object AppLockSession {
    val protectedPackages = mutableSetOf(
        "com.android.settings",
        "com.google.android.apps.photos"
        // Add banking, UPI, or gallery packages here
    )

    @Volatile
    var temporarilyUnlockedPackage: String? = null
}

/**
 * Helper to check and request Usage Access (PACKAGE_USAGE_STATS).
 */
object UsagePermissionHelper {
    fun hasUsageStatsPermission(context: Context): Boolean {
        val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
        val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            appOps.unsafeCheckOpNoThrow(
                AppOpsManager.OPSTR_GET_USAGE_STATS,
                Process.myUid(),
                context.packageName
            )
        } else {
            @Suppress("DEPRECATION")
            appOps.checkOpNoThrow(
                AppOpsManager.OPSTR_GET_USAGE_STATS,
                Process.myUid(),
                context.packageName
            )
        }
        return mode == AppOpsManager.MODE_ALLOWED
    }

    fun openUsageAccessSettings(context: Context) {
        val intent = Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        context.startActivity(intent)
    }
}

/**
 * 1. ForegroundAppMonitorService
 * Polls UsageStatsManager events to detect when a protected app moves to the foreground.
 * Register in AndroidManifest.xml with foregroundServiceType="specialUse" or "dataSync".
 */
class ForegroundAppMonitorService : Service() {

    private val serviceScope = CoroutineScope(Dispatchers.Default + Job())
    private lateinit var usageStatsManager: UsageStatsManager

    override fun onCreate() {
        super.onCreate()
        usageStatsManager = getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
        startForeground(101, buildNotification())
        startMonitoring()
    }

    private fun startMonitoring() {
        serviceScope.launch {
            while (isActive) {
                val topPackage = getTopForegroundPackage()
                if (topPackage != null && topPackage != packageName) {
                    if (topPackage in AppLockSession.protectedPackages &&
                        topPackage != AppLockSession.temporarilyUnlockedPackage
                    ) {
                        launchLockScreen(topPackage)
                    } else if (topPackage !in AppLockSession.protectedPackages) {
                        // Re-lock once user leaves the protected app
                        AppLockSession.temporarilyUnlockedPackage = null
                    }
                }
                delay(400L)
            }
        }
    }

    private fun getTopForegroundPackage(): String? {
        val endTime = System.currentTimeMillis()
        val startTime = endTime - 2_000L
        val events = usageStatsManager.queryEvents(startTime, endTime)
        val event = UsageEvents.Event()
        var latestPackage: String? = null

        while (events.hasNextEvent()) {
            events.getNextEvent(event)
            val isForegroundEvent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                event.eventType == UsageEvents.Event.ACTIVITY_RESUMED
            } else {
                @Suppress("DEPRECATION")
                event.eventType == UsageEvents.Event.MOVE_TO_FOREGROUND
            }
            if (isForegroundEvent) {
                latestPackage = event.packageName
            }
        }
        return latestPackage
    }

    private fun launchLockScreen(targetPackage: String) {
        val lockIntent = Intent(this, BiometricLockActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_NO_ANIMATION)
            putExtra(BiometricLockActivity.EXTRA_TARGET_PACKAGE, targetPackage)
        }
        startActivity(lockIntent)
    }

    private fun buildNotification(): Notification {
        val channelId = "app_lock_monitor"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId,
                "App Lock Protection",
                NotificationManager.IMPORTANCE_LOW
            )
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(channel)
        }
        return NotificationCompat.Builder(this, channelId)
            .setContentTitle("Biometric App Lock Active")
            .setContentText("Protecting sensitive apps with mandatory biometrics")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .build()
    }

    override fun onDestroy() {
        serviceScope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}

/**
 * 2. BiometricLockActivity
 * Enforces iPhone-style mandatory BIOMETRIC_STRONG authentication with NO device PIN fallback.
 */
class BiometricLockActivity : FragmentActivity() {

    companion object {
        const val EXTRA_TARGET_PACKAGE = "extra_target_package"
    }

    private var targetPackage: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        targetPackage = intent.getStringExtra(EXTRA_TARGET_PACKAGE)
        showMandatoryBiometricPrompt()
    }

    private fun showMandatoryBiometricPrompt() {
        val biometricManager = BiometricManager.from(this)
        if (biometricManager.canAuthenticate(BIOMETRIC_STRONG) != BiometricManager.BIOMETRIC_SUCCESS) {
            // Device lacks Class 3 strong biometric hardware/enrollment; block access safely
            navigateToHome()
            return
        }

        val executor = ContextCompat.getMainExecutor(this)
        val biometricPrompt = BiometricPrompt(
            this,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    AppLockSession.temporarilyUnlockedPackage = targetPackage
                    finish()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    navigateToHome()
                }
            }
        )

        // BIOMETRIC_STRONG only — no DEVICE_CREDENTIAL fallback, matching iPhone Stolen Device Protection
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Protected App Locked")
            .setSubtitle("Verify your fingerprint or face to open")
            .setAllowedAuthenticators(BIOMETRIC_STRONG)
            .setNegativeButtonText("Exit to Home")
            .build()

        biometricPrompt.authenticate(promptInfo)
    }

    private fun navigateToHome() {
        val homeIntent = Intent(Intent.ACTION_MAIN).apply {
            addCategory(Intent.CATEGORY_HOME)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
        }
        startActivity(homeIntent)
        finish()
    }
}
