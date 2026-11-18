package com.example.antispyware.security

import android.Manifest
import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.UserHandle
import android.provider.Settings
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.nio.ByteBuffer

/**
 * 1. RiskyAppAuditor
 * Scans installed third-party apps for sensitive permissions and checks if ADB debugging is active.
 * Required Manifest permission: android.permission.QUERY_ALL_PACKAGES
 */
data class AppRiskReport(
    val packageName: String,
    val appName: String,
    val dangerousPermissions: List<String>,
    val riskScore: Int
)

class RiskyAppAuditor(private val context: Context) {

    private val highRiskPermissions = setOf(
        Manifest.permission.CAMERA,
        Manifest.permission.RECORD_AUDIO,
        Manifest.permission.ACCESS_FINE_LOCATION,
        Manifest.permission.READ_SMS,
        Manifest.permission.READ_CALL_LOG,
        Manifest.permission.SYSTEM_ALERT_WINDOW
    )

    fun isAdbDebuggingEnabled(): Boolean {
        return try {
            Settings.Global.getInt(
                context.contentResolver,
                Settings.Global.ADB_ENABLED,
                0
            ) == 1
        } catch (_: Exception) {
            false
        }
    }

    fun scanInstalledApps(): List<AppRiskReport> {
        val pm = context.packageManager
        val packages: List<PackageInfo> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(
                PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong())
            )
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        }

        return packages.mapNotNull { pkg ->
            val appInfo = pkg.applicationInfo ?: return@mapNotNull null
            val isSystemApp = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            if (isSystemApp || pkg.packageName == context.packageName) return@mapNotNull null

            val requested = pkg.requestedPermissions?.toList().orEmpty()
            val matched = requested.filter { it in highRiskPermissions }
            if (matched.isEmpty()) return@mapNotNull null

            val label = pm.getApplicationLabel(appInfo).toString()
            AppRiskReport(
                packageName = pkg.packageName,
                appName = label,
                dangerousPermissions = matched,
                riskScore = (matched.size * 20).coerceAtMost(100)
            )
        }.sortedByDescending { it.riskScore }
    }
}

/**
 * 2. SpywareServiceDetector
 * Detects third-party apps holding active Accessibility Service or Notification Listener access,
 * which stalkerware commonly abuses to silently read WhatsApp notifications and screen content.
 */
data class SpywareServiceAlert(
    val packageName: String,
    val appName: String,
    val hasAccessibilityAccess: Boolean,
    val hasNotificationAccess: Boolean
)

class SpywareServiceDetector(private val context: Context) {

    fun scanHiddenSpywareServices(): List<SpywareServiceAlert> {
        val accessibilityPkgs = parseEnabledComponentPackages(
            Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
            )
        )
        val notificationPkgs = parseEnabledComponentPackages(
            Settings.Secure.getString(
                context.contentResolver,
                "enabled_notification_listeners"
            )
        )

        val allFlagged = (accessibilityPkgs + notificationPkgs)
            .filter { it != context.packageName }
            .toSet()

        val pm = context.packageManager
        return allFlagged.mapNotNull { pkgName ->
            try {
                val appInfo = pm.getApplicationInfo(pkgName, 0)
                val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                if (isSystem) return@mapNotNull null

                SpywareServiceAlert(
                    packageName = pkgName,
                    appName = pm.getApplicationLabel(appInfo).toString(),
                    hasAccessibilityAccess = pkgName in accessibilityPkgs,
                    hasNotificationAccess = pkgName in notificationPkgs
                )
            } catch (_: PackageManager.NameNotFoundException) {
                null
            }
        }
    }

    private fun parseEnabledComponentPackages(settingValue: String?): Set<String> {
        if (settingValue.isNullOrBlank()) return emptySet()
        return settingValue.split(':')
            .mapNotNull { component ->
                val pkg = component.substringBefore('/').trim()
                pkg.takeIf { it.isNotEmpty() }
            }
            .toSet()
    }
}

/**
 * 3. SideloadedAndAdminDetector
 * Flags apps installed outside Google Play Store (sideloaded APKs) and
 * detects unknown apps holding active Device Admin privileges.
 */
data class SideloadedAppAlert(
    val packageName: String,
    val appName: String,
    val installerPackage: String?
)

data class UnknownAdminAlert(
    val packageName: String,
    val appName: String
)

class SideloadedAndAdminDetector(private val context: Context) {

    private val trustedStores = setOf(
        "com.android.vending", // Google Play Store
        "com.sec.android.app.samsungapps" // Samsung Galaxy Store
    )

    fun scanSideloadedApps(): List<SideloadedAppAlert> {
        val pm = context.packageManager
        val packages: List<PackageInfo> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0L))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(0)
        }

        return packages.mapNotNull { pkg ->
            val appInfo = pkg.applicationInfo ?: return@mapNotNull null
            val isSystemApp = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            if (isSystemApp || pkg.packageName == context.packageName) return@mapNotNull null

            val installer = try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    pm.getInstallSourceInfo(pkg.packageName).installingPackageName
                } else {
                    @Suppress("DEPRECATION")
                    pm.getInstallerPackageName(pkg.packageName)
                }
            } catch (_: Exception) {
                null
            }

            if (installer != null && installer in trustedStores) return@mapNotNull null

            SideloadedAppAlert(
                packageName = pkg.packageName,
                appName = pm.getApplicationLabel(appInfo).toString(),
                installerPackage = installer ?: "Unknown / Manual APK"
            )
        }
    }

    fun scanUnknownDeviceAdmins(): List<UnknownAdminAlert> {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val pm = context.packageManager
        val activeAdmins = dpm.activeAdmins.orEmpty()

        return activeAdmins.mapNotNull { adminComponent ->
            val pkgName = adminComponent.packageName
            if (pkgName == context.packageName) return@mapNotNull null
            try {
                val appInfo = pm.getApplicationInfo(pkgName, 0)
                UnknownAdminAlert(
                    packageName = pkgName,
                    appName = pm.getApplicationLabel(appInfo).toString()
                )
            } catch (_: PackageManager.NameNotFoundException) {
                UnknownAdminAlert(packageName = pkgName, appName = pkgName)
            }
        }
    }
}

/**
 * 4. SecurityShieldVpnService
 * Non-root local VPN firewall that inspects outbound IPv4 destination headers
 * and drops/logs traffic matching a local blocklist.
 * Declare in AndroidManifest.xml with permission="android.permission.BIND_VPN_SERVICE".
 */
class SecurityShieldVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private val serviceScope = CoroutineScope(Dispatchers.IO + Job())

    // Populate from Room DB or user-defined firewall rules
    private val blockedIps = mutableSetOf<String>()

    var onConnectionDetected: ((destinationIp: String, isBlocked: Boolean) -> Unit)? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startLocalFirewall()
        return START_STICKY
    }

    private fun startLocalFirewall() {
        if (vpnInterface != null) return

        val builder = Builder()
            .setSession("DefensiveSecurityShield")
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)

        // Prevent routing loop by excluding this app from the VPN tunnel
        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: PackageManager.NameNotFoundException) {
            // Safe fallback
        }

        vpnInterface = builder.establish()
        val fd = vpnInterface?.fileDescriptor ?: return

        serviceScope.launch {
            val input = FileInputStream(fd)
            val buffer = ByteBuffer.allocate(32767)

            while (isActive) {
                buffer.clear()
                val length = input.read(buffer.array())
                if (length > 0) {
                    val destIp = extractIpv4Destination(buffer.array(), length)
                    if (destIp != null) {
                        val isBlocked = destIp in blockedIps
                        onConnectionDetected?.invoke(destIp, isBlocked)
                        // Note: Forward allowed packets via protected DatagramSocket/Socket
                        // and drop packets if isBlocked == true.
                    }
                }
            }
        }
    }

    private fun extractIpv4Destination(packet: ByteArray, length: Int): String? {
        if (length < 20) return null
        val version = (packet[0].toInt() ushr 4) and 0x0F
        if (version != 4) return null

        val b1 = packet[16].toInt() and 0xFF
        val b2 = packet[17].toInt() and 0xFF
        val b3 = packet[18].toInt() and 0xFF
        val b4 = packet[19].toInt() and 0xFF
        return "$b1.$b2.$b3.$b4"
    }

    override fun onDestroy() {
        serviceScope.cancel()
        vpnInterface?.close()
        vpnInterface = null
        super.onDestroy()
    }
}

/**
 * 5. IntruderAdminReceiver
 * Detects failed lock-screen attempts and locks the device after threshold.
 * Register in AndroidManifest.xml with android.app.action.DEVICE_ADMIN_ENABLED
 * and <uses-policies><watch-login /><force-lock /></uses-policies>.
 */
class IntruderAdminReceiver : DeviceAdminReceiver() {

    override fun onPasswordFailed(context: Context, intent: Intent, user: UserHandle) {
        super.onPasswordFailed(context, intent, user)
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val adminComponent = ComponentName(context, IntruderAdminReceiver::class.java)

        val failedAttempts = dpm.currentFailedPasswordAttempts
        if (failedAttempts >= 3 && dpm.isAdminActive(adminComponent)) {
            // Immediately enforce lock screen; trigger CameraX capture in a foreground service if enabled
            dpm.lockNow()
        }
    }
}
