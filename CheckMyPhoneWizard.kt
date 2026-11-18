package com.example.antispyware.ui

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.antispyware.security.RiskyAppAuditor
import com.example.antispyware.security.SideloadedAndAdminDetector
import com.example.antispyware.security.SideloadedAppAlert
import com.example.antispyware.security.SpywareServiceAlert
import com.example.antispyware.security.SpywareServiceDetector
import com.example.antispyware.security.UnknownAdminAlert
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class PhoneCheckSummary(
    val adbEnabled: Boolean = false,
    val spywareServices: List<SpywareServiceAlert> = emptyList(),
    val sideloadedApps: List<SideloadedAppAlert> = emptyList(),
    val unknownAdmins: List<UnknownAdminAlert> = emptyList(),
    val hasScanned: Boolean = false
) {
    val totalIssues: Int
        get() = (if (adbEnabled) 1 else 0) +
            spywareServices.size +
            sideloadedApps.size +
            unknownAdmins.size
}

/**
 * 1-Tap "Check My Phone" Wizard designed for everyday users.
 * Runs all defensive spyware, sideloaded APK, ADB, and Device Admin checks in one tap
 * and provides direct buttons to fix each issue in Android Settings.
 */
@Composable
fun CheckMyPhoneWizardScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var isScanning by remember { mutableStateOf(false) }
    var summary by remember { mutableStateOf(PhoneCheckSummary()) }

    fun runOneTapScan() {
        isScanning = true
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                val auditor = RiskyAppAuditor(context)
                val spywareDetector = SpywareServiceDetector(context)
                val sideloadDetector = SideloadedAndAdminDetector(context)

                PhoneCheckSummary(
                    adbEnabled = auditor.isAdbDebuggingEnabled(),
                    spywareServices = spywareDetector.scanHiddenSpywareServices(),
                    sideloadedApps = sideloadDetector.scanSideloadedApps(),
                    unknownAdmins = sideloadDetector.scanUnknownDeviceAdmins(),
                    hasScanned = true
                )
            }
            summary = result
            isScanning = false
        }
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Text(
                text = "1-Tap Check My Phone",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "Check for hidden screen-readers, sideloaded APKs, unknown admins, and USB debugging.",
                style = MaterialTheme.typography.bodyMedium
            )
            Spacer(modifier = Modifier.height(12.dp))
            Button(
                onClick = { runOneTapScan() },
                enabled = !isScanning,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(if (isScanning) "Scanning Phone..." else "Check My Phone Now")
            }
        }

        if (summary.hasScanned) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = if (summary.totalIssues == 0)
                            MaterialTheme.colorScheme.primaryContainer
                        else
                            MaterialTheme.colorScheme.errorContainer
                    )
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = if (summary.totalIssues == 0)
                                "No Hidden Spyware Signals Found"
                            else
                                "${summary.totalIssues} Potential Risk(s) Detected",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = if (summary.totalIssues == 0)
                                "Also remember to check WhatsApp -> Linked Devices manually."
                            else
                                "Review each flagged item below and revoke access or uninstall.",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }

            if (summary.adbEnabled) {
                item {
                    IssueActionCard(
                        title = "USB / Wireless Debugging (ADB) is ON",
                        subtitle = "Someone with PC access could inspect or control your phone.",
                        actionLabel = "Open Developer Settings",
                        onAction = {
                            openSafeSettings(context, Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS)
                        }
                    )
                }
            }

            items(summary.spywareServices, key = { "spy_${it.packageName}" }) { item ->
                val flags = buildList {
                    if (item.hasAccessibilityAccess) add("Accessibility (Screen Read)")
                    if (item.hasNotificationAccess) add("Notification Access")
                }.joinToString(" + ")

                IssueActionCard(
                    title = "${item.appName} has $flags",
                    subtitle = "Package: ${item.packageName}",
                    actionLabel = "Review Accessibility",
                    onAction = {
                        openSafeSettings(context, Settings.ACTION_ACCESSIBILITY_SETTINGS)
                    }
                )
            }

            items(summary.unknownAdmins, key = { "adm_${it.packageName}" }) { admin ->
                IssueActionCard(
                    title = "${admin.appName} is a Device Admin",
                    subtitle = "Active admin apps cannot be uninstalled until deactivated.",
                    actionLabel = "Open Security Settings",
                    onAction = {
                        openSafeSettings(context, Settings.ACTION_SECURITY_SETTINGS)
                    }
                )
            }

            items(summary.sideloadedApps, key = { "side_${it.packageName}" }) { app ->
                IssueActionCard(
                    title = "${app.appName} (Installed Outside Play Store)",
                    subtitle = "Source: ${app.installerPackage ?: "Unknown APK"}",
                    actionLabel = "Inspect / Uninstall",
                    onAction = { openAppInfo(context, app.packageName) }
                )
            }
        }
    }
}

@Composable
private fun IssueActionCard(
    title: String,
    subtitle: String,
    actionLabel: String,
    onAction: () -> Unit
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(text = title, fontWeight = FontWeight.SemiBold)
            Spacer(modifier = Modifier.height(4.dp))
            Text(text = subtitle, style = MaterialTheme.typography.bodySmall)
            Spacer(modifier = Modifier.height(8.dp))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                OutlinedButton(onClick = onAction) {
                    Text(actionLabel)
                }
            }
        }
    }
}

private fun openSafeSettings(context: Context, action: String) {
    try {
        context.startActivity(Intent(action).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    } catch (_: Exception) {
        context.startActivity(
            Intent(Settings.ACTION_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        )
    }
}

private fun openAppInfo(context: Context, packageName: String) {
    val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
        data = Uri.fromParts("package", packageName, null)
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    context.startActivity(intent)
}
