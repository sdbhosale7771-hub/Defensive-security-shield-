package com.example.antispyware.ui

import android.app.Application
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
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
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.antispyware.applock.ForegroundAppMonitorService
import com.example.antispyware.applock.UsagePermissionHelper
import com.example.antispyware.security.AppRiskReport
import com.example.antispyware.security.RiskyAppAuditor
import com.example.antispyware.security.SecurityShieldVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/*
 * Required AndroidManifest.xml permissions:
 * <uses-permission android:name="android.permission.INTERNET" />
 * <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
 * <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" />
 * <uses-permission android:name="android.permission.PACKAGE_USAGE_STATS" tools:ignore="ProtectedPermissions" />
 * <uses-permission android:name="android.permission.USE_BIOMETRIC" />
 */

data class SecurityUiState(
    val isAdbEnabled: Boolean = false,
    val isVpnShieldActive: Boolean = false,
    val isAppLockActive: Boolean = false,
    val hasUsagePermission: Boolean = false,
    val riskyApps: List<AppRiskReport> = emptyList()
)

class SecurityViewModel(application: Application) : AndroidViewModel(application) {

    private val auditor = RiskyAppAuditor(application)

    private val _uiState = MutableStateFlow(SecurityUiState())
    val uiState: StateFlow<SecurityUiState> = _uiState.asStateFlow()

    init {
        refreshSecurityAudit()
    }

    fun refreshSecurityAudit() {
        val ctx = getApplication<Application>()
        viewModelScope.launch(Dispatchers.IO) {
            val adbActive = auditor.isAdbDebuggingEnabled()
            val usageGranted = UsagePermissionHelper.hasUsageStatsPermission(ctx)
            val scannedApps = auditor.scanInstalledApps()

            _uiState.update {
                it.copy(
                    isAdbEnabled = adbActive,
                    hasUsagePermission = usageGranted,
                    riskyApps = scannedApps
                )
            }
        }
    }

    fun setVpnShieldActive(active: Boolean) {
        val ctx = getApplication<Application>()
        val intent = Intent(ctx, SecurityShieldVpnService::class.java)
        if (active) {
            ctx.startService(intent)
        } else {
            ctx.stopService(intent)
        }
        _uiState.update { it.copy(isVpnShieldActive = active) }
    }

    fun toggleBiometricAppLock(enable: Boolean) {
        val ctx = getApplication<Application>()
        if (enable && !UsagePermissionHelper.hasUsageStatsPermission(ctx)) {
            UsagePermissionHelper.openUsageAccessSettings(ctx)
            return
        }
        val serviceIntent = Intent(ctx, ForegroundAppMonitorService::class.java)
        if (enable) {
            ContextCompat.startForegroundService(ctx, serviceIntent)
        } else {
            ctx.stopService(serviceIntent)
        }
        _uiState.update { it.copy(isAppLockActive = enable) }
    }
}

class MainActivity : ComponentActivity() {

    private val viewModel: SecurityViewModel by viewModels()

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            viewModel.setVpnShieldActive(true)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                val state by viewModel.uiState.collectAsState()
                DefensiveDashboardScreen(
                    state = state,
                    onToggleVpn = { enable ->
                        if (enable) {
                            val prepareIntent = VpnService.prepare(this)
                            if (prepareIntent != null) {
                                vpnPermissionLauncher.launch(prepareIntent)
                            } else {
                                viewModel.setVpnShieldActive(true)
                            }
                        } else {
                            viewModel.setVpnShieldActive(false)
                        }
                    },
                    onToggleAppLock = { enable -> viewModel.toggleBiometricAppLock(enable) },
                    onRescan = { viewModel.refreshSecurityAudit() }
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        viewModel.refreshSecurityAudit()
    }
}

@Composable
fun DefensiveDashboardScreen(
    state: SecurityUiState,
    onToggleVpn: (Boolean) -> Unit,
    onToggleAppLock: (Boolean) -> Unit,
    onRescan: () -> Unit
) {
    Scaffold { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item {
                Text(
                    text = "Defensive Security Shield",
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = if (state.isAdbEnabled)
                        "Alert: USB/Wireless Debugging (ADB) is ON"
                    else
                        "Device Status: ADB Debugging is OFF",
                    color = if (state.isAdbEnabled)
                        MaterialTheme.colorScheme.error
                    else
                        MaterialTheme.colorScheme.primary,
                    style = MaterialTheme.typography.bodyMedium
                )
            }

            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors()
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text("Local Firewall (VpnService)", fontWeight = FontWeight.SemiBold)
                                Text(
                                    "Monitors outbound IP connections without root",
                                    style = MaterialTheme.typography.bodySmall
                                )
                            }
                            Switch(
                                checked = state.isVpnShieldActive,
                                onCheckedChange = onToggleVpn
                            )
                        }

                        Spacer(modifier = Modifier.height(12.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text("Mandatory Biometric Lock", fontWeight = FontWeight.SemiBold)
                                Text(
                                    "iPhone-style BIOMETRIC_STRONG lock for sensitive apps",
                                    style = MaterialTheme.typography.bodySmall
                                )
                            }
                            Switch(
                                checked = state.isAppLockActive,
                                onCheckedChange = onToggleAppLock
                            )
                        }
                    }
                }
            }

            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "High-Risk Permission Apps (${state.riskyApps.size})",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                    Button(onClick = onRescan) {
                        Text("Rescan")
                    }
                }
            }

            items(state.riskyApps, key = { it.packageName }) { app ->
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(app.appName, fontWeight = FontWeight.SemiBold)
                            Text(
                                text = "Risk: ${app.riskScore}/100",
                                color = MaterialTheme.colorScheme.error,
                                fontWeight = FontWeight.Medium
                            )
                        }
                        Text(
                            text = app.packageName,
                            style = MaterialTheme.typography.bodySmall
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = app.dangerousPermissions.joinToString(", ") {
                                it.substringAfterLast('.')
                            },
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }
        }
    }
}
