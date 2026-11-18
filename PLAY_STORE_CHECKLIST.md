# Google Play Store Release & Privacy Checklist

Before publishing **Defensive Security Shield** to Google Play, complete these required policy and security items:

1. **VpnService Policy Compliance**
   - Show a prominent in-app disclosure explaining that the local VPN only inspects outbound IP headers on-device and never routes user traffic to third-party servers.
   - Reference: https://support.google.com/googleplay/android-developer/answer/12564964?hl=en

2. **QUERY_ALL_PACKAGES Declaration**
   - In Play Console -> App Content -> Sensitive Permissions, declare **Device Security / Anti-Malware** as the core functionality requiring package visibility.

3. **Data Safety & Privacy Policy**
   - Host a public Privacy Policy URL stating what data stays strictly on-device (app list, failed unlock timestamps, firewall rules).
   - If you add external IP Geolocation lookups, disclose that destination IP addresses are sent to the GeoIP provider.

4. **Release Build Hardening**
   - Verify `isMinifyEnabled = true` and `isShrinkResources = true` in `app/build.gradle.kts`.
   - Verify `android:allowBackup="false"` in `AndroidManifest.xml`.
   - Set `EXPECTED_RELEASE_SHA256` in `AppHardeningSecurity.kt` to your Play App Signing certificate SHA-256.
