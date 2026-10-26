import AppKit
import SwiftUI

struct SecurityView: View {
    @ObservedObject var store: HistoryStore
    @ObservedObject var monitor: ClipboardMonitor

    @State private var canPaste = Permissions.canPostEvents

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Security")
                        .font(.system(size: 24, weight: .bold))
                    Text("How ClipVault protects what you copy.")
                        .font(.system(size: 13))
                        .foregroundStyle(.secondary)
                }

                HStack(spacing: 12) {
                    stat("\(monitor.concealedCount)", "concealed this session", tint: .green)
                    stat("\(store.secretCount)", "secrets in history", tint: .orange)
                    stat("\(store.imageCount)", "images, read on device", tint: .purple)
                }

                GroupCard {
                    row(
                        symbol: "lock.shield.fill", tint: .green,
                        title: "Secure Enclave seal",
                        detail: SecretVault.shared.isAvailable
                            ? "Secrets are sealed to a key inside this Mac's Secure Enclave. Opening one needs Touch ID or your password — the history files and Keychain alone can't decrypt them."
                            : "Unavailable on this Mac. Secrets are encrypted at rest with the vault key.",
                        ok: SecretVault.shared.isAvailable
                    )
                    Divider().padding(.leading, 52)
                    row(
                        symbol: "externaldrive.fill.badge.checkmark", tint: .blue,
                        title: "Encrypted history",
                        detail: store.isEphemeral
                            ? (store.lastError ?? "The history file can't be read; nothing is being saved.")
                            : "AES-256-GCM. The key is a device-only item in your login Keychain. Files are readable only by you.",
                        ok: !store.isEphemeral
                    )
                    Divider().padding(.leading, 52)
                    row(
                        symbol: "eye.slash.fill", tint: .orange,
                        title: "Concealed on the clipboard",
                        detail: "Secrets are re-marked within a quarter second so Raycast, Alfred, Paste and Maccy skip them. An app that reads the clipboard faster can still see the value.",
                        ok: Prefs.bool(Prefs.concealSecrets)
                    )
                    Divider().padding(.leading, 52)
                    row(
                        symbol: "timer", tint: .purple,
                        title: "Auto-clear",
                        detail: clearDetail,
                        ok: Prefs.int(Prefs.clearSecretsSeconds) > 0
                    )
                    Divider().padding(.leading, 52)
                    row(
                        symbol: "network.slash", tint: .teal,
                        title: "No network",
                        detail: AppServices.isSandboxed
                            ? "The App Sandbox blocks all network access. Nothing leaves this Mac."
                            : "This build isn't sandboxed, but ClipVault contains no network code.",
                        ok: AppServices.isSandboxed
                    )
                    Divider().padding(.leading, 52)
                    row(
                        symbol: "rectangle.on.rectangle.slash", tint: .pink,
                        title: "Hidden from screen sharing",
                        detail: "ClipVault's windows are excluded from screenshots, recordings and screen sharing.",
                        ok: Prefs.bool(Prefs.hideFromScreenCapture)
                    )
                    Divider().padding(.leading, 52)
                    row(
                        symbol: "hand.raised.fill", tint: .indigo,
                        title: "Accessibility",
                        detail: canPaste
                            ? "Granted. Picking an item pastes it into the app you were using."
                            : "Not granted. Picking an item copies it; paste it yourself with ⌘V.",
                        ok: canPaste,
                        action: canPaste ? nil : ("Allow…", Permissions.requestPostEvents)
                    )
                }
            }
            .padding(28)
            .frame(maxWidth: 760, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            canPaste = Permissions.canPostEvents
        }
    }

    private var clearDetail: String {
        let seconds = Prefs.int(Prefs.clearSecretsSeconds)
        guard seconds > 0 else { return "Off. Secrets stay on the clipboard until something else is copied." }
        return "A secret is wiped from the clipboard \(seconds) seconds after it's copied or pasted, if it's still there."
    }

    private func stat(_ value: String, _ label: String, tint: Color) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(value)
                .font(.system(size: 26, weight: .semibold, design: .rounded))
                .foregroundStyle(tint)
            Text(label)
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(Color.primary.opacity(0.035))
        )
    }

    private func row(
        symbol: String,
        tint: Color,
        title: String,
        detail: String,
        ok: Bool,
        action: (String, () -> Void)? = nil
    ) -> some View {
        HStack(alignment: .top, spacing: 12) {
            SymbolTile(symbol: symbol, tint: tint, size: 28, filled: true)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(title).font(.system(size: 13.5, weight: .semibold))
                    StatusDot(ok: ok)
                }
                Text(detail)
                    .font(.system(size: 12.5))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
            if let action {
                Button(action.0, action: action.1)
            }
        }
        .padding(14)
    }
}

struct AboutView: View {
    var body: some View {
        ScrollView {
            VStack(spacing: 18) {
                AppIconImage(size: 128)
                    .padding(.top, 20)

                VStack(spacing: 4) {
                    Text("ClipVault")
                        .font(.system(size: 28, weight: .bold))
                    Text("Version \(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "–")")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }

                Text("Clipboard history that keeps secrets secret.")
                    .font(.system(size: 14))
                    .foregroundStyle(.secondary)

                GroupCard {
                    VStack(alignment: .leading, spacing: 12) {
                        feature("clock.arrow.circlepath", "Search and paste anything you copied with \(HotKeyPrefs.load().display).")
                        feature("text.viewfinder", "Text inside screenshots and images is read on device, and searchable.")
                        feature("key.fill", "60+ token formats are detected and concealed the moment you copy them.")
                        feature("lock.shield.fill", "Secrets are sealed by the Secure Enclave and need Touch ID to open.")
                        feature("arrow.up.arrow.down", "Drag to reorder, pin what matters, change the shortcut.")
                        feature("network.slash", "Runs entirely on this Mac. No account, sync or telemetry.")
                    }
                    .padding(18)
                }
                .frame(maxWidth: 480)
            }
            .padding(30)
            .frame(maxWidth: .infinity)
        }
    }

    private func feature(_ symbol: String, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: symbol)
                .font(.system(size: 14, weight: .medium))
                .foregroundStyle(Color.accentColor)
                .frame(width: 20)
            Text(text)
                .font(.system(size: 13))
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
