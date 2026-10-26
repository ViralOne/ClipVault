import AppKit
import ServiceManagement
import SwiftUI
import UniformTypeIdentifiers

struct SettingsView: View {
    @ObservedObject var store: HistoryStore
    @ObservedObject var monitor: ClipboardMonitor

    var body: some View {
        TabView {
            GeneralSettings(monitor: monitor)
                .tabItem { Label("General", systemImage: "gearshape") }
            HistorySettings(store: store)
                .tabItem { Label("History", systemImage: "clock.arrow.circlepath") }
            ProtectionSettings()
                .tabItem { Label("Protection", systemImage: "key") }
            PrivacySettings(store: store)
                .tabItem { Label("Privacy", systemImage: "lock.shield") }
        }
        .frame(width: 580, height: 640)
    }
}

// MARK: - General

private struct GeneralSettings: View {
    @ObservedObject var monitor: ClipboardMonitor
    @AppStorage(Prefs.concealSound) private var concealSound = false

    @State private var launchAtLogin = SMAppService.mainApp.status == .enabled
    @State private var loginError: String?

    var body: some View {
        Form {
            Section {
                Toggle("Open ClipVault at login", isOn: Binding(
                    get: { launchAtLogin },
                    set: { updateLaunchAtLogin($0) }
                ))
                if let loginError {
                    Text(loginError)
                        .font(.callout)
                        .foregroundStyle(.orange)
                }
                Toggle("Record the clipboard", isOn: Binding(
                    get: { !monitor.isPaused },
                    set: { monitor.isPaused = !$0 }
                ))
                Toggle("Play a sound when a secret is concealed", isOn: $concealSound)
            }

            Section("Picker") {
                LabeledContent("Position") {
                    Button("Center on screen") {
                        PickerController.resetPosition()
                    }
                }
                Text("Drag the picker by its empty space to move it; it opens there next time.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            Section {
                LabeledContent("Welcome guide") {
                    Button("Show Again…") {
                        AppServices.shared.showOnboarding()
                    }
                }
            }
        }
        .formStyle(.grouped)
        .onAppear { launchAtLogin = SMAppService.mainApp.status == .enabled }
    }

    private func updateLaunchAtLogin(_ enabled: Bool) {
        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
            loginError = nil
        } catch {
            loginError = "Couldn't change the login item: \(error.localizedDescription). Move ClipVault to Applications and try again."
        }
        launchAtLogin = SMAppService.mainApp.status == .enabled
    }
}

// MARK: - History

private struct HistorySettings: View {
    @ObservedObject var store: HistoryStore

    @AppStorage(Prefs.keepHistory) private var keepHistory = true
    @AppStorage(Prefs.keepSecrets) private var keepSecrets = true
    @AppStorage(Prefs.pasteIntoApp) private var pasteIntoApp = true
    @AppStorage(Prefs.historyLimit) private var historyLimit = 500
    @AppStorage(Prefs.retentionDays) private var retentionDays = 0
    @AppStorage(Prefs.hideFromScreenCapture) private var hideFromCapture = true

    @State private var canPaste = Permissions.canPostEvents
    @State private var confirmClear = false

    var body: some View {
        Form {
            Section {
                Toggle("Keep clipboard history", isOn: $keepHistory)
                LabeledContent("Shortcut") { ShortcutRecorder() }
            }

            Section("Paste") {
                Toggle("Paste into the app you're using", isOn: $pasteIntoApp)
                HStack(spacing: 8) {
                    Image(systemName: canPaste ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                        .foregroundStyle(canPaste ? .green : .orange)
                    Text(canPaste
                         ? "Accessibility is on. Picking an item pastes it."
                         : "Allow Accessibility so picking an item pastes it. Without it, items are only copied.")
                    Spacer()
                    if !canPaste {
                        Button("Allow…") { Permissions.requestPostEvents() }
                    }
                }
                .font(.callout)
            }

            Section("Storage") {
                Picker("Maximum number of items", selection: $historyLimit) {
                    Text("100").tag(100)
                    Text("250").tag(250)
                    Text("500").tag(500)
                    Text("1,000").tag(1_000)
                    Text("5,000").tag(5_000)
                }
                Picker("Delete items older than", selection: $retentionDays) {
                    Text("Never").tag(0)
                    Text("1 day").tag(1)
                    Text("7 days").tag(7)
                    Text("30 days").tag(30)
                    Text("90 days").tag(90)
                }
                Toggle("Hide history content while the screen is shared or recorded", isOn: $hideFromCapture)
                    .onChange(of: hideFromCapture) { _, _ in AppServices.shared.applyCapturePolicy() }
                Toggle("Keep secrets in history, always sealed", isOn: $keepSecrets)
                LabeledContent {
                    Button("Clear History…") { confirmClear = true }
                        .disabled(store.items.isEmpty)
                } label: {
                    Text("Currently using \(byteString(store.bytesOnDisk))")
                    Text("\(store.items.count) items, \(store.pinnedCount) pinned")
                }
            }

            Section {
                AppListEditor(key: Prefs.ignoredApps, defaults: [], emptyText: "No apps")
            } header: {
                Text("Ignore these apps")
            } footer: {
                Text("Nothing these apps copy is saved. Secrets they copy are still concealed.")
            }
        }
        .formStyle(.grouped)
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            canPaste = Permissions.canPostEvents
        }
        .confirmationDialog("Clear the clipboard history?", isPresented: $confirmClear) {
            Button("Clear All Except Pinned", role: .destructive) { store.clearAll(keepPinned: true) }
            Button("Clear Everything", role: .destructive) { store.clearAll() }
        } message: {
            Text("Items and their encrypted image files are deleted. This can't be undone.")
        }
    }
}

// MARK: - Protection

private struct ProtectionSettings: View {
    @AppStorage(Prefs.concealSecrets) private var concealSecrets = true
    @AppStorage(Prefs.notifyOnConceal) private var notify = false
    @AppStorage(Prefs.clearSecretsSeconds) private var clearSeconds = 90

    var body: some View {
        Form {
            Section("Secrets") {
                Toggle("Conceal detected secrets", isOn: $concealSecrets)
                Toggle("Notify when something is concealed", isOn: $notify)
                    .onChange(of: notify) { _, enabled in
                        guard enabled else { return }
                        Task { await Notifier.requestAuthorization() }
                    }
                Picker("Clear the clipboard afterwards", selection: $clearSeconds) {
                    Text("Never").tag(0)
                    Text("After 30 seconds").tag(30)
                    Text("After 60 seconds").tag(60)
                    Text("After 90 seconds").tag(90)
                    Text("After 2 minutes").tag(120)
                    Text("After 5 minutes").tag(300)
                }
            }

            Section {
                AppListEditor(
                    key: Prefs.alwaysConcealApps,
                    defaults: Prefs.defaultAlwaysConcealApps,
                    emptyText: "No apps"
                )
            } header: {
                Text("Always conceal what these apps copy")
            } footer: {
                Text("Single-line text copied from a listed app is treated as a secret even when no pattern matches.")
            }

            Section {
                Text("Concealed items are re-marked with the nspasteboard.org types that Raycast, Alfred, Paste, Maccy and 1Password honor. Secrets kept in history are sealed to this Mac's Secure Enclave and need Touch ID or your password to open.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }
}

// MARK: - Privacy

private struct PrivacySettings: View {
    @ObservedObject var store: HistoryStore

    @State private var confirmRemoveSecrets = false
    @State private var confirmReset = false

    var body: some View {
        Form {
            Section("Encryption") {
                statusRow(
                    ok: !store.isEphemeral,
                    title: "History file",
                    detail: store.isEphemeral ? "Unreadable — running in memory only" : "AES-256-GCM, key in your login Keychain"
                )
                statusRow(
                    ok: SecretVault.shared.isAvailable,
                    title: "Secrets",
                    detail: secretStatus
                )
                statusRow(
                    ok: Biometrics.canAuthenticate,
                    title: "Unlock",
                    detail: Biometrics.hasBiometrics ? "Touch ID or your login password" : "Your login password"
                )
            }

            Section("Isolation") {
                statusRow(
                    ok: AppServices.isSandboxed,
                    title: "Network",
                    detail: AppServices.isSandboxed
                        ? "Blocked by the App Sandbox. ClipVault has no network entitlement."
                        : "Not sandboxed in this build. ClipVault still contains no network code."
                )
                statusRow(ok: true, title: "Telemetry", detail: "None. No account, sync, analytics or crash reports.")
            }

            Section("Data") {
                LabeledContent("Location") {
                    Button("Show in Finder") {
                        NSWorkspace.shared.activateFileViewerSelecting([store.fileURL])
                    }
                    .disabled(!FileManager.default.fileExists(atPath: store.fileURL.path))
                }
                Text(store.directory.path)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                if let error = store.lastError {
                    Text(error)
                        .font(.callout)
                        .foregroundStyle(.red)
                }
            }

            Section {
                LabeledContent("Remove every secret from history") {
                    Button("Remove…") { confirmRemoveSecrets = true }
                        .disabled(store.secretCount == 0)
                }
                LabeledContent("Delete the history and its keys") {
                    Button("Reset…") { confirmReset = true }
                }
            } header: {
                Text("Danger zone")
            } footer: {
                Text("Reset deletes the encrypted files and creates a new Secure Enclave key. Use it if the history can no longer be read.")
            }
        }
        .formStyle(.grouped)
        .confirmationDialog("Remove all secrets?", isPresented: $confirmRemoveSecrets) {
            Button("Remove \(store.secretCount) Secrets", role: .destructive) { store.removeSecrets() }
        } message: {
            Text("Every item classified as a secret, including images with secret text, is deleted.")
        }
        .confirmationDialog("Reset the encrypted store?", isPresented: $confirmReset) {
            Button("Reset", role: .destructive) {
                store.resetVault()
                SecretVault.shared.reset()
            }
        } message: {
            Text("The whole history is deleted. This can't be undone.")
        }
    }

    private var secretStatus: String {
        switch SecretVault.shared.status {
        case .secureEnclave:
            return "Sealed by the Secure Enclave. Only you can open them, on this Mac."
        case .unavailable(let reason):
            return "\(reason) Secrets are encrypted at rest only."
        }
    }

    private func statusRow(ok: Bool, title: String, detail: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: ok ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(ok ? .green : .orange)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                Text(detail)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: - App list editor

/// An editable list of apps, stored as bundle identifiers.
struct AppListEditor: View {
    let key: String
    let defaults: [String]
    let emptyText: String

    @State private var bundleIDs: [String] = []
    @State private var selection: String?

    var body: some View {
        VStack(spacing: 0) {
            if bundleIDs.isEmpty {
                Text(emptyText)
                    .foregroundStyle(.tertiary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 6)
            } else {
                ForEach(bundleIDs, id: \.self) { id in
                    HStack(spacing: 10) {
                        AppIconView(bundleID: id, appName: nil, size: 22)
                        Text(appName(for: id))
                        Spacer()
                        Text(id)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 5)
                    .padding(.horizontal, 6)
                    .background(
                        RoundedRectangle(cornerRadius: 6, style: .continuous)
                            .fill(selection == id ? Color.accentColor.opacity(0.18) : .clear)
                    )
                    .contentShape(Rectangle())
                    .onTapGesture { selection = selection == id ? nil : id }
                }
            }

            Divider().padding(.vertical, 6)

            HStack(spacing: 14) {
                Button { addApp() } label: { Image(systemName: "plus") }
                    .help("Add an app")
                Button {
                    guard let selection else { return }
                    bundleIDs.removeAll { $0 == selection }
                    self.selection = nil
                    save()
                } label: { Image(systemName: "minus") }
                    .disabled(selection == nil)
                    .help("Remove the selected app")
                Spacer()
                if !defaults.isEmpty {
                    Button("Reset to Defaults") {
                        bundleIDs = defaults
                        save()
                    }
                    .disabled(bundleIDs == defaults)
                }
            }
            .buttonStyle(.borderless)
        }
        .onAppear { bundleIDs = Prefs.strings(key) }
    }

    private func appName(for bundleID: String) -> String {
        guard let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID) else {
            return bundleID.components(separatedBy: ".").last ?? bundleID
        }
        return FileManager.default.displayName(atPath: url.path).replacingOccurrences(of: ".app", with: "")
    }

    private func addApp() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.application]
        panel.directoryURL = URL(fileURLWithPath: "/Applications")
        panel.allowsMultipleSelection = true
        panel.prompt = "Add"
        NSApp.activate(ignoringOtherApps: true)
        guard panel.runModal() == .OK else { return }
        for url in panel.urls {
            if let id = Bundle(url: url)?.bundleIdentifier, !bundleIDs.contains(id) {
                bundleIDs.append(id)
            }
        }
        save()
    }

    private func save() {
        UserDefaults.standard.set(bundleIDs, forKey: key)
    }
}
