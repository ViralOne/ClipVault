import AppKit
import Combine
import SwiftUI
import UserNotifications
import ClipVaultKit

struct OnboardingView: View {
    @ObservedObject var store: HistoryStore
    @ObservedObject var monitor: ClipboardMonitor
    var initialPage = 0
    var onFinish: () -> Void

    @State private var page = 0
    @State private var demoTexts: [String] = []
    @State private var startedAt = Date()

    private let pageCount = 6

    var body: some View {
        VStack(spacing: 0) {
            Group {
                switch page {
                case 0: WelcomePage()
                case 1: HistoryPage(onCopy: copyDemo)
                case 2: SecretPage(monitor: monitor, onCopy: copyDemo)
                case 3: NotificationsPage()
                case 4: ShortcutPage()
                default: DonePage()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .padding(.horizontal, 44)
            .padding(.top, 36)
            .transition(.asymmetric(
                insertion: .opacity.combined(with: .offset(x: 24)),
                removal: .opacity
            ))
            .id(page)

            Divider()

            HStack {
                HStack(spacing: 8) {
                    ForEach(0..<pageCount, id: \.self) { index in
                        Circle()
                            .fill(index == page ? Color.accentColor : Color.primary.opacity(0.15))
                            .frame(width: 7, height: 7)
                    }
                }
                Spacer()
                if page > 0 {
                    Button("Back") { go(-1) }
                        .controlSize(.large)
                }
                Button(page == pageCount - 1 ? "Start Using ClipVault" : "Continue") {
                    if page == pageCount - 1 { finish() } else { go(1) }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .keyboardShortcut(.defaultAction)
            }
            .padding(.horizontal, 22)
            .padding(.vertical, 16)
        }
        .frame(width: 620, height: 640)
        .onAppear { page = initialPage }
    }

    private func go(_ delta: Int) {
        withAnimation(.easeInOut(duration: 0.22)) {
            page = min(max(page + delta, 0), pageCount - 1)
        }
    }

    /// Writes straight to the pasteboard (not through `PasteboardWriter`) so
    /// the monitor treats it like a normal copy.
    private func copyDemo(_ text: String) {
        demoTexts.append(text)
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(text, forType: .string)
    }

    private func finish() {
        // Samples copied during the tour are not kept in history.
        store.deleteItems(matching: demoTexts, since: startedAt)
        UserDefaults.standard.set(true, forKey: Prefs.onboardingCompleted)
        onFinish()
    }
}

// MARK: - Pages

private struct PageHeader: View {
    let symbol: String
    let title: String
    let subtitle: String

    var body: some View {
        VStack(spacing: 14) {
            HeroIcon(symbol: symbol)
                .padding(.bottom, 4)
            Text(title)
                .font(.system(size: 26, weight: .bold))
                .multilineTextAlignment(.center)
            Text(subtitle)
                .font(.system(size: 14))
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity)
    }
}

private struct WelcomePage: View {
    var body: some View {
        VStack(spacing: 0) {
            Spacer(minLength: 10)
            AppIconImage(size: 128)
                .shadow(color: .black.opacity(0.12), radius: 16, y: 8)
            Text("Welcome to ClipVault")
                .font(.system(size: 32, weight: .bold))
                .padding(.top, 22)
            Text("Clipboard history that keeps secrets secret")
                .font(.system(size: 15))
                .foregroundStyle(.secondary)
                .padding(.top, 8)

            VStack(alignment: .leading, spacing: 22) {
                feature(
                    "clock.arrow.circlepath",
                    "Clipboard history",
                    "Press \(HotKeyPrefs.load().display) to search everything you copied — text, links and images — and paste it again."
                )
                feature(
                    "key.fill",
                    "Protect your secrets",
                    "Passwords and API keys are concealed the moment you copy them, and sealed by the Secure Enclave."
                )
                feature(
                    "lock.shield.fill",
                    "Offline, private, on-device",
                    "Nothing leaves this Mac. The App Sandbox blocks all network access."
                )
            }
            .padding(.top, 36)
            .frame(maxWidth: 470)
            Spacer(minLength: 10)
        }
    }

    private func feature(_ symbol: String, _ title: String, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 16) {
            Image(systemName: symbol)
                .font(.system(size: 22))
                .foregroundStyle(Color.accentColor)
                .frame(width: 30)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.system(size: 15, weight: .semibold))
                Text(text)
                    .font(.system(size: 13.5))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

private struct HistoryPage: View {
    var onCopy: (String) -> Void

    @State private var canPaste = Permissions.canPostEvents
    @State private var copied: String?
    private let poll = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    private let samples = [
        ("A note", "Lunch at 12:30, bring the slides"),
        ("A link", "https://www.apple.com/macos/"),
        ("A command", "git push origin main")
    ]

    var body: some View {
        VStack(spacing: 22) {
            PageHeader(
                symbol: "clock.arrow.circlepath",
                title: "Your clipboard history",
                subtitle: "Press \(HotKeyPrefs.load().display) anywhere to search what you copied and paste it again."
            )

            VStack(spacing: 14) {
                ForEach(samples, id: \.1) { sample in
                    SampleRow(title: sample.0, value: sample.1, copied: copied == sample.1) {
                        onCopy(sample.1)
                        copied = sample.1
                    }
                }
            }

            HStack {
                Text("That's your history. Pick any item to paste it.")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
                Spacer()
                Button {
                    AppServices.shared.picker.show()
                } label: {
                    Text("Try it  \(HotKeyPrefs.load().display)")
                        .padding(.horizontal, 6)
                }
                .buttonStyle(.borderedProminent)
                .buttonBorderShape(.capsule)
                .controlSize(.large)
            }

            if canPaste {
                StatusBanner(
                    symbol: "checkmark.circle.fill",
                    title: "Paste permission: granted",
                    message: "Picking an item pastes it straight into the app you're using."
                )
            } else {
                HStack(alignment: .center) {
                    StatusBanner(
                        symbol: "hand.raised.fill",
                        title: "Allow pasting",
                        message: "Give ClipVault Accessibility access so picking an item pastes it. Without it, items are only copied.",
                        tint: .orange
                    )
                    .overlay(alignment: .trailing) {
                        Button("Allow…") { Permissions.requestPostEvents() }
                            .padding(.trailing, 14)
                    }
                }
            }
            Spacer(minLength: 0)
        }
        .onReceive(poll) { _ in canPaste = Permissions.canPostEvents }
    }
}

private struct SecretPage: View {
    @ObservedObject var monitor: ClipboardMonitor
    var onCopy: (String) -> Void

    @State private var copied: String?
    /// Generated at runtime so no token-shaped string lives in the source.
    @State private var sampleToken = "ghp_" + String((0..<36).map { _ in
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".randomElement()!
    })

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            PageHeader(
                symbol: "hand.tap.fill",
                title: "Try copying a secret",
                subtitle: "Copy each sample and watch what happens."
            )

            SampleRow(
                title: "Ordinary text",
                value: "Lunch at 12:30, bring the slides",
                note: "Saved as a normal item.",
                copied: copied == "plain"
            ) {
                onCopy("Lunch at 12:30, bring the slides")
                copied = "plain"
            }

            SampleRow(
                title: "Looks like a secret",
                value: sampleToken,
                note: "A GitHub-style token: concealed before clipboard managers see it.",
                copied: copied == "secret"
            ) {
                onCopy(sampleToken)
                copied = "secret"
            }

            if let event = monitor.lastEvent, copied != nil {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Latest clipboard change")
                        .font(.system(size: 12.5))
                        .foregroundStyle(.secondary)
                    HStack(spacing: 12) {
                        AppIconView(bundleID: event.bundleID, appName: event.appName, size: 30)
                        VStack(alignment: .leading, spacing: 2) {
                            HStack(spacing: 5) {
                                Text(event.appName ?? "Unknown app").font(.system(size: 14, weight: .semibold))
                                if event.secretKind != nil {
                                    Image(systemName: "lock.fill").font(.system(size: 11)).foregroundStyle(.green)
                                }
                            }
                            Text(event.secretKind.map { "•••• \($0) · \(event.characterCount) chars" } ?? "Text · \(event.characterCount) chars")
                                .font(.system(size: 13))
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text(clockTime(event.date))
                            .font(.system(size: 12).monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                }

                if let kind = event.secretKind {
                    StatusBanner(
                        symbol: "checkmark.shield.fill",
                        title: "\(kind) concealed",
                        message: clearMessage
                    )
                } else {
                    StatusBanner(
                        symbol: "doc.on.clipboard.fill",
                        title: "Saved to history",
                        message: "Ordinary text is kept, encrypted, so you can paste it again later.",
                        tint: .blue
                    )
                }
            }
            Spacer(minLength: 0)
        }
    }

    private var clearMessage: String {
        let seconds = Prefs.int(Prefs.clearSecretsSeconds)
        let clear = seconds > 0 ? "The clipboard clears itself in \(seconds) seconds." : "Auto-clear is off."
        return "Clipboard managers won't keep it, and the copy in your history is sealed. \(clear)"
    }
}

private struct NotificationsPage: View {
    @State private var status: UNAuthorizationStatus = .notDetermined
    @AppStorage(Prefs.notifyOnConceal) private var notify = false

    var body: some View {
        VStack(spacing: 28) {
            PageHeader(
                symbol: "bell.badge.fill",
                title: "Know when a secret was caught",
                subtitle: "ClipVault can show a notification each time it conceals something. It looks like this:"
            )

            HStack(alignment: .top, spacing: 14) {
                AppIconImage(size: 40)
                VStack(alignment: .leading, spacing: 3) {
                    Text("Secret concealed").font(.system(size: 14, weight: .semibold))
                    Text("GitHub token detected in your clipboard and hidden from clipboard managers.")
                        .font(.system(size: 13.5))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }
            .padding(18)
            .frame(maxWidth: 420)
            .background(
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .fill(Color(nsColor: .windowBackgroundColor))
                    .shadow(color: .black.opacity(0.12), radius: 14, y: 6)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .strokeBorder(Color.primary.opacity(0.08))
            )

            HStack(spacing: 12) {
                switch status {
                case .authorized, .provisional:
                    Image(systemName: notify ? "bell.fill" : "bell.slash")
                        .foregroundStyle(notify ? .green : .secondary)
                    Toggle("Notify me when a secret is concealed", isOn: $notify)
                        .toggleStyle(.switch)
                case .denied:
                    Image(systemName: "bell.slash.fill").foregroundStyle(.orange)
                    Text("Notifications are off for ClipVault.")
                    Button("Turn On in System Settings") { Permissions.openNotificationSettings() }
                default:
                    Image(systemName: "bell").foregroundStyle(.secondary)
                    Text("Notifications are optional.")
                    Button("Turn On Notifications") {
                        Task {
                            notify = await Notifier.requestAuthorization()
                            status = await Notifier.authorizationStatus()
                        }
                    }
                }
            }
            .font(.system(size: 13.5))
            Spacer(minLength: 0)
        }
        .task { status = await Notifier.authorizationStatus() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            Task { status = await Notifier.authorizationStatus() }
        }
    }
}

private struct ShortcutPage: View {
    var body: some View {
        VStack(spacing: 30) {
            PageHeader(
                symbol: "command",
                title: "Pick your shortcut",
                subtitle: "This opens the picker from any app. Click the field and press a new combination, or keep the default."
            )
            ShortcutRecorder(width: 260)
            VStack(alignment: .leading, spacing: 12) {
                tip("⌘1–9", "Paste one of the first nine items instantly")
                tip("⌘P", "Pin an item to the top")
                tip("⌘↑ ⌘↓", "Move the selected item up or down your history")
                tip("⌘R", "Reveal a secret with Touch ID")
            }
            .frame(maxWidth: 380, alignment: .leading)
            Spacer(minLength: 0)
        }
    }

    private func tip(_ keys: String, _ text: String) -> some View {
        HStack(spacing: 12) {
            KeyCap(label: keys, prominent: true)
                .frame(minWidth: 64, alignment: .leading)
            Text(text).font(.system(size: 13.5)).foregroundStyle(.secondary)
        }
    }
}

private struct DonePage: View {
    var body: some View {
        VStack(spacing: 26) {
            PageHeader(
                symbol: "checkmark",
                title: "You're all set",
                subtitle: "ClipVault lives in the menu bar. It's recording now."
            )
            GroupCard {
                VStack(alignment: .leading, spacing: 14) {
                    row("lock.doc", "Click the menu bar icon for recent items, pause and settings.")
                    row("macwindow", "Open the ClipVault window to browse, filter, reorder and inspect everything.")
                    row("hand.draw", "Drag the picker anywhere on screen. It remembers the spot.")
                    row("gearshape", "Ignore apps, change retention and protection in Settings.")
                }
                .padding(18)
            }
            .frame(maxWidth: 460)
            Spacer(minLength: 0)
        }
    }

    private func row(_ symbol: String, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: symbol)
                .foregroundStyle(Color.accentColor)
                .frame(width: 20)
            Text(text).font(.system(size: 13.5))
        }
    }
}

// MARK: - Sample row

private struct SampleRow: View {
    let title: String
    let value: String
    var note: String?
    var copied = false
    var onCopy: () -> Void

    var body: some View {
        HStack(alignment: .center, spacing: 16) {
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.system(size: 14.5, weight: .semibold))
                Text(value)
                    .font(.system(size: 13.5, design: .monospaced))
                    .lineLimit(1)
                    .truncationMode(.middle)
                if let note {
                    Text(note)
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            Button(action: onCopy) {
                Label(copied ? "Copied" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc")
                    .frame(minWidth: 70)
            }
            .controlSize(.large)
        }
    }
}
