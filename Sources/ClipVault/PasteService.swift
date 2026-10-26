import AppKit
import OSLog
import SwiftUI
import ClipVaultKit

enum Permissions {
    /// Posting ⌘V into another app needs the Accessibility (post event)
    /// permission. These calls work inside the App Sandbox.
    static var canPostEvents: Bool { CGPreflightPostEventAccess() }

    static func requestPostEvents() {
        if !CGRequestPostEventAccess() {
            openAccessibilitySettings()
        }
    }

    static func openAccessibilitySettings() {
        let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")!
        NSWorkspace.shared.open(url)
    }

    static func openNotificationSettings() {
        let id = Bundle.main.bundleIdentifier ?? "app.clipvault.ClipVault"
        let url = URL(string: "x-apple.systempreferences:com.apple.Notifications-Settings.extension?id=\(id)")!
        NSWorkspace.shared.open(url)
    }
}

/// Resolves an item's content, asking for Touch ID or the login password first
/// when it is a secret.
@MainActor
enum ClipAccess {
    static func payload(for item: HistoryItem, store: HistoryStore, verb: String) async -> ClipPayload? {
        guard item.isSecret else {
            let payload = store.payload(for: item)
            if payload == nil {
                HUD.show("This item is no longer in the encrypted store", symbol: "exclamationmark.triangle.fill")
            }
            return payload
        }

        let kind = item.displayKind ?? "secret"
        guard let context = await Biometrics.authenticate(reason: "\(verb) \(kind.lowercased()) from ClipVault", scope: item.id) else {
            return nil
        }
        do {
            return try store.unseal(item, context: context)
        } catch {
            // The error never contains secret content.
            Logger(subsystem: "app.clipvault.ClipVault", category: "secrets")
                .error("Unseal failed: \(error.localizedDescription, privacy: .public)")
            Biometrics.endSession()
            HUD.show(error.localizedDescription, symbol: "exclamationmark.triangle.fill")
            return nil
        }
    }
}

@MainActor
enum PasteService {
    static func copy(_ payload: ClipPayload) {
        guard write(payload) else { return }
        if payload.isSecret {
            HUD.show("Copied as concealed", symbol: "lock.fill")
        } else {
            HUD.show(payload.imageData != nil ? "Image copied" : "Copied")
        }
    }

    /// Writes the content and, when allowed, presses ⌘V in the app that was
    /// frontmost before the picker opened.
    static func paste(_ payload: ClipPayload, into app: NSRunningApplication?) {
        guard write(payload) else { return }

        guard Prefs.bool(Prefs.pasteIntoApp) else {
            HUD.show("Copied")
            return
        }
        guard Permissions.canPostEvents else {
            HUD.show("Copied — allow Accessibility to paste automatically", symbol: "exclamationmark.triangle.fill")
            return
        }
        guard let app, app.bundleIdentifier != Bundle.main.bundleIdentifier else {
            HUD.show("Copied")
            return
        }

        app.activate()
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
            sendCommandV()
        }
    }

    private static func write(_ payload: ClipPayload) -> Bool {
        let changeCount: Int
        if let data = payload.imageData {
            changeCount = PasteboardWriter.writeImage(data, uti: payload.uti, concealed: payload.isSecret)
        } else if let text = payload.text {
            changeCount = PasteboardWriter.write(text, concealed: payload.isSecret)
        } else {
            HUD.show("Nothing to copy", symbol: "exclamationmark.triangle.fill")
            return false
        }
        if payload.isSecret {
            AppServices.shared.monitor.scheduleClear(after: changeCount)
        }
        return true
    }

    static func togglePin(_ item: HistoryItem, store: HistoryStore) {
        store.togglePin(item.id)
        let pinned = store.items.first { $0.id == item.id }?.pinned ?? !item.pinned
        HUD.show(pinned ? "Pinned" : "Unpinned", symbol: pinned ? "pin.fill" : "pin.slash")
    }

    private static func sendCommandV() {
        guard let source = CGEventSource(stateID: .combinedSessionState) else { return }
        let down = CGEvent(keyboardEventSource: source, virtualKey: 9, keyDown: true)
        let up = CGEvent(keyboardEventSource: source, virtualKey: 9, keyDown: false)
        down?.flags = .maskCommand
        up?.flags = .maskCommand
        down?.post(tap: .cghidEventTap)
        up?.post(tap: .cghidEventTap)
    }
}

// MARK: - Transient HUD

@MainActor
enum HUD {
    private static var panel: NSPanel?

    static func show(_ message: String, symbol: String = "checkmark.circle.fill") {
        panel?.orderOut(nil)

        let hosting = NSHostingView(rootView: HUDView(message: message, symbol: symbol))
        let size = hosting.fittingSize
        let hudPanel = NSPanel(
            contentRect: NSRect(origin: .zero, size: size),
            styleMask: [.borderless, .nonactivatingPanel],
            backing: .buffered,
            defer: false
        )
        hudPanel.isOpaque = false
        hudPanel.backgroundColor = .clear
        hudPanel.level = .statusBar
        hudPanel.hasShadow = false
        hudPanel.ignoresMouseEvents = true
        hudPanel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .transient]
        hosting.frame = NSRect(origin: .zero, size: size)
        hudPanel.contentView = hosting

        if let screen = NSScreen.main {
            let frame = screen.visibleFrame
            hudPanel.setFrameOrigin(NSPoint(x: frame.midX - size.width / 2, y: frame.minY + 90))
        }

        hudPanel.alphaValue = 0
        hudPanel.orderFrontRegardless()
        NSAnimationContext.runAnimationGroup { context in
            context.duration = 0.18
            hudPanel.animator().alphaValue = 1
        }
        panel = hudPanel

        DispatchQueue.main.asyncAfter(deadline: .now() + 1.8) {
            NSAnimationContext.runAnimationGroup({ context in
                context.duration = 0.3
                hudPanel.animator().alphaValue = 0
            }, completionHandler: {
                Task { @MainActor in
                    hudPanel.orderOut(nil)
                    if HUD.panel === hudPanel { HUD.panel = nil }
                }
            })
        }
    }
}

private struct HUDView: View {
    let message: String
    let symbol: String

    var body: some View {
        HStack(spacing: 9) {
            Image(systemName: symbol)
                .font(.system(size: 14, weight: .semibold))
                .symbolRenderingMode(.hierarchical)
            Text(message)
                .font(.system(size: 13, weight: .medium))
                .lineLimit(2)
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 11)
        .background(.regularMaterial, in: Capsule())
        .overlay(Capsule().strokeBorder(Color.primary.opacity(0.08)))
        .shadow(color: .black.opacity(0.18), radius: 14, y: 6)
        .padding(20)
        .fixedSize()
    }
}
