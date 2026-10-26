import AppKit
import SwiftUI

@MainActor
final class AppServices {
    static let shared = AppServices()

    let store: HistoryStore
    let monitor: ClipboardMonitor
    let picker: PickerController

    private var mainWindow: NSWindow?
    private var onboardingWindow: NSWindow?
    private var observers: [NSObjectProtocol] = []

    /// True when running inside the App Sandbox, which blocks network access
    /// because the app has no network entitlement.
    static let isSandboxed = ProcessInfo.processInfo.environment["APP_SANDBOX_CONTAINER_ID"] != nil

    private init() {
        Prefs.registerDefaults()
        store = HistoryStore()
        monitor = ClipboardMonitor(store: store)
        picker = PickerController(store: store)
    }

    func start() {
        monitor.start()
        applyHotKey()

        // Every window — including Settings and the menu bar window, which
        // SwiftUI creates — follows the screen-capture preference.
        observers.append(NotificationCenter.default.addObserver(
            forName: NSWindow.didBecomeKeyNotification,
            object: nil,
            queue: .main
        ) { note in
            Task { @MainActor in
                if let window = note.object as? NSWindow { AppServices.shared.applyCapturePolicy(to: window) }
            }
        })
    }

    func stop() {
        monitor.stop()
        GlobalHotKey.shared.unregister()
        store.flush()
    }

    @discardableResult
    func applyHotKey() -> Bool {
        let config = HotKeyPrefs.load()
        return GlobalHotKey.shared.register(
            keyCode: config.keyCode,
            modifiers: config.modifiers
        ) { [weak self] in
            DispatchQueue.main.async {
                self?.picker.toggle()
            }
        }
    }

    // MARK: - Screen capture

    func applyCapturePolicy(to window: NSWindow) {
        window.sharingType = Prefs.bool(Prefs.hideFromScreenCapture) ? .none : .readOnly
    }

    func applyCapturePolicy() {
        NSApp.windows.forEach(applyCapturePolicy(to:))
    }

    // MARK: - Windows

    /// The main window is owned by AppKit rather than a SwiftUI `Window` scene
    /// so `open`, a menu action and the `clipvault://main` URL all reliably show
    /// the same window, including after it has been closed.
    func showMainWindow() {
        if let mainWindow {
            mainWindow.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1_100, height: 680),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = "ClipVault"
        window.titlebarAppearsTransparent = true
        window.toolbarStyle = .unified
        window.contentView = NSHostingView(rootView: MainView(store: store, monitor: monitor))
        window.contentMinSize = NSSize(width: 940, height: 560)
        window.isReleasedWhenClosed = false
        window.isRestorable = false
        window.center()
        window.setFrameAutosaveName("ClipVaultMain")
        applyCapturePolicy(to: window)
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)

        mainWindow = window
    }

    func showOnboarding() {
        if let onboardingWindow {
            onboardingWindow.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 620, height: 640),
            styleMask: [.titled, .closable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.isMovableByWindowBackground = true
        window.isReleasedWhenClosed = false
        window.contentView = NSHostingView(rootView: OnboardingView(store: store, monitor: monitor) { [weak self] in
            self?.onboardingWindow?.close()
            self?.onboardingWindow = nil
            self?.showMainWindow()
        })
        window.center()
        applyCapturePolicy(to: window)
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)

        onboardingWindow = window
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        let services = AppServices.shared
        services.start()
        if !Prefs.bool(Prefs.onboardingCompleted) {
            services.showOnboarding()
        } else if !launchedAsLoginItem {
            services.showMainWindow()
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        AppServices.shared.stop()
    }

    /// `clipvault://picker` opens the picker from Shortcuts, Raycast or a
    /// terminal. `clipvault://main` opens the history window and
    /// `clipvault://welcome` the welcome guide. URLs never carry content.
    func application(_ application: NSApplication, open urls: [URL]) {
        for url in urls {
            switch url.host ?? url.path.trimmingCharacters(in: CharacterSet(charactersIn: "/")) {
            case "picker": AppServices.shared.picker.show()
            case "main": AppServices.shared.showMainWindow()
            case "welcome": AppServices.shared.showOnboarding()
            default: break
            }
        }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        AppServices.shared.showMainWindow()
        return true
    }

    func applicationShouldSaveApplicationState(_ app: NSApplication) -> Bool { false }

    func applicationShouldRestoreApplicationState(_ app: NSApplication) -> Bool { false }

    /// Login items are opened with `kAELaunchedAsLogInItem`; do not pop a
    /// window in the user's face on every login.
    private var launchedAsLoginItem: Bool {
        guard let event = NSAppleEventManager.shared().currentAppleEvent,
              event.eventID == AEEventID(0x6F617070) else { // 'oapp'
            return false
        }
        let property = event.paramDescriptor(forKeyword: AEKeyword(0x70726474)) // 'prdt'
        return property?.enumCodeValue == 0x6C696769 // 'ligi'
    }
}

@main
struct ClipVaultApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    var body: some Scene {
        MenuBarExtra {
            MenuBarMenu(monitor: AppServices.shared.monitor, store: AppServices.shared.store)
        } label: {
            MenuBarLabel(monitor: AppServices.shared.monitor)
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView(store: AppServices.shared.store, monitor: AppServices.shared.monitor)
        }
    }
}
