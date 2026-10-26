import AppKit
import Combine
import SwiftUI
import ClipVaultKit

@MainActor
final class PickerModel: ObservableObject {
    @Published var query = "" {
        didSet {
            guard query != oldValue else { return }
            selection = filtered.first?.id
        }
    }
    @Published var selection: UUID?
    @Published var isBusy = false

    let store: HistoryStore
    let reveal = RevealState()
    var onPick: ((HistoryItem) -> Void)?
    var onOpenMain: (() -> Void)?
    private var storeObserver: AnyCancellable?

    init(store: HistoryStore) {
        self.store = store
        storeObserver = store.objectWillChange.sink { [weak self] _ in
            self?.objectWillChange.send()
            // Keep a valid selection when items are added or pruned.
            DispatchQueue.main.async { self?.selectFirstIfNeeded() }
        }
    }

    /// Stored order: pinned items first, then the rest.
    var filtered: [HistoryItem] {
        HistoryFilter.apply(store.items, query: query)
    }

    var selectedItem: HistoryItem? {
        guard let selection else { return nil }
        return filtered.first { $0.id == selection }
    }

    func selectFirstIfNeeded() {
        if selection == nil || selectedItem == nil { selection = filtered.first?.id }
    }

    func moveSelection(_ delta: Int) {
        let items = filtered
        guard !items.isEmpty else { return }
        if let index = items.firstIndex(where: { $0.id == selection }) {
            selection = items[min(max(index + delta, 0), items.count - 1)].id
        } else {
            selection = items.first?.id
        }
    }

    /// Reorders the selected item in the stored history. Only possible while
    /// the list is unfiltered, because the picker shows stored order.
    func moveSelectedItem(by delta: Int) {
        guard let item = selectedItem else { return }
        guard query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            HUD.show("Clear the search to reorder", symbol: "arrow.up.arrow.down")
            return
        }
        store.move(item.id, by: delta)
        selection = item.id
    }

    func activateSelected() {
        guard !isBusy, let item = selectedItem else { return }
        onPick?(item)
    }

    func quickPick(_ number: Int) {
        let items = filtered
        guard number >= 1, number <= min(9, items.count) else { return }
        selection = items[number - 1].id
        activateSelected()
    }

    func togglePinOnSelection() {
        guard let item = selectedItem else { return }
        PasteService.togglePin(item, store: store)
        selection = item.id
    }

    func deleteSelection() {
        guard let item = selectedItem else { return }
        let items = filtered
        let index = items.firstIndex(where: { $0.id == item.id }) ?? 0
        reveal.hide(item.id)
        store.delete(item.id)
        let remaining = filtered
        selection = remaining.isEmpty ? nil : remaining[min(index, remaining.count - 1)].id
    }

    func toggleRevealOnSelection() {
        guard let item = selectedItem, item.isSecret else { return }
        if reveal.isRevealed(item.id) {
            reveal.hide(item.id)
        } else {
            Task { await reveal.reveal(item, store: store) }
        }
    }
}

/// Owns the floating picker panel and translates keyboard events into model
/// actions. A local event monitor is used so arrow keys work while the search
/// field is focused.
@MainActor
final class PickerController {
    static let size = NSSize(width: 720, height: 440)

    private let store: HistoryStore
    private var panel: KeyPanel?
    private var model: PickerModel?
    private var keyMonitor: Any?
    private var observers: [NSObjectProtocol] = []
    private var previousApp: NSRunningApplication?
    private var authObserver: AnyCancellable?

    init(store: HistoryStore) {
        self.store = store
    }

    var isVisible: Bool { panel?.isVisible ?? false }

    // MARK: - Presentation

    func toggle() {
        isVisible ? hide(reactivate: true) : show()
    }

    func show() {
        rememberPreviousApp()
        buildModel()

        let panel = ensurePanel()
        let hosting = NSHostingView(rootView: PickerView(model: model!))
        hosting.frame = NSRect(origin: .zero, size: Self.size)
        panel.contentView = hosting
        panel.setContentSize(Self.size)
        position(panel)
        AppServices.shared.applyCapturePolicy(to: panel)

        NSApp.activate(ignoringOtherApps: true)
        panel.alphaValue = 0
        panel.makeKeyAndOrderFront(nil)
        NSAnimationContext.runAnimationGroup { context in
            context.duration = 0.12
            panel.animator().alphaValue = 1
        }

        installKeyMonitor()
        model?.selectFirstIfNeeded()
    }

    private func buildModel() {
        let model = PickerModel(store: store)
        model.onPick = { [weak self] item in self?.pick(item) }
        model.onOpenMain = { [weak self] in
            self?.hide(reactivate: false)
            AppServices.shared.showMainWindow()
        }
        self.model = model

        // The Touch ID dialog belongs to another process and takes focus.
        // Keep the panel up while it is showing, then bring it back to the
        // front so the revealed secret is visible.
        authObserver = model.$isBusy
            .combineLatest(model.reveal.$authenticatingID.map { $0 != nil })
            .map { $0 || $1 }
            .removeDuplicates()
            .sink { [weak self] busy in
                Task { @MainActor in self?.authenticationChanged(busy) }
            }
    }

    private func authenticationChanged(_ busy: Bool) {
        guard let panel else { return }
        if busy {
            panel.hidesOnDeactivate = false
        } else {
            panel.hidesOnDeactivate = true
            guard panel.isVisible else { return }
            NSApp.activate(ignoringOtherApps: true)
            panel.makeKeyAndOrderFront(nil)
        }
    }

    private func ensurePanel() -> KeyPanel {
        if let panel { return panel }

        let panel = KeyPanel(
            contentRect: NSRect(origin: .zero, size: Self.size),
            styleMask: [.borderless, .nonactivatingPanel, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        panel.level = .floating
        panel.isFloatingPanel = true
        panel.hidesOnDeactivate = true
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        // Drag the panel by any empty area to move it; the spot is remembered.
        panel.isMovable = true
        panel.isMovableByWindowBackground = true
        panel.animationBehavior = .none
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .transient]

        observers.append(NotificationCenter.default.addObserver(
            forName: NSWindow.didMoveNotification,
            object: panel,
            queue: .main
        ) { [weak panel] _ in
            Task { @MainActor in
                guard let panel, panel.isVisible else { return }
                UserDefaults.standard.set(NSStringFromPoint(panel.frame.origin), forKey: Prefs.pickerOrigin)
            }
        })
        observers.append(NotificationCenter.default.addObserver(
            forName: NSWindow.didResignKeyNotification,
            object: panel,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.handleResignKey() }
        })

        self.panel = panel
        return panel
    }

    private func position(_ panel: NSPanel) {
        let size = panel.frame.size
        if let saved = UserDefaults.standard.string(forKey: Prefs.pickerOrigin) {
            let origin = NSPointFromString(saved)
            let frame = NSRect(origin: origin, size: size)
            if NSScreen.screens.contains(where: { $0.visibleFrame.intersects(frame.insetBy(dx: 80, dy: 80)) }) {
                panel.setFrameOrigin(origin)
                return
            }
        }

        let mouseLocation = NSEvent.mouseLocation
        let screen = NSScreen.screens.first(where: { $0.frame.contains(mouseLocation) }) ?? NSScreen.main
        guard let visible = screen?.visibleFrame else { return }
        let x = visible.midX - size.width / 2
        let y = visible.maxY - size.height - visible.height * 0.16
        panel.setFrameOrigin(NSPoint(x: x, y: max(visible.minY + 40, y)))
    }

    static func resetPosition() {
        UserDefaults.standard.removeObject(forKey: Prefs.pickerOrigin)
    }

    private func rememberPreviousApp() {
        // Opened from ClipVault itself: there is no other app to paste into.
        guard let front = NSWorkspace.shared.frontmostApplication,
              front.bundleIdentifier != Bundle.main.bundleIdentifier else {
            previousApp = nil
            return
        }
        previousApp = front
    }

    // MARK: - Dismissal and picking

    func hide(reactivate: Bool) {
        removeKeyMonitor()
        model?.reveal.hideAll()
        panel?.orderOut(nil)
        if reactivate, let previousApp, previousApp.bundleIdentifier != Bundle.main.bundleIdentifier {
            previousApp.activate()
        }
    }

    private func pick(_ item: HistoryItem) {
        guard let model, !model.isBusy else { return }
        let target = previousApp

        if let revealed = model.reveal.payload(for: item.id) {
            finishPicking(revealed, target: target)
            return
        }

        model.isBusy = true
        Task {
            let payload = await ClipAccess.payload(for: item, store: store, verb: "Paste")
            model.isBusy = false
            guard let payload else { return }
            finishPicking(payload, target: target)
        }
    }

    private func finishPicking(_ payload: ClipPayload, target: NSRunningApplication?) {
        hide(reactivate: false)
        PasteService.paste(payload, into: target)
    }

    private func handleResignKey() {
        // Touch ID dialogs take key status; keep the panel for those.
        guard let model, !model.isBusy, !model.reveal.isAuthenticating else { return }
        // Defer, so a dialog that is just appearing has flipped the busy flag.
        DispatchQueue.main.async { [weak self] in
            guard let self, let panel = self.panel, panel.isVisible, !panel.isKeyWindow,
                  let model = self.model, !model.isBusy, !model.reveal.isAuthenticating else { return }
            self.hide(reactivate: false)
        }
    }

    // MARK: - Keyboard

    private func installKeyMonitor() {
        removeKeyMonitor()
        keyMonitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
            guard let self, let panel = self.panel, panel.isVisible, panel.isKeyWindow,
                  let model = self.model else { return event }
            let command = event.modifierFlags.contains(.command)

            switch Int(event.keyCode) {
            case 53: // escape
                if !model.query.isEmpty {
                    model.query = ""
                } else {
                    self.hide(reactivate: true)
                }
                return nil
            case 126: // up arrow
                command ? model.moveSelectedItem(by: -1) : model.moveSelection(-1)
                return nil
            case 125: // down arrow
                command ? model.moveSelectedItem(by: 1) : model.moveSelection(1)
                return nil
            case 36, 76: // return, keypad enter
                model.activateSelected()
                return nil
            case 35 where command: // ⌘P
                model.togglePinOnSelection()
                return nil
            case 15 where command: // ⌘R
                model.toggleRevealOnSelection()
                return nil
            case 51 where command: // ⌘⌫
                model.deleteSelection()
                return nil
            case 31 where command: // ⌘O
                model.onOpenMain?()
                return nil
            default:
                if command, let number = Self.digit(for: event.keyCode) {
                    model.quickPick(number)
                    return nil
                }
                return event
            }
        }
    }

    private static func digit(for keyCode: UInt16) -> Int? {
        let map: [UInt16: Int] = [18: 1, 19: 2, 20: 3, 21: 4, 23: 5, 22: 6, 26: 7, 28: 8, 25: 9]
        return map[keyCode]
    }

    private func removeKeyMonitor() {
        if let keyMonitor {
            NSEvent.removeMonitor(keyMonitor)
            self.keyMonitor = nil
        }
    }
}

private final class KeyPanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { true }
}
