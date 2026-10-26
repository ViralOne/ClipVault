import AppKit
import SwiftUI
import ClipVaultKit

enum MainSection: Hashable {
    case history(HistoryScope)
    case security
    case about
}

enum HistoryScope: String, CaseIterable, Identifiable {
    case all, pinned, text, links, images, secrets

    var id: String { rawValue }

    var title: String {
        switch self {
        case .all: return "All"
        case .pinned: return "Pinned"
        case .text: return "Text"
        case .links: return "Links"
        case .images: return "Images"
        case .secrets: return "Secrets"
        }
    }

    var symbol: String {
        switch self {
        case .all: return "clock.arrow.circlepath"
        case .pinned: return "pin"
        case .text: return "text.alignleft"
        case .links: return "link"
        case .images: return "photo.on.rectangle"
        case .secrets: return "key"
        }
    }

    func includes(_ item: HistoryItem) -> Bool {
        switch self {
        case .all: return true
        case .pinned: return item.pinned
        case .text: return !item.isImage && !item.isSecret && !item.isLink
        case .links: return item.isLink
        case .images: return item.isImage
        case .secrets: return item.isSecret
        }
    }
}

struct MainView: View {
    @ObservedObject var store: HistoryStore
    @ObservedObject var monitor: ClipboardMonitor
    @StateObject private var reveal = RevealState()

    @State private var section: MainSection? = .history(.all)
    @State private var selection: UUID?
    @State private var query = ""
    @State private var confirmDelete: HistoryItem?

    private var scope: HistoryScope? {
        if case .history(let scope) = section { return scope }
        return nil
    }

    private var filtered: [HistoryItem] {
        let scoped = store.items.filter { (scope ?? .all).includes($0) }
        return HistoryFilter.apply(scoped, query: query)
    }

    private var canReorder: Bool {
        scope == .all && query.trimmingCharacters(in: .whitespaces).isEmpty
    }

    private var selectedItem: HistoryItem? {
        guard let selection else { return nil }
        return store.items.first { $0.id == selection }
    }

    var body: some View {
        NavigationSplitView {
            sidebar
        } detail: {
            switch section ?? .history(.all) {
            case .history:
                historyPane
            case .security:
                SecurityView(store: store, monitor: monitor)
            case .about:
                AboutView()
            }
        }
        .frame(minWidth: 940, minHeight: 560)
        .onAppear { ensureSelection() }
        .onChange(of: store.items.count) { _, _ in ensureSelection() }
        .onChange(of: query) { _, _ in ensureSelection() }
        .onChange(of: section) { _, _ in ensureSelection() }
        .onChange(of: selection) { old, _ in
            if let old { reveal.hide(old) }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.willCloseNotification)) { _ in
            reveal.hideAll()
        }
        .alert(
            "Delete this item?",
            isPresented: Binding(get: { confirmDelete != nil }, set: { if !$0 { confirmDelete = nil } })
        ) {
            Button("Delete", role: .destructive) {
                if let item = confirmDelete { store.delete(item.id) }
                confirmDelete = nil
            }
            Button("Cancel", role: .cancel) { confirmDelete = nil }
        } message: {
            Text("The item and any encrypted image file are removed.")
        }
    }

    // MARK: - Sidebar

    private var sidebar: some View {
        List(selection: $section) {
            Section("Clipboard") {
                ForEach(HistoryScope.allCases) { scope in
                    sidebarRow(scope.title, symbol: scope.symbol, count: store.items.filter(scope.includes).count)
                        .tag(MainSection.history(scope))
                }
            }
            Section("Vault") {
                Label("Security", systemImage: "lock.shield")
                    .tag(MainSection.security)
                Label("About", systemImage: "info.circle")
                    .tag(MainSection.about)
            }
        }
        .listStyle(.sidebar)
        .navigationSplitViewColumnWidth(min: 190, ideal: 210, max: 260)
        .safeAreaInset(edge: .bottom, spacing: 0) {
            sidebarFooter
        }
    }

    private func sidebarRow(_ title: String, symbol: String, count: Int) -> some View {
        HStack {
            Label(title, systemImage: symbol)
            Spacer()
            Text("\(count)")
                .font(.system(size: 11.5).monospacedDigit())
                .foregroundStyle(.secondary)
        }
    }

    private var sidebarFooter: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(monitor.isPaused ? Color.orange : Color.green)
                .frame(width: 8, height: 8)
            Text(monitor.isPaused ? "Paused" : "Recording")
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
            Spacer()
            Image(systemName: SecretVault.shared.isAvailable ? "lock.shield.fill" : "lock.shield")
                .foregroundStyle(SecretVault.shared.isAvailable ? Color.green : Color.secondary)
                .help(SecretVault.shared.isAvailable ? "Secrets are sealed by the Secure Enclave" : "Secure Enclave unavailable")
            SettingsButton()
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }

    // MARK: - History

    private var historyPane: some View {
        HStack(spacing: 0) {
            VStack(spacing: 0) {
                listHeader
                if filtered.isEmpty {
                    emptyList
                } else {
                    itemList
                }
            }
            .frame(minWidth: 360, idealWidth: 430, maxWidth: .infinity)

            Divider()

            Group {
                if let item = selectedItem {
                    InspectorView(item: item, store: store, reveal: reveal) {
                        confirmDelete = item
                    }
                    .id(item.id)
                } else {
                    emptyInspector
                }
            }
            .frame(width: 380)
            .frame(maxHeight: .infinity)
        }
        .toolbar {
            ToolbarItemGroup {
                Button {
                    monitor.isPaused.toggle()
                } label: {
                    Image(systemName: monitor.isPaused ? "play.circle" : "pause.circle")
                }
                .help(monitor.isPaused ? "Resume recording" : "Pause recording")

                Button {
                    AppServices.shared.picker.show()
                } label: {
                    Image(systemName: "rectangle.and.text.magnifyingglass")
                }
                .help("Open the picker (\(HotKeyPrefs.load().display))")
            }
        }
        .searchable(text: $query, placement: .toolbar, prompt: "App, content, kind")
    }

    private var listHeader: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text(scope == .all ? "History" : scope?.title ?? "History")
                    .font(.system(size: 17, weight: .semibold))
                Text("\(filtered.count) of \(store.items.count) items")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if canReorder && filtered.count > 1 {
                Text("Drag to reorder")
                    .font(.system(size: 11.5))
                    .foregroundStyle(.tertiary)
            }
        }
        .padding(.horizontal, 20)
        .padding(.top, 14)
        .padding(.bottom, 8)
    }

    private var itemList: some View {
        List(selection: $selection) {
            ForEach(filtered) { item in
                HistoryCard(item: item, selected: selection == item.id)
                    .tag(item.id)
                    .listRowInsets(EdgeInsets(top: 3, leading: 12, bottom: 3, trailing: 12))
                    .listRowSeparator(.hidden)
                    .listRowBackground(Color.clear)
                    .moveDisabled(!canReorder)
                    .contextMenu { contextMenu(for: item) }
            }
            .onMove { source, destination in
                guard canReorder else { return }
                store.move(from: source, to: destination)
            }
        }
        .listStyle(.plain)
        .scrollContentBackground(.hidden)
    }

    @ViewBuilder
    private func contextMenu(for item: HistoryItem) -> some View {
        Button("Copy") { copy(item) }
        Button(item.pinned ? "Unpin" : "Pin") { store.togglePin(item.id) }
        Divider()
        Button("Move Up") { store.move(item.id, by: -1) }
            .disabled(!store.canMove(item.id, by: -1))
        Button("Move Down") { store.move(item.id, by: 1) }
            .disabled(!store.canMove(item.id, by: 1))
        Divider()
        Button("Delete…", role: .destructive) { confirmDelete = item }
    }

    private var emptyList: some View {
        VStack(spacing: 8) {
            Image(systemName: store.items.isEmpty ? "clipboard" : "magnifyingglass")
                .font(.system(size: 30, weight: .light))
                .foregroundStyle(.tertiary)
            Text(store.items.isEmpty ? "No history yet" : "No matches")
                .font(.system(size: 14, weight: .semibold))
            Text(store.items.isEmpty ? "Copy text or an image in any app to start." : "Try another search or filter.")
                .font(.system(size: 12.5))
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var emptyInspector: some View {
        VStack(spacing: 12) {
            AppIconImage(size: 72)
            Text("Select an item")
                .font(.system(size: 14, weight: .semibold))
            Text("Press \(HotKeyPrefs.load().display) in any app to search and paste.")
                .font(.system(size: 12.5))
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(30)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func copy(_ item: HistoryItem) {
        Task {
            if let payload = await ClipAccess.payload(for: item, store: store, verb: "Copy") {
                PasteService.copy(payload)
            }
        }
    }

    private func ensureSelection() {
        let items = filtered
        if let selection, items.contains(where: { $0.id == selection }) { return }
        selection = items.first?.id
    }
}

// MARK: - Row card

struct HistoryCard: View {
    let item: HistoryItem
    let selected: Bool

    var body: some View {
        HStack(alignment: .top, spacing: 11) {
            ItemIcon(item: item, size: 30)

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(item.sourceApp ?? "Unknown app")
                        .font(.system(size: 13.5, weight: .semibold))
                        .lineLimit(1)
                    if item.isSecret {
                        Image(systemName: "lock.fill")
                            .font(.system(size: 10))
                            .foregroundStyle(.green)
                    }
                    Spacer(minLength: 6)
                    if item.pinned {
                        Image(systemName: "pin.fill")
                            .font(.system(size: 10))
                            .foregroundStyle(.secondary)
                    }
                    Text(clockTime(item.createdAt))
                        .font(.system(size: 11.5).monospacedDigit())
                        .foregroundStyle(.secondary)
                }

                Text(preview)
                    .font(.system(size: 12.5))
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(selected ? Color.primary.opacity(0.11) : Color.primary.opacity(0.04))
        )
        .contentShape(Rectangle())
    }

    private var preview: String {
        if item.isSecret {
            return item.isImage ? "•••• \(item.displayKind ?? "Secret") in an image" : "•••• \(item.displayKind ?? "Secret") · \(item.characterCount) chars"
        }
        if item.isImage {
            let text = item.ocrText.map { " · \($0.replacingOccurrences(of: "\n", with: " "))" } ?? ""
            return "Image \(item.imageWidth)×\(item.imageHeight)\(text)"
        }
        return item.text
            .replacingOccurrences(of: "\n", with: " ⏎ ")
            .trimmingCharacters(in: .whitespaces)
    }
}

// MARK: - Inspector

struct InspectorView: View {
    let item: HistoryItem
    @ObservedObject var store: HistoryStore
    @ObservedObject var reveal: RevealState
    var onDelete: () -> Void

    private var current: HistoryItem {
        store.items.first { $0.id == item.id } ?? item
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    header
                    MetadataGrid(rows: rows, labelWidth: 84)
                    contentSection
                }
                .padding(22)
            }
            Divider()
            actions
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            if current.isSecret || current.isImage {
                ItemIcon(item: current, size: 46)
            } else {
                AppIconView(bundleID: current.sourceBundleID, appName: current.sourceApp, size: 46, fallback: kindSymbol(for: current))
            }
            VStack(alignment: .leading, spacing: 3) {
                Text(current.sourceApp ?? "Unknown app")
                    .font(.system(size: 19, weight: .semibold))
                    .lineLimit(1)
                if let bundleID = current.sourceBundleID {
                    Text(bundleID)
                        .font(.system(size: 11.5, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                HStack(spacing: 5) {
                    if current.pinned { Badge(text: "PINNED", tint: .orange) }
                    if current.isSecret { Badge(text: "SECRET", tint: .green) }
                    if current.isImage { Badge(text: "IMAGE", tint: .purple) }
                }
            }
        }
    }

    private var rows: [(String, String)] {
        var rows: [(String, String)] = [
            ("When", copiedDate(current.createdAt)),
            ("Kind", current.kindLabel)
        ]
        rows.append(("Content", contentSummary(for: current)))
        if current.isSecret {
            rows.append(("Protection", current.isSealed ? "Secure Enclave seal" : "Encrypted at rest"))
        } else {
            rows.append(("Storage", "AES-256-GCM, this Mac only"))
        }
        return rows
    }

    @ViewBuilder
    private var contentSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Content")
                .font(.system(size: 14, weight: .semibold))

            Group {
                if current.isSecret {
                    SecretPanel(item: current, reveal: reveal, store: store, compact: true)
                        .padding(16)
                } else if current.isImage {
                    ImagePreview(item: current, store: store)
                        .frame(minHeight: 260)
                } else {
                    Text(current.text.count > 8_000 ? String(current.text.prefix(8_000)) + "…" : current.text)
                        .font(.system(size: 13, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(14)
                }
            }
            .background(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(Color.primary.opacity(0.045))
            )
        }
    }

    private var actions: some View {
        HStack(spacing: 8) {
            Button {
                Task {
                    if let payload = await ClipAccess.payload(for: current, store: store, verb: "Copy") {
                        PasteService.copy(payload)
                    }
                }
            } label: {
                Label("Copy", systemImage: "doc.on.doc")
            }
            .buttonStyle(.borderedProminent)

            Button {
                store.togglePin(current.id)
            } label: {
                Image(systemName: current.pinned ? "pin.slash" : "pin")
            }
            .help(current.pinned ? "Unpin" : "Pin to the top")

            Button {
                store.move(current.id, by: -1)
            } label: {
                Image(systemName: "arrow.up")
            }
            .help("Move up")
            .disabled(!store.canMove(current.id, by: -1))

            Button {
                store.move(current.id, by: 1)
            } label: {
                Image(systemName: "arrow.down")
            }
            .help("Move down")
            .disabled(!store.canMove(current.id, by: 1))

            Spacer()

            Button(role: .destructive, action: onDelete) {
                Image(systemName: "trash")
            }
            .help("Delete")
        }
        .controlSize(.large)
    }
}

/// Opens the Settings window and brings it to the front, which an accessory
/// app has to do explicitly.
struct SettingsButton: View {
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        Button {
            NSApp.activate(ignoringOtherApps: true)
            openSettings()
        } label: {
            Image(systemName: "gearshape")
        }
        .buttonStyle(.borderless)
        .help("Settings")
    }
}
