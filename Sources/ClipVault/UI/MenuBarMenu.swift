import AppKit
import SwiftUI
import ClipVaultKit

/// The window shown from the menu bar icon: status, a quick search over recent
/// items and the app's main commands.
struct MenuBarMenu: View {
    @ObservedObject var monitor: ClipboardMonitor
    @ObservedObject var store: HistoryStore
    @Environment(\.openSettings) private var openSettings
    @State private var query = ""
    @State private var hovered: UUID?

    private var items: [HistoryItem] {
        Array(HistoryFilter.apply(store.items, query: query).prefix(7))
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider().padding(.top, 10)
            list
            Divider()
            HStack {
                menuButton("Conceal clipboard now") {
                    if monitor.concealCurrentClipboard() {
                        HUD.show("Clipboard concealed", symbol: "lock.fill")
                    } else {
                        HUD.show("No text on the clipboard", symbol: "exclamationmark.circle")
                    }
                }
                Spacer()
                menuButton("Open ClipVault") {
                    closeMenu()
                    AppServices.shared.showMainWindow()
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            Divider()
            HStack(spacing: 16) {
                menuButton(monitor.isPaused ? "Resume" : "Pause") {
                    monitor.isPaused.toggle()
                }
                menuButton("Settings…") {
                    closeMenu()
                    NSApp.activate(ignoringOtherApps: true)
                    openSettings()
                }
                Spacer()
                menuButton("Quit") {
                    AppServices.shared.stop()
                    NSApp.terminate(nil)
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
        }
        .frame(width: 380)
    }

    private var header: some View {
        VStack(spacing: 10) {
            HStack {
                Text("ClipVault")
                    .font(.system(size: 15, weight: .bold))
                Spacer()
                Text(monitor.isPaused ? "Paused" : "Recording")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(monitor.isPaused ? Color.orange : Color.green)
            }

            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                TextField("Search clipboard history", text: $query)
                    .textFieldStyle(.plain)
                    .font(.system(size: 14))
                Text(HotKeyPrefs.load().display)
                    .font(.system(size: 12))
                    .foregroundStyle(.tertiary)
            }
            .padding(.horizontal, 11)
            .frame(height: 34)
            .background(
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill(Color.primary.opacity(0.07))
            )
        }
        .padding(.horizontal, 14)
        .padding(.top, 14)
    }

    @ViewBuilder
    private var list: some View {
        if items.isEmpty {
            Text(store.items.isEmpty ? "Copied items appear here." : "No matches")
                .font(.system(size: 13))
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 26)
        } else {
            VStack(spacing: 0) {
                ForEach(items) { item in
                    Button {
                        copy(item)
                    } label: {
                        row(item)
                    }
                    .buttonStyle(.plain)
                    .onHover { hovered = $0 ? item.id : (hovered == item.id ? nil : hovered) }
                }
            }
            .padding(.vertical, 6)
            .padding(.horizontal, 6)
        }
    }

    private func row(_ item: HistoryItem) -> some View {
        HStack(spacing: 11) {
            ItemIcon(item: item, size: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(item.isSecret ? item.title : (item.isImage ? item.imageTitle : item.textTitle))
                    .font(.system(size: 13.5))
                    .lineLimit(1)
                Text([item.sourceApp, relativeTime(item.createdAt)].compactMap { $0 }.joined(separator: " · "))
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .background(
            RoundedRectangle(cornerRadius: 7, style: .continuous)
                .fill(hovered == item.id ? Color.primary.opacity(0.08) : .clear)
        )
        .contentShape(Rectangle())
    }

    private func menuButton(_ title: String, action: @escaping () -> Void) -> some View {
        Button(title, action: action)
            .buttonStyle(.plain)
            .font(.system(size: 13.5))
            .foregroundStyle(.secondary)
    }

    private func copy(_ item: HistoryItem) {
        closeMenu()
        Task {
            if let payload = await ClipAccess.payload(for: item, store: store, verb: "Copy") {
                PasteService.copy(payload)
            }
        }
    }

    /// MenuBarExtra windows have no dismiss action; ordering the key window
    /// out closes it.
    private func closeMenu() {
        NSApp.keyWindow?.orderOut(nil)
    }
}

struct MenuBarLabel: View {
    @ObservedObject var monitor: ClipboardMonitor

    var body: some View {
        Image(systemName: monitor.isPaused ? "pause.circle" : "lock.doc")
            .accessibilityLabel(monitor.isPaused ? "ClipVault is paused" : "ClipVault is protecting the clipboard")
    }
}
