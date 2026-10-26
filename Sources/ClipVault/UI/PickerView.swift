import SwiftUI
import ClipVaultKit

struct PickerView: View {
    @ObservedObject var model: PickerModel
    @ObservedObject private var reveal: RevealState
    @FocusState private var searchFocused: Bool

    init(model: PickerModel) {
        self.model = model
        self.reveal = model.reveal
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            HStack(spacing: 0) {
                list
                    .frame(width: 300)
                Divider()
                detail
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            Divider()
            footer
        }
        .frame(width: PickerController.size.width, height: PickerController.size.height)
        .background(.regularMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .strokeBorder(Color.primary.opacity(0.1), lineWidth: 0.5)
        )
        .onAppear {
            DispatchQueue.main.async { searchFocused = true }
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 18, weight: .regular))
                .foregroundStyle(.secondary)

            TextField("Search clipboard history", text: $model.query)
                .textFieldStyle(.plain)
                .font(.system(size: 20))
                .focused($searchFocused)

            if model.isBusy || reveal.isAuthenticating {
                ProgressView().controlSize(.small)
            }
        }
        .padding(.horizontal, 18)
        .frame(height: 52)
    }

    // MARK: - List

    @ViewBuilder
    private var list: some View {
        let items = model.filtered
        if model.store.items.isEmpty {
            emptyState(
                symbol: "clipboard",
                title: "Nothing copied yet",
                message: "Copy text or an image in any app and it appears here."
            )
        } else if items.isEmpty {
            emptyState(symbol: "magnifyingglass", title: "No results", message: "Nothing matches “\(model.query)”.")
        } else {
            let pinned = items.filter(\.pinned)
            let recent = items.filter { !$0.pinned }
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        if !pinned.isEmpty {
                            sectionHeader("Pinned")
                            ForEach(Array(pinned.enumerated()), id: \.element.id) { offset, item in
                                row(item, number: offset + 1)
                            }
                        }
                        if !recent.isEmpty {
                            sectionHeader("Recent")
                            ForEach(Array(recent.enumerated()), id: \.element.id) { offset, item in
                                row(item, number: pinned.count + offset + 1)
                            }
                        }
                    }
                    .padding(.horizontal, 8)
                    .padding(.bottom, 8)
                }
                .scrollIndicators(.never)
                .onChange(of: model.selection) { _, newValue in
                    guard let newValue else { return }
                    withAnimation(.easeOut(duration: 0.1)) {
                        proxy.scrollTo(newValue)
                    }
                }
            }
        }
    }

    private func sectionHeader(_ title: String) -> some View {
        Text(title)
            .font(.system(size: 12, weight: .semibold))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 12)
            .padding(.top, 12)
            .padding(.bottom, 4)
    }

    private func row(_ item: HistoryItem, number: Int) -> some View {
        let selected = model.selection == item.id

        return HStack(spacing: 11) {
            ItemIcon(item: item, size: 30, selected: selected)

            VStack(alignment: .leading, spacing: 2) {
                Text(item.title)
                    .font(.system(size: 13.5, weight: .medium))
                    .lineLimit(1)
                Text(subtitle(item))
                    .font(.system(size: 12))
                    .foregroundStyle(selected ? Color.white.opacity(0.85) : Color.secondary)
                    .lineLimit(1)
            }

            Spacer(minLength: 4)

            if item.pinned {
                Image(systemName: "pin.fill")
                    .font(.system(size: 11))
                    .foregroundStyle(selected ? Color.white.opacity(0.9) : Color.secondary)
            }
            if number <= 9 {
                Text("⌘\(number)")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(selected ? Color.white : Color.secondary.opacity(0.8))
            }
        }
        .foregroundStyle(selected ? Color.white : Color.primary)
        .padding(.horizontal, 10)
        .frame(height: 46)
        .background(
            RoundedRectangle(cornerRadius: 9, style: .continuous)
                .fill(selected ? Color.accentColor : Color.clear)
        )
        .contentShape(Rectangle())
        .id(item.id)
        .onTapGesture(count: 2) {
            model.selection = item.id
            model.activateSelected()
        }
        .simultaneousGesture(TapGesture().onEnded { model.selection = item.id })
    }

    private func subtitle(_ item: HistoryItem) -> String {
        [item.sourceApp, relativeTime(item.createdAt)].compactMap { $0 }.joined(separator: " · ")
    }

    private func emptyState(symbol: String, title: String, message: String) -> some View {
        VStack(spacing: 8) {
            Image(systemName: symbol)
                .font(.system(size: 26, weight: .light))
                .foregroundStyle(.tertiary)
            Text(title)
                .font(.system(size: 13, weight: .semibold))
            Text(message)
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Detail

    @ViewBuilder
    private var detail: some View {
        if let item = model.selectedItem {
            VStack(spacing: 0) {
                ContentPreview(item: item, reveal: reveal, store: model.store)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .id(item.id)
                Divider()
                MetadataGrid(rows: metadataRows(for: item))
                    .padding(.horizontal, 22)
                    .padding(.vertical, 14)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            VStack(spacing: 10) {
                AppIconImage(size: 64)
                Text("Press \(HotKeyPrefs.load().display) anywhere to open this picker.")
                    .font(.system(size: 12.5))
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    // MARK: - Footer

    private var footer: some View {
        HStack(spacing: 12) {
            ShortcutHint(keys: "↩", label: "Paste")
            ShortcutHint(keys: "⌘1–9", label: "Quick pick")
            ShortcutHint(keys: "⌘P", label: "Pin")
            if model.selectedItem?.isSecret == true {
                ShortcutHint(keys: "⌘R", label: reveal.isRevealed(model.selection ?? UUID()) ? "Hide" : "Reveal")
            }
            ShortcutHint(keys: "⌘⌫", label: "Delete")

            Spacer(minLength: 8)

            Text("\(model.store.items.count) items · encrypted")
                .font(.system(size: 12))
                .foregroundStyle(.tertiary)
                .lineLimit(1)
                .fixedSize()

            Button {
                model.onOpenMain?()
            } label: {
                Image(systemName: "macwindow")
                    .font(.system(size: 13))
            }
            .buttonStyle(.plain)
            .foregroundStyle(.secondary)
            .help("Open ClipVault (⌘O)")
        }
        .padding(.horizontal, 14)
        .frame(height: 38)
    }
}
