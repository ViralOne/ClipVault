import AppKit
import SwiftUI
import ClipVaultKit

// MARK: - Reveal state

/// Secrets the user has unsealed with Touch ID. Each one hides itself again
/// after 30 seconds, and everything is dropped when the owning view goes away.
@MainActor
final class RevealState: ObservableObject {
    static let revealSeconds: Double = 30

    @Published private(set) var revealed: [UUID: ClipPayload] = [:]
    @Published private(set) var authenticatingID: UUID?
    private var timers: [UUID: DispatchWorkItem] = [:]
    private var lockObserver: NSObjectProtocol?

    init() {
        lockObserver = NotificationCenter.default.addObserver(
            forName: Biometrics.didLockNotification, object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.hideAll() }
        }
    }

    var isAuthenticating: Bool { authenticatingID != nil }

    func isRevealed(_ id: UUID) -> Bool { revealed[id] != nil }

    func payload(for id: UUID) -> ClipPayload? { revealed[id] }

    func reveal(_ item: HistoryItem, store: HistoryStore) async {
        guard authenticatingID == nil, !isRevealed(item.id) else { return }
        authenticatingID = item.id
        let payload = await ClipAccess.payload(for: item, store: store, verb: "Reveal")
        authenticatingID = nil
        guard let payload else { return }

        revealed[item.id] = payload
        timers[item.id]?.cancel()
        let work = DispatchWorkItem { [weak self] in
            Task { @MainActor in self?.hide(item.id) }
        }
        timers[item.id] = work
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.revealSeconds, execute: work)
    }

    func hide(_ id: UUID) {
        timers[id]?.cancel()
        timers[id] = nil
        revealed[id] = nil
    }

    func hideAll() {
        timers.values.forEach { $0.cancel() }
        timers.removeAll()
        revealed.removeAll()
    }
}

// MARK: - Secret panel

struct SecretPanel: View {
    let item: HistoryItem
    @ObservedObject var reveal: RevealState
    let store: HistoryStore
    var compact = false

    private var payload: ClipPayload? { reveal.payload(for: item.id) }

    var body: some View {
        VStack(spacing: compact ? 12 : 16) {
            Image(systemName: "lock.shield.fill")
                .font(.system(size: compact ? 34 : 42))
                .symbolRenderingMode(.palette)
                .foregroundStyle(.white, Color.green.gradient)

            Text(item.displayKind ?? "Secret")
                .font(.system(size: compact ? 17 : 19, weight: .semibold))
                .multilineTextAlignment(.center)

            if item.isImage, let data = payload?.imageData, let image = NSImage(data: data) {
                Image(nsImage: image)
                    .resizable()
                    .scaledToFit()
                    .frame(maxHeight: 150)
                    .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            }

            valuePill

            Button(payload == nil ? "Reveal" : "Hide") {
                if payload == nil {
                    Task { await reveal.reveal(item, store: store) }
                } else {
                    reveal.hide(item.id)
                }
            }
            .controlSize(.large)
            .disabled(reveal.isAuthenticating)

            Text(explanation)
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.leading)
                .frame(maxWidth: .infinity, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity)
    }

    private var valuePill: some View {
        Group {
            if let text = payload?.text {
                ScrollView {
                    Text(text)
                        .font(.system(size: 13.5, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .center)
                }
                .frame(maxHeight: 90)
            } else {
                Text(item.isImage ? item.maskedOCRPreview : item.maskedPreview)
                    .font(.system(size: 15, weight: .medium, design: .monospaced))
                    .lineLimit(1)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(Color.primary.opacity(0.06))
        )
    }

    private var explanation: String {
        if payload != nil {
            return "Hides again in \(Int(RevealState.revealSeconds)) seconds."
        }
        if compact {
            return "Touch ID to reveal or paste. Pastes concealed, so other clipboard managers skip it."
        }
        let seal = item.isSealed
            ? "Sealed by the Secure Enclave — it can't be decrypted without you."
            : "Encrypted at rest."
        return "Touch ID to reveal or paste. Pastes as concealed, so other clipboard managers skip it. \(seal)"
    }
}

// MARK: - Content preview

/// The content area for any item: text, code, image with recognised text, or
/// the secret panel.
struct ContentPreview: View {
    let item: HistoryItem
    @ObservedObject var reveal: RevealState
    let store: HistoryStore
    var textSize: CGFloat = 14

    var body: some View {
        if item.isSecret {
            ScrollView {
                SecretPanel(item: item, reveal: reveal, store: store, compact: true)
                    .padding(.horizontal, 24)
                    .padding(.vertical, 26)
            }
        } else if item.isImage {
            ImagePreview(item: item, store: store)
        } else {
            ScrollView {
                Text(item.text.count > 20_000 ? String(item.text.prefix(20_000)) + "…" : item.text)
                    .font(item.looksLikeCode
                          ? .system(size: textSize - 1, design: .monospaced)
                          : .system(size: textSize))
                    .lineSpacing(item.looksLikeCode ? 2 : 3)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .topLeading)
                    .padding(.horizontal, 22)
                    .padding(.vertical, 18)
            }
        }
    }
}

struct ImagePreview: View {
    let item: HistoryItem
    let store: HistoryStore

    @State private var image: NSImage?
    @State private var loaded = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                ZStack {
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .fill(Color.primary.opacity(0.04))
                    if let image {
                        Image(nsImage: image)
                            .resizable()
                            .scaledToFit()
                            .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
                            .padding(10)
                    } else if loaded {
                        Label("Image unavailable", systemImage: "exclamationmark.triangle")
                            .font(.system(size: 12))
                            .foregroundStyle(.secondary)
                            .padding(30)
                    } else {
                        ProgressView().controlSize(.small).padding(30)
                    }
                }
                .frame(maxWidth: .infinity, minHeight: 120, maxHeight: 260)

                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Label("Recognised text", systemImage: "text.viewfinder")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundStyle(.secondary)
                        Spacer()
                        if let text = item.ocrText, !text.isEmpty {
                            Button("Copy text") {
                                PasteboardWriter.write(text, concealed: false)
                                HUD.show("Recognised text copied")
                            }
                            .buttonStyle(.link)
                            .font(.system(size: 12))
                        }
                    }
                    if let text = item.ocrText, !text.isEmpty {
                        Text(text)
                            .font(.system(size: 12.5))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    } else {
                        Text("No text found in this image.")
                            .font(.system(size: 12.5))
                            .foregroundStyle(.tertiary)
                    }
                }
            }
            .padding(18)
        }
        .task(id: item.id) {
            image = store.imageData(for: item).flatMap(NSImage.init(data:))
            loaded = true
        }
    }
}
