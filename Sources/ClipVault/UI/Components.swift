import AppKit
import SwiftUI
import ClipVaultKit

// MARK: - Formatting

func relativeTime(_ date: Date, now: Date = Date()) -> String {
    let seconds = Int(now.timeIntervalSince(date))
    switch seconds {
    case ..<45: return "just now"
    case ..<3_600: return "\(max(1, seconds / 60)) min ago"
    case ..<86_400: return "\(seconds / 3_600) hr ago"
    case ..<604_800:
        let days = seconds / 86_400
        return days == 1 ? "yesterday" : "\(days) days ago"
    default:
        return date.formatted(.dateTime.day().month(.abbreviated))
    }
}

func copiedDate(_ date: Date) -> String {
    let day = date.formatted(.dateTime.day().month(.abbreviated).year())
    let time = date.formatted(.dateTime.hour().minute())
    return "\(day) at \(time)"
}

func clockTime(_ date: Date) -> String {
    date.formatted(.dateTime.hour(.twoDigits(amPM: .omitted)).minute().second())
}

func byteString(_ bytes: Int) -> String {
    ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
}

func contentSummary(for item: HistoryItem) -> String {
    if item.isImage {
        let format = item.imageUTI == "public.jpeg" ? "JPEG" : "PNG"
        var parts = ["\(item.imageWidth) × \(item.imageHeight)", format]
        if item.hasSecretText {
            parts.append("secret text")
        } else if let text = item.ocrText, !text.isEmpty {
            parts.append("\(text.count) characters recognised")
        }
        return parts.joined(separator: " · ")
    }
    if item.isSecret {
        return "\(item.characterCount) characters"
    }
    let words = item.wordCount
    return "\(item.characterCount.formatted()) characters · \(words.formatted()) \(words == 1 ? "word" : "words")"
}

func kindSymbol(for item: HistoryItem) -> String {
    if item.isSecret { return "lock.fill" }
    if item.isImage { return "photo" }
    if item.isLink { return "link" }
    if item.looksLikeCode { return "chevron.left.forwardslash.chevron.right" }
    if item.text.contains("\n") { return "text.alignleft" }
    return "doc.text"
}

// MARK: - App icons

/// Icons of source apps, looked up by bundle identifier and cached.
@MainActor
enum AppIconCache {
    private static var icons: [String: NSImage] = [:]
    private static var misses: Set<String> = []

    static func icon(bundleID: String?, appName: String?) -> NSImage? {
        let key = bundleID ?? appName ?? ""
        guard !key.isEmpty, !misses.contains(key) else { return nil }
        if let cached = icons[key] { return cached }
        if bundleID == Bundle.main.bundleIdentifier || appName == "ClipVault" {
            return NSApp.applicationIconImage
        }

        var url: URL?
        if let bundleID {
            url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID)
        }
        if url == nil, let appName {
            url = NSWorkspace.shared.runningApplications
                .first { $0.localizedName == appName }?
                .bundleURL
        }
        guard let url else {
            misses.insert(key)
            return nil
        }
        let icon = NSWorkspace.shared.icon(forFile: url.path)
        icons[key] = icon
        return icon
    }
}

struct AppIconView: View {
    let bundleID: String?
    let appName: String?
    var size: CGFloat = 28
    var fallback: String = "app.dashed"

    var body: some View {
        if let icon = AppIconCache.icon(bundleID: bundleID, appName: appName) {
            Image(nsImage: icon)
                .resizable()
                .interpolation(.high)
                .frame(width: size, height: size)
        } else {
            SymbolTile(symbol: fallback, tint: .secondary, size: size)
        }
    }
}

struct SymbolTile: View {
    let symbol: String
    var tint: Color = .accentColor
    var size: CGFloat = 28
    var filled = false

    var body: some View {
        RoundedRectangle(cornerRadius: size * 0.24, style: .continuous)
            .fill(filled ? AnyShapeStyle(tint.gradient) : AnyShapeStyle(tint.opacity(0.14)))
            .frame(width: size, height: size)
            .overlay(
                Image(systemName: symbol)
                    .font(.system(size: size * 0.44, weight: .semibold))
                    .foregroundStyle(filled ? AnyShapeStyle(.white) : AnyShapeStyle(tint))
            )
    }
}

/// The leading icon of a history row: a lock tile for secrets, a thumbnail for
/// images, otherwise the source app's icon.
struct ItemIcon: View {
    let item: HistoryItem
    var size: CGFloat = 28
    var selected = false

    var body: some View {
        if item.isSecret {
            RoundedRectangle(cornerRadius: size * 0.24, style: .continuous)
                .fill(selected ? Color.white.opacity(0.2) : Color.green.opacity(0.16))
                .frame(width: size, height: size)
                .overlay(
                    Image(systemName: "lock.fill")
                        .font(.system(size: size * 0.42, weight: .semibold))
                        .foregroundStyle(selected ? Color.white : Color.green)
                )
        } else if item.isImage {
            ImageThumbnail(item: item, size: size)
        } else {
            AppIconView(
                bundleID: item.sourceBundleID,
                appName: item.sourceApp,
                size: size,
                fallback: kindSymbol(for: item)
            )
        }
    }
}

/// Decrypts and shows a small preview of a non-secret image.
struct ImageThumbnail: View {
    let item: HistoryItem
    var size: CGFloat = 28

    @State private var image: NSImage?

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.22, style: .continuous)
                .fill(Color.primary.opacity(0.06))
            if let image {
                Image(nsImage: image)
                    .resizable()
                    .scaledToFill()
                    .frame(width: size, height: size)
                    .clipShape(RoundedRectangle(cornerRadius: size * 0.22, style: .continuous))
            } else {
                Image(systemName: "photo")
                    .font(.system(size: size * 0.42))
                    .foregroundStyle(.secondary)
            }
        }
        .frame(width: size, height: size)
        .overlay(
            RoundedRectangle(cornerRadius: size * 0.22, style: .continuous)
                .strokeBorder(Color.primary.opacity(0.08))
        )
        .task(id: item.imageFile) {
            guard !item.isSecret, let file = item.imageFile,
                  let data = ImageStore.shared.data(filename: file) else { return }
            image = NSImage(data: data)
        }
    }
}

// MARK: - Keyboard hints

struct KeyCap: View {
    let label: String
    var prominent = false

    var body: some View {
        Text(label)
            .font(.system(size: 11.5, weight: .medium))
            .foregroundStyle(prominent ? Color.primary : Color.secondary)
            .padding(.horizontal, 6)
            .frame(minWidth: 22, minHeight: 20)
            .background(
                RoundedRectangle(cornerRadius: 5, style: .continuous)
                    .fill(Color.primary.opacity(0.07))
            )
    }
}

struct ShortcutHint: View {
    let keys: String
    let label: String

    var body: some View {
        HStack(spacing: 6) {
            KeyCap(label: keys, prominent: true)
            Text(label)
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .fixedSize()
        }
    }
}

// MARK: - Onboarding hero

/// A glossy, glowing app-style tile used at the top of onboarding pages.
struct HeroIcon: View {
    let symbol: String
    var size: CGFloat = 76

    var body: some View {
        RoundedRectangle(cornerRadius: size * 0.27, style: .continuous)
            .fill(
                LinearGradient(
                    colors: [Color(red: 0.25, green: 0.62, blue: 1.0), Color(red: 0.0, green: 0.42, blue: 0.98)],
                    startPoint: .top,
                    endPoint: .bottom
                )
            )
            .overlay(
                RoundedRectangle(cornerRadius: size * 0.27, style: .continuous)
                    .strokeBorder(Color.white.opacity(0.25), lineWidth: 0.6)
            )
            .overlay(
                Image(systemName: symbol)
                    .font(.system(size: size * 0.46, weight: .semibold))
                    .foregroundStyle(.white)
            )
            .frame(width: size, height: size)
            .shadow(color: Color.accentColor.opacity(0.35), radius: size * 0.28, y: size * 0.08)
    }
}

struct AppIconImage: View {
    var size: CGFloat = 96

    var body: some View {
        Image(nsImage: NSApp.applicationIconImage)
            .resizable()
            .interpolation(.high)
            .frame(width: size, height: size)
    }
}

// MARK: - Grouped sections

/// A rounded, softly filled group of rows, like System Settings.
struct GroupCard<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        VStack(spacing: 0) {
            content
        }
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(Color.primary.opacity(0.035))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(Color.primary.opacity(0.06))
        )
    }
}

struct Badge: View {
    let text: String
    var tint: Color = .green

    var body: some View {
        Text(text)
            .font(.system(size: 10.5, weight: .bold))
            .foregroundStyle(tint)
            .padding(.horizontal, 7)
            .padding(.vertical, 2.5)
            .background(Capsule().fill(tint.opacity(0.14)))
    }
}

struct StatusBanner: View {
    let symbol: String
    let title: String
    let message: String
    var tint: Color = .green

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: symbol)
                .font(.system(size: 20))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(tint)
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.system(size: 13.5, weight: .semibold))
                Text(message)
                    .font(.system(size: 12.5))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(tint.opacity(0.09))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(tint.opacity(0.28))
        )
    }
}

struct StatusDot: View {
    let ok: Bool

    var body: some View {
        Circle()
            .fill(ok ? Color.green : Color.orange)
            .frame(width: 7, height: 7)
    }
}

struct MetadataGrid: View {
    let rows: [(String, String)]
    var labelWidth: CGFloat = 76

    var body: some View {
        Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 7) {
            ForEach(Array(rows.enumerated()), id: \.offset) { _, row in
                GridRow {
                    Text(row.0)
                        .foregroundStyle(.secondary)
                        .frame(minWidth: labelWidth, alignment: .leading)
                    Text(row.1)
                        .lineLimit(2)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                }
            }
        }
        .font(.system(size: 12.5))
    }
}

func metadataRows(for item: HistoryItem) -> [(String, String)] {
    var rows: [(String, String)] = [
        ("Source", item.sourceApp ?? "Unknown"),
        ("Copied", copiedDate(item.createdAt))
    ]
    if item.isSecret {
        rows.append(("Kind", item.displayKind ?? "Secret"))
        rows.append(("Protection", item.isSealed ? "Sealed by the Secure Enclave" : "Encrypted at rest"))
    } else {
        rows.append(("Content", contentSummary(for: item)))
    }
    return rows
}
