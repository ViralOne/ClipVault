import AppKit
import Carbon.HIToolbox
import SwiftUI

/// A user-recordable global shortcut. `modifiers` uses Carbon's modifier masks
/// because that is what `RegisterEventHotKey` consumes.
struct HotKeyConfig: Codable, Equatable {
    var keyCode: UInt32
    var modifiers: UInt32
    var display: String

    static let `default` = HotKeyConfig(
        keyCode: UInt32(kVK_ANSI_V),
        modifiers: UInt32(controlKey | cmdKey),
        display: "⌃⌘V"
    )
}

enum HotKeyPrefs {
    private static let storageKey = "hotKeyConfig"

    static func load() -> HotKeyConfig {
        guard
            let data = UserDefaults.standard.data(forKey: storageKey),
            let config = try? JSONDecoder().decode(HotKeyConfig.self, from: data),
            config.modifiers != 0
        else {
            return .default
        }
        return config
    }

    static func save(_ config: HotKeyConfig) {
        guard let data = try? JSONEncoder().encode(config) else { return }
        UserDefaults.standard.set(data, forKey: storageKey)
    }
}

enum HotKeyBuilder {
    static func config(from event: NSEvent) -> HotKeyConfig? {
        let flags = event.modifierFlags.intersection([.command, .option, .control, .shift])
        guard flags.contains(.command) || flags.contains(.option) || flags.contains(.control) else {
            return nil
        }

        return HotKeyConfig(
            keyCode: UInt32(event.keyCode),
            modifiers: carbonModifiers(flags),
            display: displayString(flags: flags, event: event)
        )
    }

    static func carbonModifiers(_ flags: NSEvent.ModifierFlags) -> UInt32 {
        var value: UInt32 = 0
        if flags.contains(.command) { value |= UInt32(cmdKey) }
        if flags.contains(.option) { value |= UInt32(optionKey) }
        if flags.contains(.control) { value |= UInt32(controlKey) }
        if flags.contains(.shift) { value |= UInt32(shiftKey) }
        return value
    }

    static func displayString(flags: NSEvent.ModifierFlags, event: NSEvent) -> String {
        var result = ""
        if flags.contains(.control) { result += "⌃" }
        if flags.contains(.option) { result += "⌥" }
        if flags.contains(.shift) { result += "⇧" }
        if flags.contains(.command) { result += "⌘" }
        result += keyLabel(for: event)
        return result
    }

    static func keyLabel(for event: NSEvent) -> String {
        switch Int(event.keyCode) {
        case kVK_Space: return "Space"
        case kVK_Return: return "↩"
        case kVK_ANSI_KeypadEnter: return "⌤"
        case kVK_Tab: return "⇥"
        case kVK_Delete: return "⌫"
        case kVK_ForwardDelete: return "⌦"
        case kVK_Escape: return "⎋"
        case kVK_LeftArrow: return "←"
        case kVK_RightArrow: return "→"
        case kVK_UpArrow: return "↑"
        case kVK_DownArrow: return "↓"
        case kVK_Home: return "↖"
        case kVK_End: return "↘"
        case kVK_PageUp: return "⇞"
        case kVK_PageDown: return "⇟"
        case kVK_F1: return "F1"
        case kVK_F2: return "F2"
        case kVK_F3: return "F3"
        case kVK_F4: return "F4"
        case kVK_F5: return "F5"
        case kVK_F6: return "F6"
        case kVK_F7: return "F7"
        case kVK_F8: return "F8"
        case kVK_F9: return "F9"
        case kVK_F10: return "F10"
        case kVK_F11: return "F11"
        case kVK_F12: return "F12"
        default:
            let characters = event.charactersIgnoringModifiers ?? ""
            let trimmed = characters.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? "Key \(event.keyCode)" : trimmed.uppercased()
        }
    }
}

/// Click-to-record shortcut field used in Settings and onboarding. While
/// recording, every key press is consumed so a shortcut cannot trigger app or
/// system commands.
struct ShortcutRecorder: View {
    var width: CGFloat = 220

    @State private var config = HotKeyPrefs.load()
    @State private var recording = false
    @State private var error: String?
    @State private var monitor: Any?

    var body: some View {
        VStack(alignment: .trailing, spacing: 5) {
            HStack(spacing: 6) {
                Button {
                    recording ? stop(cancel: true) : startRecording()
                } label: {
                    Text(recording ? "Type a shortcut…" : config.display)
                        .font(.system(size: recording ? 13 : 15, weight: .medium))
                        .foregroundStyle(recording ? Color.accentColor : Color.primary)
                        .frame(width: width, height: 30)
                        .background(
                            RoundedRectangle(cornerRadius: 8, style: .continuous)
                                .fill(Color.primary.opacity(0.07))
                        )
                        .overlay(
                            RoundedRectangle(cornerRadius: 8, style: .continuous)
                                .strokeBorder(recording ? Color.accentColor : .clear, lineWidth: 1.5)
                        )
                }
                .buttonStyle(.plain)
                .help("Click, then press the new shortcut. Esc cancels.")

                if config != .default && !recording {
                    Button {
                        apply(.default)
                    } label: {
                        Image(systemName: "arrow.counterclockwise")
                    }
                    .buttonStyle(.borderless)
                    .help("Restore \(HotKeyConfig.default.display)")
                }
            }

            if let error {
                Text(error)
                    .font(.system(size: 11))
                    .foregroundStyle(.orange)
            }
        }
        .onDisappear { stop(cancel: true) }
    }

    private func startRecording() {
        guard !recording else { return }
        recording = true
        error = nil
        // Release the current shortcut so pressing it is recorded instead of
        // opening the picker.
        GlobalHotKey.shared.unregister()

        monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
            if Int(event.keyCode) == kVK_Escape {
                stop(cancel: true)
                return nil
            }

            guard let candidate = HotKeyBuilder.config(from: event) else {
                error = "Include ⌘, ⌃ or ⌥."
                return nil
            }

            if apply(candidate) {
                stop(cancel: false)
            }
            return nil
        }
    }

    @discardableResult
    private func apply(_ candidate: HotKeyConfig) -> Bool {
        let previous = HotKeyPrefs.load()
        HotKeyPrefs.save(candidate)

        if AppServices.shared.applyHotKey() {
            config = candidate
            error = nil
            return true
        }

        HotKeyPrefs.save(previous)
        _ = AppServices.shared.applyHotKey()
        config = previous
        error = "\(candidate.display) is already in use. Try another."
        return false
    }

    private func stop(cancel: Bool) {
        if let monitor {
            NSEvent.removeMonitor(monitor)
            self.monitor = nil
        }
        let wasRecording = recording
        recording = false
        if cancel, wasRecording {
            AppServices.shared.applyHotKey()
        } else if !cancel {
            error = nil
        }
    }
}
