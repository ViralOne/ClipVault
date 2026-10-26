import AppKit
import CryptoKit
import Foundation
import LocalAuthentication
import ClipVaultKit

/// Owns the Secure Enclave key that secret values are sealed to.
///
/// The private key never leaves the Secure Enclave. Its access control requires
/// user presence (Touch ID, Apple Watch or the login password) for every use,
/// so a sealed secret cannot be decrypted from the history files and Keychain
/// items alone. The Keychain only stores the key's opaque, device-bound handle.
/// Sealing uses the public key and never prompts.
@MainActor
final class SecretVault {
    static let shared = SecretVault()

    enum Status: Equatable {
        case secureEnclave
        case unavailable(String)
    }

    private(set) var status: Status = .unavailable("Not loaded")
    private var publicKey: P256.KeyAgreement.PublicKey?
    private var keyHandle: Data?

    private let service = "app.clipvault.ClipVault"
    private let account = "secure-enclave-secret-key"

    var isAvailable: Bool { publicKey != nil }

    private init() {
        load()
    }

    private func load() {
        guard SecureEnclave.isAvailable else {
            status = .unavailable("This Mac has no Secure Enclave.")
            return
        }
        do {
            if let handle = try Keychain.read(service: service, account: account) {
                let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: handle)
                adopt(key)
                return
            }
            try createKey()
        } catch {
            status = .unavailable("Secure Enclave key unavailable: \(error.localizedDescription)")
        }
    }

    private func createKey() throws {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .userPresence],
            &error
        ) else {
            throw error!.takeRetainedValue() as Error
        }

        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        let added = try Keychain.add(
            key.dataRepresentation,
            service: service,
            account: account,
            label: "ClipVault Secure Enclave key handle"
        )
        if added {
            adopt(key)
        } else if let handle = try Keychain.read(service: service, account: account) {
            adopt(try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: handle))
        }
    }

    private func adopt(_ key: SecureEnclave.P256.KeyAgreement.PrivateKey) {
        keyHandle = key.dataRepresentation
        publicKey = key.publicKey
        status = .secureEnclave
    }

    // MARK: - Sealing

    func seal(_ plaintext: Data) throws -> Data {
        guard let publicKey else { throw SecretEnvelopeError.malformed }
        return try SecretEnvelope.seal(plaintext, to: publicKey)
    }

    func seal(_ text: String) throws -> Data {
        try seal(Data(text.utf8))
    }

    /// Opens an envelope with a context that has already been authenticated,
    /// so the Secure Enclave does not prompt a second time.
    func open(_ envelope: Data, context: LAContext) throws -> Data {
        guard let keyHandle else { throw SecretEnvelopeError.malformed }
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: keyHandle,
            authenticationContext: context
        )
        return try SecretEnvelope.open(envelope, with: key)
    }

    /// Deletes the key handle. Every secret sealed to it becomes unreadable.
    func reset() {
        Keychain.delete(service: service, account: account)
        publicKey = nil
        keyHandle = nil
        load()
    }
}

/// Touch ID / password unlock. An unlock is scoped to one item: revealing a
/// secret and then pasting that same secret asks once, but every other secret
/// asks again. The scope lasts `sessionSeconds` and ends immediately when the
/// Mac sleeps, locks or starts the screen saver.
@MainActor
enum Biometrics {
    static let sessionSeconds: TimeInterval = 60

    private static var session: (context: LAContext, scope: UUID, expires: Date)?
    private static var observers: [NSObjectProtocol] = []

    static var canAuthenticate: Bool {
        LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
    }

    static var hasBiometrics: Bool {
        LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }

    /// Returns an authenticated context, reusing a live unlock of the same
    /// item, or nil when the user cancels.
    static func authenticate(reason: String, scope: UUID) async -> LAContext? {
        if let session, session.scope == scope, session.expires > Date() {
            return session.context
        }
        endSession()
        installObserversIfNeeded()

        let context = LAContext()
        context.localizedFallbackTitle = "Use Password"
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) else { return nil }
        do {
            guard try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) else {
                return nil
            }
        } catch {
            return nil
        }
        session = (context, scope, Date().addingTimeInterval(sessionSeconds))
        return context
    }

    static func endSession() {
        session?.context.invalidate()
        session = nil
    }

    private static func installObserversIfNeeded() {
        guard observers.isEmpty else { return }
        let workspace = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.willSleepNotification, NSWorkspace.screensDidSleepNotification, NSWorkspace.sessionDidResignActiveNotification] {
            observers.append(workspace.addObserver(forName: name, object: nil, queue: .main) { _ in
                Task { @MainActor in endSession() }
            })
        }
        let distributed = DistributedNotificationCenter.default()
        for name in ["com.apple.screenIsLocked", "com.apple.screensaver.didstart"] {
            observers.append(distributed.addObserver(forName: Notification.Name(name), object: nil, queue: .main) { _ in
                Task { @MainActor in endSession() }
            })
        }
    }
}
