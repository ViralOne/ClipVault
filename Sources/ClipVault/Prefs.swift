import Foundation

enum Prefs {
    static let keepHistory = "keepHistory"
    static let keepSecrets = "keepSecrets"
    static let concealSecrets = "concealSecrets"
    static let notifyOnConceal = "notifyOnConceal"
    static let concealSound = "concealSound"
    /// Seconds before a secret is cleared from the clipboard. 0 means never.
    static let clearSecretsSeconds = "clearSecretsSeconds"
    static let historyLimit = "historyLimit"
    static let retentionDays = "retentionDays"
    static let hideFromScreenCapture = "hideFromScreenCapture"
    static let pasteIntoApp = "pasteIntoApp"
    static let ignoredApps = "ignoredApps"
    static let alwaysConcealApps = "alwaysConcealApps"
    static let onboardingCompleted = "onboardingCompleted"
    static let pickerOrigin = "pickerOrigin"

    static let defaultAlwaysConcealApps = [
        "com.apple.keychainaccess",
        "com.apple.Passwords"
    ]

    static func registerDefaults() {
        let defaults = UserDefaults.standard
        // 0.2 stored an on/off switch next to the delay; fold it into the delay.
        if defaults.object(forKey: "clearSecretsEnabled") != nil {
            if !defaults.bool(forKey: "clearSecretsEnabled") {
                defaults.set(0, forKey: clearSecretsSeconds)
            }
            defaults.removeObject(forKey: "clearSecretsEnabled")
        }

        defaults.register(defaults: [
            keepHistory: true,
            keepSecrets: true,
            concealSecrets: true,
            notifyOnConceal: false,
            concealSound: false,
            clearSecretsSeconds: 90,
            historyLimit: 500,
            retentionDays: 0,
            hideFromScreenCapture: true,
            pasteIntoApp: true,
            ignoredApps: [String](),
            alwaysConcealApps: defaultAlwaysConcealApps,
            onboardingCompleted: false
        ])
    }

    static func bool(_ key: String) -> Bool { UserDefaults.standard.bool(forKey: key) }
    static func int(_ key: String) -> Int { UserDefaults.standard.integer(forKey: key) }
    static func strings(_ key: String) -> [String] { UserDefaults.standard.stringArray(forKey: key) ?? [] }
}
