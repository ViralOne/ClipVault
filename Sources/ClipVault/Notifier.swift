import Foundation
import UserNotifications

/// Local notifications for concealed secrets. Notification text names the
/// kind of secret only, never its value.
enum Notifier {
    static func authorizationStatus() async -> UNAuthorizationStatus {
        await UNUserNotificationCenter.current().notificationSettings().authorizationStatus
    }

    @discardableResult
    static func requestAuthorization() async -> Bool {
        (try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])) ?? false
    }

    static func postConcealed(kind: String) {
        let content = UNMutableNotificationContent()
        content.title = "Secret concealed"
        content.body = "\(kind) detected in your clipboard and hidden from clipboard managers."
        content.threadIdentifier = "concealed"
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }
}
