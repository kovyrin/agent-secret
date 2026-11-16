import AppKit

@MainActor
enum SettingsApplication {
    static func run() {
        let application = NSApplication.shared
        let delegate = SettingsApplicationDelegate()
        application.setActivationPolicy(.accessory)
        application.delegate = delegate
        withExtendedLifetime(delegate) { application.run() }
    }
}
