import AppKit

@MainActor
final class SettingsApplicationDelegate: NSObject, NSApplicationDelegate {
    private var coordinator: SettingsCoordinator?
    private var defaultLaunch = true
    private var launchFinished = false
    private var requestedOpen = false
    private var pendingOpenEvent: NSAppleEventDescriptor?

    func applicationDidFinishLaunching(_ notification: Notification) {
        defaultLaunch = notification.userInfo?[NSApplication.launchIsDefaultUserInfoKey] as? Bool ?? true
        launchFinished = true
        installMenu()
        let event = pendingOpenEvent ?? NSAppleEventManager.shared().currentAppleEvent
        guard SettingsLaunch.shouldShowWindow(defaultLaunch: defaultLaunch, event: event) else {
            NSApp.terminate(nil)
            return
        }
        if requestedOpen {
            showSettings()
            Task { await coordinator?.bootstrap() }
        }
    }

    func applicationShouldOpenUntitledFile(_: NSApplication) -> Bool {
        // AppKit can ask before didFinishLaunching. Wait for its default-launch information.
        let event = NSAppleEventManager.shared().currentAppleEvent
        requestedOpen = true
        pendingOpenEvent = event
        if launchFinished, SettingsLaunch.shouldShowWindow(defaultLaunch: defaultLaunch, event: event) {
            showSettings()
            Task { await coordinator?.bootstrap() }
        }
        return false
    }

    func applicationShouldHandleReopen(_: NSApplication, hasVisibleWindows _: Bool) -> Bool {
        let event = NSAppleEventManager.shared().currentAppleEvent
        if SettingsLaunch.shouldShowWindow(defaultLaunch: true, event: event) { showSettings() }
        return false
    }

    func applicationShouldTerminateAfterLastWindowClosed(_: NSApplication) -> Bool {
        true
    }

    private func showSettings() {
        if coordinator == nil { coordinator = SettingsCoordinator() }
        coordinator?.refresh()
        NSApp.setActivationPolicy(.regular)
        coordinator?.controller.showWindow(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func installMenu() {
        let menu = NSMenu()
        let app = NSMenuItem()
        app.submenu = NSMenu(title: "Agent Secret")
        app.submenu?.addItem(
            withTitle: "Quit Agent Secret", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"
        )
        menu.addItem(app)
        let file = NSMenuItem()
        file.submenu = NSMenu(title: "File")
        file.submenu?.addItem(
            withTitle: "Close Window", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w"
        )
        menu.addItem(file)
        let edit = NSMenuItem()
        edit.submenu = NSMenu(title: "Edit")
        edit.submenu?.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.submenu?.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        menu.addItem(edit)
        NSApp.mainMenu = menu
    }
}
