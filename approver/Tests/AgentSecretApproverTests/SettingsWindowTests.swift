@testable import AgentSecretApproverApp
import AppKit
import XCTest

@MainActor
final class SettingsWindowTests: XCTestCase {
    func testOpeningSettingsDoesNotRunActions() {
        var actions = 0
        let controller = SettingsWindowController(state: .previewInstalled, icon: nil)
        controller.onInstall = { actions += 1 }
        controller.onDiagnostics = { actions += 1 }
        controller.onCheckForUpdates = { actions += 1 }
        controller.onAutomaticChecks = { _ in actions += 1 }

        controller.window?.contentView?.layoutSubtreeIfNeeded()

        XCTAssertEqual(actions, 0)
        XCTAssertEqual(controller.window?.contentLayoutRect.size, NSSize(width: 500, height: 350))
        XCTAssertEqual(controller.window?.styleMask.contains(.closable), true)
    }

    func testRenderSettingsPreviewsWhenRequested() throws {
        guard let directory = ProcessInfo.processInfo.environment["AGENT_SECRET_SETTINGS_PREVIEW_DIR"] else {
            throw XCTSkip("Set AGENT_SECRET_SETTINGS_PREVIEW_DIR to render fixture previews.")
        }
        let destination = URL(fileURLWithPath: directory, isDirectory: true)
        try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
        let source = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("scripts/build/assets/AppIcon.png")
        let icon = NSImage(contentsOf: source)
        let fixtures: [(String, SettingsState)] = [
            ("installed", .previewInstalled), ("missing", .previewMissing), ("repair", .previewRepair),
            ("approval", .previewApproval), ("unavailable", .previewUnavailable), ("busy", .previewBusy)
        ]
        for appearance in [NSAppearance.Name.aqua, .darkAqua] {
            for (name, state) in fixtures {
                let controller = SettingsWindowController(state: state, icon: icon)
                let window = try XCTUnwrap(controller.window)
                try capture(window, name: name, appearance: appearance, destination: destination)
            }
            let output = ["Agent Secret diagnostics — fixture", "No provider request was made.", ""]
                + (1 ... 35).map { "Fixture component \($0): ready" }
            let details = SettingsDetailsController(
                title: "Diagnostics", summary: "Completed", output: output.joined(separator: "\n")
            )
            let detailsWindow = try XCTUnwrap(details.window)
            try capture(detailsWindow, name: "diagnostics", appearance: appearance, destination: destination)
        }
    }

    private func capture(
        _ window: NSWindow,
        name: String,
        appearance: NSAppearance.Name,
        destination: URL
    ) throws {
        window.appearance = NSAppearance(named: appearance)
        window.contentView?.layoutSubtreeIfNeeded()
        let frame = try XCTUnwrap(window.contentView?.superview)
        frame.display()
        let bitmap = try XCTUnwrap(frame.bitmapImageRepForCachingDisplay(in: frame.bounds))
        frame.cacheDisplay(in: frame.bounds, to: bitmap)
        let data = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))
        let mode = appearance == .aqua ? "light" : "dark"
        try data.write(to: destination.appendingPathComponent("settings-\(name)-\(mode).png"))
        window.close()
    }
}

extension SettingsState {
    static var previewInstalled: Self {
        Self(version: "0.1.3", cli: .installed, updatesConfigured: true, automaticChecks: true)
    }

    static var previewMissing: Self {
        Self(version: "0.1.3", cli: .missing, updatesConfigured: true, automaticChecks: false)
    }

    static var previewRepair: Self {
        var state = previewInstalled
        state.cli = .repairNeeded
        return state
    }

    static var previewApproval: Self {
        var state = previewInstalled
        state.updateNotice = "Allow Agent Secret in System Settings → General → Login Items."
        return state
    }

    static var previewUnavailable: Self {
        Self(version: "0.1.3", cli: .unavailable, updatesConfigured: false, automaticChecks: false)
    }

    static var previewBusy: Self {
        var state = previewInstalled
        state.busy = true
        state.activity = "Running diagnostics…"
        return state
    }
}
