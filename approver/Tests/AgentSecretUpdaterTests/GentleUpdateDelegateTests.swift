@testable import AgentSecretUpdaterApp
import AppKit
import Sparkle
import XCTest

@MainActor
final class GentleUpdateDelegateTests: XCTestCase {
    func testDeferredReminderWaitsForApprovalAndShowsOnce() {
        let foreground = NotificationCenter()
        var approvalHasFocus = true
        var shown = 0
        let delegate = GentleUpdateDelegate(foregroundChanges: foreground) { approvalHasFocus }
        delegate.presentDeferredReminder = { shown += 1 }
        XCTAssertTrue(delegate.responds(to: #selector(
            SPUStandardUserDriverDelegate.standardUserDriverWillHandleShowingUpdate(_:forUpdate:state:)
        )))

        delegate.deferReminder()
        foreground.post(name: NSWorkspace.didActivateApplicationNotification, object: nil)
        XCTAssertEqual(shown, 0)

        approvalHasFocus = false
        foreground.post(name: NSWorkspace.didActivateApplicationNotification, object: nil)
        foreground.post(name: NSWorkspace.didActivateApplicationNotification, object: nil)
        XCTAssertEqual(shown, 1)
    }

    func testEndingTheUpdateSessionDropsTheDeferredReminder() {
        let foreground = NotificationCenter()
        var approvalHasFocus = true
        var shown = 0
        let delegate = GentleUpdateDelegate(foregroundChanges: foreground) { approvalHasFocus }
        delegate.presentDeferredReminder = { shown += 1 }

        delegate.deferReminder()
        delegate.standardUserDriverWillFinishUpdateSession()
        approvalHasFocus = false
        foreground.post(name: NSWorkspace.didActivateApplicationNotification, object: nil)
        XCTAssertEqual(shown, 0)
    }
}
