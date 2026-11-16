@testable import AgentSecretApproverApp
import AppKit
import CoreServices
import XCTest

final class SettingsLaunchTests: XCTestCase {
    func testExplicitOpenShowsSettings() {
        XCTAssertTrue(SettingsLaunch.shouldShowWindow(defaultLaunch: true, event: nil))
    }

    func testRestoredLoginAndServiceLaunchesStayQuiet() {
        XCTAssertFalse(SettingsLaunch.shouldShowWindow(defaultLaunch: false, event: nil))
        for origin in [keyAELaunchedAsLogInItem, keyAELaunchedAsServiceItem] {
            let event = NSAppleEventDescriptor(
                eventClass: AEEventClass(kCoreEventClass),
                eventID: AEEventID(kAEOpenApplication),
                targetDescriptor: nil,
                returnID: AEReturnID(kAutoGenerateReturnID),
                transactionID: AETransactionID(kAnyTransactionID)
            )
            event.setParam(NSAppleEventDescriptor(enumCode: OSType(origin)), forKeyword: AEKeyword(keyAEPropData))
            XCTAssertFalse(SettingsLaunch.shouldShowWindow(defaultLaunch: true, event: event))
        }
    }
}
