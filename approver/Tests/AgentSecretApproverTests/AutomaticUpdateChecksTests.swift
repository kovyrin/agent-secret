@testable import AgentSecretApprover
import ServiceManagement
import XCTest

final class AutomaticUpdateChecksTests: XCTestCase {
    private final class RegistrationState {
        // swiftlint:disable:next discouraged_optional_boolean
        var preference: Bool?
        var status = SMAppService.Status.notFound
        var registrationFails = false

        var settings: AutomaticUpdateChecks {
            AutomaticUpdateChecks(
                readPreference: { self.preference },
                writePreference: { self.preference = $0 },
                registrationStatus: { self.status },
                register: {
                    if self.registrationFails { throw POSIXError(.EPERM) }
                    self.status = .enabled
                },
                unregister: { self.status = .notRegistered }
            )
        }
    }

    func testMissingPreferenceEnablesAndRegistersChecksWithoutSavingAnOptIn() throws {
        let state = RegistrationState()

        XCTAssertTrue(state.settings.checksRequested)
        try state.settings.bootstrap()

        XCTAssertEqual(state.status, .enabled)
        XCTAssertNil(state.preference)
    }

    func testExplicitOptOutSurvivesRepeatedBootstrap() throws {
        let state = RegistrationState()
        state.preference = false
        state.status = .notRegistered

        try state.settings.bootstrap()
        try state.settings.bootstrap()

        XCTAssertFalse(try XCTUnwrap(state.preference))
        XCTAssertFalse(state.settings.checksRequested)
        XCTAssertEqual(state.status, .notRegistered)
    }

    func testExplicitOptInRegistersMissingLoginItem() throws {
        let state = RegistrationState()
        state.preference = true

        try state.settings.bootstrap()

        XCTAssertEqual(state.status, .enabled)
        XCTAssertTrue(try XCTUnwrap(state.preference))
    }

    func testBootstrapPreservesMacOSApprovalRequirement() throws {
        let state = RegistrationState()
        state.preference = true
        state.status = .requiresApproval

        try state.settings.bootstrap()

        XCTAssertEqual(state.status, .requiresApproval)
        XCTAssertTrue(try XCTUnwrap(state.preference))
    }

    func testRegistrationFailurePreservesExplicitOptIn() throws {
        let state = RegistrationState()
        state.registrationFails = true

        XCTAssertThrowsError(try state.settings.setAutomaticChecks(true))

        XCTAssertTrue(try XCTUnwrap(state.preference))
        XCTAssertTrue(state.settings.checksRequested)
    }

    func testFailedDefaultRegistrationCanRetryWithoutChangingPreference() throws {
        let state = RegistrationState()
        state.registrationFails = true

        XCTAssertThrowsError(try state.settings.bootstrap())
        XCTAssertNil(state.preference)
        state.registrationFails = false
        try state.settings.bootstrap()

        XCTAssertEqual(state.status, .enabled)
        XCTAssertNil(state.preference)
    }

    func testOptingOutUnregistersAnEnabledLoginItem() throws {
        let state = RegistrationState()
        state.status = .enabled

        try state.settings.setAutomaticChecks(false)

        XCTAssertEqual(state.status, .notRegistered)
        XCTAssertFalse(try XCTUnwrap(state.preference))
    }
}
