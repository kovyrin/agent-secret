import ServiceManagement

struct AutomaticUpdateChecks {
    // swiftlint:disable:next discouraged_optional_boolean
    let readPreference: () -> Bool?
    let writePreference: (Bool) -> Void
    let registrationStatus: () -> SMAppService.Status
    let register: () throws -> Void
    let unregister: () throws -> Void

    var checksRequested: Bool {
        readPreference() ?? true
    }

    func bootstrap() throws {
        guard checksRequested else {
            return
        }
        if registrationStatus() == .notRegistered || registrationStatus() == .notFound {
            try register()
        }
    }

    func setAutomaticChecks(_ enabled: Bool) throws {
        writePreference(enabled)
        if !enabled {
            try removeRegistration()
            return
        }
        try bootstrap()
    }

    func removeRegistration() throws {
        if registrationStatus() == .enabled || registrationStatus() == .requiresApproval {
            try unregister()
        }
    }
}
