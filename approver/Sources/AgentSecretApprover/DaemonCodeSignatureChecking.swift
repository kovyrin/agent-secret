import Foundation

#if canImport(Darwin)
    import Darwin

    protocol DaemonCodeSignatureChecking {
        func staticCodeTeamID(for path: String) throws -> String
        func processTeamID(for pid: pid_t) throws -> String
    }
#endif
