import Foundation

/// Typed denial reasons accepted by the daemon approval protocol.
public enum ApprovalDenialReason: String, Codable, Equatable, Sendable {
    case computerLocked = "computer_locked"
}
