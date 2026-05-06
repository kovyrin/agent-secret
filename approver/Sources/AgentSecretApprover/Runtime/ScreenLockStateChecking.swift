import Foundation

/// Reads whether macOS currently has the user's screen session locked.
public protocol ScreenLockStateChecking {
    /// Returns true when the user's interactive screen session is locked.
    func isScreenLocked() -> Bool
}
