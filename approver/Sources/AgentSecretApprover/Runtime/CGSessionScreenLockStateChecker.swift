import Foundation

#if canImport(CoreGraphics)
    import CoreGraphics
#endif

/// Reads the current macOS login session lock state through CoreGraphics.
public struct CGSessionScreenLockStateChecker: ScreenLockStateChecking {
    private static let screenIsLockedKey = "CGSSessionScreenIsLocked"

    public init() {
        // The CoreGraphics session checker has no stored configuration.
    }

    public func isScreenLocked() -> Bool {
        #if canImport(CoreGraphics)
            guard let session = CGSessionCopyCurrentDictionary() as? [String: Any] else {
                return false
            }
            return session[Self.screenIsLockedKey] as? Bool ?? false
        #else
            return false
        #endif
    }
}
