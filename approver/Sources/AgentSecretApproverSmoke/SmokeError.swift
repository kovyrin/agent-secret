import Foundation

internal struct SmokeError: Error, CustomStringConvertible {
    internal var description: String

    internal init(_ description: String) {
        self.description = description
    }
}
