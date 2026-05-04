import Foundation

/// Stores references only; raw secret values must not enter approver UI models.
public struct RequestedSecret: Codable, Equatable, Sendable {
    public var alias: String
    public var ref: String
    public var account: String?

    public init(alias: String, ref: String, account: String? = nil) {
        self.alias = alias
        self.ref = ref
        self.account = account
    }
}
