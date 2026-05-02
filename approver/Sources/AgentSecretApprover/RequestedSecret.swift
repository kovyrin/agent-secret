import Foundation

/// One approved environment alias and its backing 1Password reference.
public struct RequestedSecret: Codable, Equatable, Sendable {
    /// Environment variable alias the command expects.
    public var alias: String
    /// 1Password reference approved by the operator.
    public var ref: String
    /// 1Password account scope for this reference, when the daemon can resolve it.
    public var account: String?

    /// Creates a requested secret row for the approval prompt.
    public init(alias: String, ref: String, account: String? = nil) {
        self.alias = alias
        self.ref = ref
        self.account = account
    }
}
