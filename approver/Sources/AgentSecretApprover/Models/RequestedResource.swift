import Foundation

/// Stores references only; raw secret values must not enter approver UI models.
public struct RequestedResource: Codable, Equatable, Sendable {
    private enum CodingKeys: String, CodingKey {
        case alias
        case ref
        case account
        case source
        case bitwardenTokenAlias = "bitwarden_token_alias"
    }

    public var alias: String
    public var ref: String
    public var account: String
    public var source: String
    public var bitwardenTokenAlias: String

    public init(alias: String, ref: String, account: String, source: String = "", bitwardenTokenAlias: String = "") {
        self.alias = alias
        self.ref = ref
        self.account = account
        self.source = source
        self.bitwardenTokenAlias = bitwardenTokenAlias
    }

    public init(from decoder: Decoder) throws {
        let container: KeyedDecodingContainer<CodingKeys> = try decoder.container(keyedBy: CodingKeys.self)
        alias = try container.decode(String.self, forKey: .alias)
        ref = try container.decode(String.self, forKey: .ref)
        account = try container.decode(String.self, forKey: .account)
        source = try container.decodeIfPresent(String.self, forKey: .source) ?? ""
        bitwardenTokenAlias = try container.decodeIfPresent(String.self, forKey: .bitwardenTokenAlias) ?? ""
    }
}
