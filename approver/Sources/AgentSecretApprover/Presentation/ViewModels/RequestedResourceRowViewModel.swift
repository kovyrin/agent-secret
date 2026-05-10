import Foundation

/// One requested approval resource prepared for display without secret values.
struct RequestedResourceRowViewModel: Equatable {
    private static let emphasizedReferencePartCount: Int = 2
    private static let minimumEmphasizedReferencePartCount: Int = 3
    private static let opReferencePrefix: String = "op://"

    let alias: String
    let ref: String
    let refSegments: [RequestedResourceReferenceSegment]
    let account: String
    let accountLabel: String
    let vaultName: String
    let vaultScopeName: String
    let itemName: String?
    let fieldName: String?
    let symbolName: String

    init(alias: String, ref: String, account: String) {
        let parts: [String] = Self.referenceParts(ref)
        let normalizedAccount: String = account.trimmingCharacters(in: .whitespacesAndNewlines)
        self.alias = Self.sanitizedDisplayText(alias)
        self.ref = Self.sanitizedDisplayText(ref)
        refSegments = Self.referenceSegments(ref)
        self.account = Self.sanitizedDisplayText(normalizedAccount)
        vaultName = Self.sanitizedDisplayText(parts.first ?? "Unknown vault")
        if self.account.isEmpty {
            accountLabel = ""
            vaultScopeName = vaultName
        } else {
            accountLabel = "Account: \(self.account)"
            vaultScopeName = "\(self.account) / \(vaultName)"
        }
        itemName = parts.dropFirst().first.map(Self.sanitizedDisplayText)
        fieldName = parts.dropFirst().dropFirst().first.map(Self.sanitizedDisplayText)
        symbolName = Self.symbolName(alias: alias, ref: ref)
    }

    private static func referenceParts(_ ref: String) -> [String] {
        guard ref.hasPrefix(opReferencePrefix) else {
            return []
        }
        return ref.dropFirst(opReferencePrefix.count)
            .split(separator: "/", omittingEmptySubsequences: false)
            .map(String.init)
    }

    private static func referenceSegments(_ ref: String) -> [RequestedResourceReferenceSegment] {
        let parts: [String] = Self.referenceParts(ref)
        guard parts.count >= minimumEmphasizedReferencePartCount else {
            return [
                RequestedResourceReferenceSegment(text: Self.sanitizedDisplayText(ref), isEmphasized: false)
            ]
        }

        let emphasizedStartIndex: Int = parts.count - emphasizedReferencePartCount
        let prefixParts: [String] = parts.prefix(emphasizedStartIndex).map(Self.sanitizedDisplayText)
        let emphasizedParts: [String] = parts.suffix(emphasizedReferencePartCount).map(Self.sanitizedDisplayText)
        return [
            RequestedResourceReferenceSegment(
                text: "\(opReferencePrefix)\(prefixParts.joined(separator: "/"))/",
                isEmphasized: false
            ),
            RequestedResourceReferenceSegment(text: emphasizedParts[0], isEmphasized: true),
            RequestedResourceReferenceSegment(text: "/", isEmphasized: false),
            RequestedResourceReferenceSegment(text: emphasizedParts[1], isEmphasized: true)
        ]
    }

    private static func symbolName(alias: String, ref: String) -> String {
        let text = "\(alias) \(ref)".uppercased()
        if text.contains("PASSWORD") {
            return "lock"
        }
        if text.contains("USER") || text.contains("LOGIN") || text.contains("EMAIL") {
            return "person"
        }
        return "key"
    }

    private static func sanitizedDisplayText(_ value: String) -> String {
        ApprovalDisplayTextSanitizer.sanitize(value)
    }
}
