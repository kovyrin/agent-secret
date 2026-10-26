import Foundation

/// A scope choice is local UI state, never an approval in itself.
enum ApprovalScope: String, CaseIterable {
    case once, reusable

    static func allowsReuse(_ request: ApprovalRequest) -> Bool {
        request.operation == .exec && request.allowsReusable && request.reusableUses > 1
    }

    func decision(for request: ApprovalRequest) -> ApprovalDecisionKind {
        self == .reusable && Self.allowsReuse(request) ? .approveReusable : .approveOnce
    }

    func primaryTitle(for request: ApprovalRequest) -> String {
        switch request.operation {
        case .itemDescribe:
            "Allow lookup"

        case .sessionCreate:
            "Start session"

        case .exec:
            decision(for: request) == .approveReusable ? "Allow reuse" : "Allow this run"
        }
    }
}
