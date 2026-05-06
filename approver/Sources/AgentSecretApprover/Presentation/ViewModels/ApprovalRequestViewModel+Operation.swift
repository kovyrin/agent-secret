import Foundation

extension ApprovalRequestViewModel {
    static func title(for operation: ApprovalOperation) -> String {
        switch operation {
        case .exec:
            "Secret Access Request"

        case .itemDescribe:
            "Item Metadata Request"
        }
    }

    static func requestedSecretsHeading(operation: ApprovalOperation, secretCount: Int) -> String {
        if operation == .itemDescribe {
            return "Requested item metadata"
        }
        if secretCount == 1 {
            return "Requested secret"
        }
        return "Requested secrets (\(secretCount))"
    }

    static func requestedSecretsHeading(for request: ApprovalRequest, secretCount: Int) -> String {
        requestedSecretsHeading(operation: request.operation, secretCount: secretCount)
    }
}
