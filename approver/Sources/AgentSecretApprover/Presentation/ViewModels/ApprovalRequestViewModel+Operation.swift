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

    static func requestedResourcesHeading(operation: ApprovalOperation, resourceCount: Int) -> String {
        if operation == .itemDescribe {
            return "Requested item metadata"
        }
        if resourceCount == 1 {
            return "Requested secret"
        }
        return "Requested secrets (\(resourceCount))"
    }
}
