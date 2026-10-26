import Foundation

struct ApprovalConsequences: Equatable {
    let heading: String
    let steps: [String]
    let retention: String
    let limit: String
    let accessDuration: String?
    let readLimit: String?
    let deliveryNote: String
    let resourceAliasLabel: String

    init(request: ApprovalRequest, scope: ApprovalScope) {
        let duration = request.accessDurationSeconds.map { ApprovalRequestViewModel.formatRemaining(Double($0)) }
        accessDuration = request.operation == .sessionCreate ? duration ?? "Duration unavailable" : nil
        readLimit = request.operation == .sessionCreate ? request.sessionMaxReads.map { "\($0) total reads" }
            ?? "Read limit unavailable" : nil
        resourceAliasLabel = request.operation == .itemDescribe ? "Item" : "Injected as"
        deliveryNote = request.operation == .itemDescribe
            ? "This lookup returns item names and field metadata. Secret values are not returned."
            : "Agent Secret doesn't write secret values to disk. " +
            "Approved processes can use them as environment variables."
        switch request.operation {
        case .itemDescribe:
            heading = "One metadata lookup"
            steps = [
                "Return item names and field metadata.",
                "Secret values are not returned.",
                "Another lookup requires approval."
            ]
            retention = "This approval covers metadata only."
            limit = "One lookup"

        case .sessionCreate:
            heading = "A bounded session"
            steps = [
                "Start access after approval for the verified bound process and folder.",
                "Each read delivers the approved environment once.",
                "Access ends when its duration or read limit is reached, whichever comes first."
            ]
            retention = "Approved values stay in daemon memory during the session. " +
                "Processes may retain delivered values."
            limit = "One session"

        case .exec:
            if scope.decision(for: request) == .approveReusable {
                heading = "Reuse for this command"
                steps = [
                    "Deliver values to this run.",
                    "Reuse approval for the same command, folder, and secret scope.",
                    "Ask again after the deadline or total run limit."
                ]
                retention = "Approved values stay in daemon memory for this window. " +
                    "Processes may retain delivered values."
                limit = "Until \(request.expiresAt.formatted(date: .omitted, time: .shortened)) or " +
                    "\(request.reusableUses) total runs, including this run"
            } else {
                heading = "Just this run"
                steps = ["Deliver the approved environment once.", "Another run requires approval."]
                retention = "The process may retain delivered values after this approval ends."
                limit = "One delivery"
            }
        }
    }
}
