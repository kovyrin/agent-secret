struct ApprovalRequestViewModelRenderInput {
    let title: String
    let reason: String
    let command: String
    let commandArgumentRows: [String]
    let cwd: String
    let scopeSummary: String
    let sessionBindingSummary: String?
    let resolvedExecutable: String
    let allowMutableExecutable: Bool
    let resourceRows: [String]
    let timeRemaining: String
    let cautionMessages: [String]
}
