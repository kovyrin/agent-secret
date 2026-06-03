import Foundation

struct ApprovalRequestPathPresentation: Equatable {
    let executable: String
    let cwd: String
    let projectFolder: String
    let resolvedExecutable: String
    let allowMutableExecutable: Bool
}
