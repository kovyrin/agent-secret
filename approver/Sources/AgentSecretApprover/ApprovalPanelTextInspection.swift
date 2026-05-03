import Foundation

struct ApprovalPanelTextInspection: Identifiable {
    let title: String
    let text: String

    var id: String {
        title
    }
}
