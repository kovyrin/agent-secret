import Foundation

#if canImport(SwiftUI)
    struct ApprovalPanelReasonTextMode: Equatable {
        let lineLimit: Int?
        let allowsSelection: Bool

        init(isExpanded: Bool) {
            lineLimit = isExpanded ? nil : ApprovalPanelStyle.Metric.reasonLineLimit
            allowsSelection = isExpanded
        }
    }
#endif
