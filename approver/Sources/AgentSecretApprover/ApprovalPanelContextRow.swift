import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelContextRow: View {
        private typealias Metric = ApprovalPanelStyle.Metric

        let icon: String
        let title: String
        let value: String

        var body: some View {
            HStack(alignment: .top, spacing: Metric.rowSpacing) {
                ApprovalPanelIconBox(systemName: icon)
                VStack(alignment: .leading, spacing: Metric.rowTextSpacing) {
                    Text(title)
                        .font(.system(size: Metric.bodyFontSize + Metric.borderWidth, weight: .semibold))
                    Text(value)
                        .font(.system(size: Metric.bodyFontSize + Metric.borderWidth, design: .monospaced))
                        .lineLimit(Metric.twoLineLimit)
                        .truncationMode(.middle)
                }
            }
        }
    }
#endif
